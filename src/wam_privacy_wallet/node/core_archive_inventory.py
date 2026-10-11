"""Read-only bounded WAM v0.1.11 distribution inventory.

Consumes an untrusted signed-distribution *receipt* and verifies its matching
archive bytes before inspecting TAR.GZ/ZIP. Does not extract any member, change
filesystem permissions, create binaries or execute WAM Core. A forged receipt
cannot confer publisher trust, process identity or a launch capability.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
import stat
import tarfile
import unicodedata
import zipfile

from .core_artifact_staging import CoreArtifactStagingError, stage_untrusted_core_artifact
from .core_signed_release import (
    RELEASE_ASSETS, SignedDistributionEvidence, WAM_RELEASE_SIGNING_FINGERPRINT,
)

_MAX_MEMBERS = 64
_MAX_MEMBER_BYTES = 128 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_MAX_RATIO = 400
_CHUNK = 1 << 20
_ROOT = "wam-coin-v0.1.11"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ALLOWED_BINARY = {
    "wam-coin-v0.1.11-x86_64-linux-gnu.tar.gz": f"{_ROOT}/bin/wamd",
    "wam-coin-v0.1.11-arm64-apple-darwin.tar.gz": f"{_ROOT}/bin/wamd",
    "wam-coin-v0.1.11-x86_64-w64-mingw32.zip": f"{_ROOT}/bin/wamd.exe",
}


class CoreArchiveInventoryError(ValueError):
    """Only fixed redacted codes, never untrusted archive member names."""


@dataclass(frozen=True, slots=True)
class CoreArchiveInventory:
    """Scalar-only inspection evidence, *not* executable binary provenance."""

    archive_name: str
    member_count: int
    file_count: int
    total_uncompressed_bytes: int
    node_entry: str
    node_byte_count: int
    node_sha256: str = field(repr=False)
    status: str = field(default="UNTRUSTED_ARCHIVE_INVENTORY", init=False)
    archive_signer_revalidated: bool = field(default=False, init=False)
    extracted_binary_verified: bool = field(default=False, init=False)
    execution_identity_bound: bool = field(default=False, init=False)
    core_execution_allowed: bool = field(default=False, init=False)
    mainnet_allowed: bool = field(default=False, init=False)
    real_wallet_allowed: bool = field(default=False, init=False)


def _entry_path(name: str, is_dir: bool) -> str:
    """Canonical case-sensitive, unambiguous portable names, no traversal."""
    if type(name) is not str or not name or len(name) > 240:
        raise CoreArchiveInventoryError("CORE_ARCHIVE_PATH_DENIED")
    if "\\" in name or "\x00" in name or name.startswith("/") or ":" in name:
        raise CoreArchiveInventoryError("CORE_ARCHIVE_PATH_DENIED")
    if not is_dir and name.endswith("/"):
        raise CoreArchiveInventoryError("CORE_ARCHIVE_PATH_DENIED")
    value = name[:-1] if is_dir and name.endswith("/") else name
    # GNU tar normally contains the package root as an explicit directory.
    if is_dir and value == _ROOT:
        return value
    bits = value.split("/")
    if (len(bits) < 2 or len(bits) > 8
            or any(part in ("", ".", "..") for part in bits)
            or bits[0] != _ROOT
            or unicodedata.normalize("NFC", value) != value
            or any(any(ord(ch) < 32 or ord(ch) == 127 for ch in p) for p in bits)):
        raise CoreArchiveInventoryError("CORE_ARCHIVE_PATH_DENIED")
    return value


def _receipt(evidence: object) -> tuple[str, str]:
    if (type(evidence) is not SignedDistributionEvidence
            or type(evidence.archive_name) is not str
            or evidence.archive_name not in RELEASE_ASSETS
            or type(evidence.distribution_sha256) is not str
            or _HEX64.fullmatch(evidence.distribution_sha256) is None
            or evidence.signing_fingerprint != WAM_RELEASE_SIGNING_FINGERPRINT
            or evidence.status != "SIGNED_DISTRIBUTION_ONLY"
            or evidence.extracted_binary_verified is not False
            or evidence.execution_identity_bound is not False
            or evidence.core_execution_allowed is not False
            or evidence.mainnet_allowed is not False
            or evidence.real_wallet_allowed is not False):
        raise CoreArchiveInventoryError("CORE_ARCHIVE_RECEIPT_DENIED")
    return evidence.archive_name, evidence.distribution_sha256


def _consume_file(fileobj, size: int) -> str:
    """Hash content with exact bounded EOF; do not write any output file."""
    if type(size) is not int or not 0 <= size <= _MAX_MEMBER_BYTES:
        raise CoreArchiveInventoryError("CORE_ARCHIVE_SIZE_DENIED")
    hasher = hashlib.sha256()
    remaining = size
    while remaining:
        part = fileobj.read(min(_CHUNK, remaining))
        if not part:
            raise CoreArchiveInventoryError("CORE_ARCHIVE_TRUNCATED_DENIED")
        hasher.update(part)
        remaining -= len(part)
    # ZIP has CRC checked at EOF; also reject a stream yielding extra bytes.
    if fileobj.read(1):
        raise CoreArchiveInventoryError("CORE_ARCHIVE_SIZE_DENIED")
    return hasher.hexdigest()


def _read_tar(path: Path, node_target: str) -> CoreArchiveInventory:
    names: set[str] = set()
    members = 0
    files = 0
    total = 0
    binary_hash = None
    binary_size = 0
    try:
        with tarfile.open(path, mode="r:gz", errorlevel=2) as tf:
            for member in tf:
                members += 1
                if members > _MAX_MEMBERS:
                    raise CoreArchiveInventoryError("CORE_ARCHIVE_MEMBER_LIMIT_DENIED")
                if not (member.isfile() or member.isdir()):
                    raise CoreArchiveInventoryError("CORE_ARCHIVE_TYPE_DENIED")
                if any(k.startswith("GNU.sparse") for k in member.pax_headers):
                    raise CoreArchiveInventoryError("CORE_ARCHIVE_TYPE_DENIED")
                key = _entry_path(member.name, member.isdir())
                duplicate_key = key.casefold()
                if duplicate_key in names:
                    raise CoreArchiveInventoryError("CORE_ARCHIVE_COLLISION_DENIED")
                names.add(duplicate_key)
                if member.isdir():
                    if member.size != 0:
                        raise CoreArchiveInventoryError("CORE_ARCHIVE_TYPE_DENIED")
                    continue
                if member.size > _MAX_MEMBER_BYTES:
                    raise CoreArchiveInventoryError("CORE_ARCHIVE_SIZE_DENIED")
                files += 1
                total += member.size
                if total > _MAX_TOTAL_BYTES:
                    raise CoreArchiveInventoryError("CORE_ARCHIVE_SIZE_DENIED")
                stream = tf.extractfile(member)
                if stream is None:
                    raise CoreArchiveInventoryError("CORE_ARCHIVE_TYPE_DENIED")
                with stream:
                    digest = _consume_file(stream, member.size)
                if key == node_target:
                    if member.size == 0:
                        raise CoreArchiveInventoryError("CORE_ARCHIVE_NODE_DENIED")
                    binary_hash = digest
                    binary_size = member.size
    except CoreArchiveInventoryError:
        raise
    except (tarfile.TarError, EOFError, OSError, ValueError, OverflowError, MemoryError):
        raise CoreArchiveInventoryError("CORE_ARCHIVE_CONTAINER_DENIED") from None
    if binary_hash is None:
        raise CoreArchiveInventoryError("CORE_ARCHIVE_NODE_MISSING")
    return CoreArchiveInventory(
        path.name, members, files, total, node_target, binary_size, binary_hash,
    )


def _read_zip(path: Path, node_target: str) -> CoreArchiveInventory:
    names: set[str] = set()
    members = 0
    files = 0
    total = 0
    binary_hash = None
    binary_size = 0
    try:
        with zipfile.ZipFile(path) as zf:
            for member in zf.infolist():
                members += 1
                if members > _MAX_MEMBERS:
                    raise CoreArchiveInventoryError("CORE_ARCHIVE_MEMBER_LIMIT_DENIED")
                is_dir = member.is_dir()
                # Only regular or directory; no symlink, FIFO, device, etc.
                unix_mode = member.external_attr >> 16
                kind = stat.S_IFMT(unix_mode)
                if member.create_system == 3 and kind not in (
                        0, stat.S_IFREG if not is_dir else stat.S_IFDIR):
                    raise CoreArchiveInventoryError("CORE_ARCHIVE_TYPE_DENIED")
                if (member.flag_bits & 1 or member.compress_type not in (
                        zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                    raise CoreArchiveInventoryError("CORE_ARCHIVE_TYPE_DENIED")
                key = _entry_path(member.filename, is_dir)
                duplicate_key = key.casefold()
                if duplicate_key in names:
                    raise CoreArchiveInventoryError("CORE_ARCHIVE_COLLISION_DENIED")
                names.add(duplicate_key)
                if is_dir:
                    if member.file_size != 0:
                        raise CoreArchiveInventoryError("CORE_ARCHIVE_TYPE_DENIED")
                    continue
                if member.file_size > _MAX_MEMBER_BYTES:
                    raise CoreArchiveInventoryError("CORE_ARCHIVE_SIZE_DENIED")
                if member.file_size > _MAX_RATIO * max(member.compress_size, 1):
                    raise CoreArchiveInventoryError("CORE_ARCHIVE_RATIO_DENIED")
                files += 1
                total += member.file_size
                if total > _MAX_TOTAL_BYTES:
                    raise CoreArchiveInventoryError("CORE_ARCHIVE_SIZE_DENIED")
                with zf.open(member, "r") as stream:
                    digest = _consume_file(stream, member.file_size)
                if key == node_target:
                    if member.file_size == 0:
                        raise CoreArchiveInventoryError("CORE_ARCHIVE_NODE_DENIED")
                    binary_hash = digest
                    binary_size = member.file_size
    except CoreArchiveInventoryError:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, OSError,
            ValueError, RuntimeError, OverflowError, MemoryError):
        raise CoreArchiveInventoryError("CORE_ARCHIVE_CONTAINER_DENIED") from None
    if binary_hash is None:
        raise CoreArchiveInventoryError("CORE_ARCHIVE_NODE_MISSING")
    return CoreArchiveInventory(
        path.name, members, files, total, node_target, binary_size, binary_hash,
    )


def inspect_wam_core_archive(*, archive: object,
                             signed_receipt: object) -> CoreArchiveInventory:
    """Inventory signed-*claimed* archive via verified ephemeral staging.

    A signed receipt can be constructed/forged in Python. Callers MUST run
    GnuPG against authentic assets separately; this read-only inspector never
    promotes a receipt into a credential or WAM Core executable approval.
    """
    name, sha256 = _receipt(signed_receipt)
    # stage_untrusted_core_artifact's context manager catches ValueError
    # thrown *through its yield*, so let it finish integrity/cleanup before
    # propagating a typed archive denial (CoreArchiveInventoryError is a
    # ValueError). Otherwise all malicious archive failures masquerade as
    # checksum mismatch and critical regression identities lose their signal.
    result = None
    failure = None
    try:
        with stage_untrusted_core_artifact(archive, sha256) as staged:
            path = staged.snapshot_path
            target = _ALLOWED_BINARY[name]
            try:
                if name.endswith(".tar.gz"):
                    result = _read_tar(path, target)
                elif name.endswith(".zip"):
                    result = _read_zip(path, target)
                else:
                    raise CoreArchiveInventoryError("CORE_ARCHIVE_FORMAT_DENIED")
            except CoreArchiveInventoryError as err:
                failure = err
    except CoreArtifactStagingError:
        raise CoreArchiveInventoryError("CORE_ARCHIVE_DIGEST_DENIED") from None
    if failure is not None:
        raise failure from None
    if result is None:
        raise CoreArchiveInventoryError("CORE_ARCHIVE_CONTAINER_DENIED")
    # No staged snapshot path, filesystem handle or untrusted members escape.
    return CoreArchiveInventory(
        name, result.member_count, result.file_count,
        result.total_uncompressed_bytes, target,
        result.node_byte_count, result.node_sha256,
    )
