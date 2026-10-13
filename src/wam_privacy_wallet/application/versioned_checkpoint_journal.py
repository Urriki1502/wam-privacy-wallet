"""Immutable Linux WSP-1 encrypted checkpoint generations; synthetic-regtest only.

Unanchored disk hash chains CANNOT prove freshness or defeat rollback of the
entire directory. This prototype publishes exact private version directories,
canonical manifests and encrypted ciphertext, but rejects normal retrieval
unless the test caller explicitly opts into UNANCHORED_SYNTHETIC_REGTEST_ONLY.
No upstream WSP cryptography is reimplemented. No WAM Core or signing.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
try:
    import fcntl
except ImportError:  # Windows persistence remains unqualified.
    fcntl = None

from wam_privacy_wallet.application.encrypted_checkpoint_archive import _well_formed
from .private_checkpoint_directory import (
    open_private_checkpoint_directory, validate_private_directory,
)

_SOURCE_PIN = "ac55f13423620252bdbf848c7e8a280c3b84721e"
_ZERO = "0" * 64
_SCHEMA = 1
_MAX = 32 * 1024 * 1024 + 52
_MANIFEST_KEYS = frozenset((
    "schema", "generation", "network", "source_pin",
    "scope_digest", "tip_height", "tip_hash", "predecessor",
    "checkpoint_sha256",
))


class VersionedCheckpointError(ValueError):
    """Redacted refusal; never include private filenames or upstream bytes."""


def _hex64(x: object) -> bool:
    return type(x) is str and re.fullmatch(r"[0-9a-f]{64}", x) is not None


def _private_dir(fd: int) -> None:
    try:
        validate_private_directory(fd)
    except Exception:
        raise VersionedCheckpointError("SNAPSHOT_PRIVATE_DIRECTORY_DENIED") from None


def _open_dir(base: Path) -> int:
    if (sys.platform != "linux" or type(base) is not type(Path())
            or not base.is_absolute()
            or not all(hasattr(os, k) for k in
                       ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"))):
        raise VersionedCheckpointError("SNAPSHOT_PLATFORM_DENIED")
    if ".." in base.parts:
        raise VersionedCheckpointError("SNAPSHOT_PRIVATE_DIRECTORY_DENIED")
    try:
        return open_private_checkpoint_directory(base)
    except Exception:
        raise VersionedCheckpointError("SNAPSHOT_PRIVATE_DIRECTORY_DENIED") from None


def _lock(fd: int, *, exclusive: bool) -> None:
    # Native inter-process, non-blocking directory lock; no mutable lockfile
    # and no indefinite waiting. Same-UID malicious code can ignore advisory
    # locks; they are concurrency control, never an independent trust anchor.
    if fcntl is None:
        raise VersionedCheckpointError("SNAPSHOT_PLATFORM_DENIED")
    try:
        fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
                    | fcntl.LOCK_NB)
    except OSError:
        raise VersionedCheckpointError("SNAPSHOT_CONCURRENT_UPDATE_DENIED") from None


def _child_dir(parent: int, name: str) -> int:
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                 os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        _private_dir(fd)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _file(fd: int, name: str, body: bytes) -> None:
    f = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        os.fchmod(f, 0o600)
        st = os.fstat(f)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600):
            raise ValueError("bad staged file")
        index = 0
        while index < len(body):
            n = os.write(f, body[index:])
            if n < 1:
                raise OSError("short write")
            index += n
        os.fsync(f)
    finally:
        os.close(f)


def _read(fd: int, name: str, max_size: int) -> bytes:
    f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                os.O_NONBLOCK, dir_fd=fd)
    try:
        before = os.fstat(f)
        if (not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != os.geteuid() or before.st_nlink != 1
                or not 1 <= before.st_size <= max_size):
            raise ValueError("unsafe stored file")
        data = bytearray()
        while len(data) < before.st_size:
            chunk = os.read(f, min(65536, before.st_size-len(data)))
            if not chunk:
                raise ValueError("truncated file")
            data.extend(chunk)
        after = os.fstat(f)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
             after.st_ctime_ns)) or after.st_nlink != 1:
            raise ValueError("file modified during read")
        return bytes(data)
    finally:
        os.close(f)


def _canonical(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _name(generation: int) -> str:
    if type(generation) is not int or not 1 <= generation <= 2**63 - 1:
        raise VersionedCheckpointError("SNAPSHOT_GENERATION_DENIED")
    return f"{generation:016x}"


def write_unanchored_regtest_generation(
    directory: Path, generation: int, envelope: bytes, *,
    scope_digest: str, tip_height: int, tip_hash: str,
    predecessor_digest: str,
) -> str:
    """Commit an immutable version, returning an UNTRUSTED manifest digest.

    No 'latest' selector or rollback authorization is provided. The caller
    must not treat this digest as a hardware-backed monotonic commitment.
    """
    manifest = _generation_manifest(
        generation, envelope, scope_digest=scope_digest, tip_height=tip_height,
        tip_hash=tip_hash, predecessor_digest=predecessor_digest,
    )
    return _persist_generation(directory, generation, envelope, manifest)


def _generation_manifest(generation: int, envelope: bytes, *,
                         scope_digest: str, tip_height: int, tip_hash: str,
                         predecessor_digest: str) -> dict:
    _name(generation)
    if (not _well_formed(envelope) or not _hex64(scope_digest)
            or not _hex64(tip_hash) or not _hex64(predecessor_digest)
            or type(tip_height) is not int or not 0 <= tip_height <= 2**31
            or (generation == 1 and predecessor_digest != _ZERO)
            or (generation > 1 and predecessor_digest == _ZERO)):
        raise VersionedCheckpointError("SNAPSHOT_INPUT_DENIED")
    return {
        "schema": _SCHEMA, "generation": generation, "network": "regtest",
        "source_pin": _SOURCE_PIN, "scope_digest": scope_digest,
        "tip_height": tip_height, "tip_hash": tip_hash,
        "predecessor": predecessor_digest,
        "checkpoint_sha256": hashlib.sha256(envelope).hexdigest(),
    }


def _persist_generation(directory: Path, generation: int, envelope: bytes,
                        manifest: dict, metadata: bytes | None = None) -> str:
    name = _name(generation)
    raw = _canonical(manifest)
    digest = hashlib.sha256(raw).hexdigest()
    root = None
    versions = None
    version = None
    try:
        root = _open_dir(directory)
        _lock(root, exclusive=True)
        try:
            os.mkdir("versions", 0o700, dir_fd=root)
            os.fsync(root)
        except FileExistsError:
            pass
        versions = _child_dir(root, "versions")
        # O_EXCL semantics for directories: cannot overwrite any old version.
        os.mkdir(name, 0o700, dir_fd=versions)
        version = _child_dir(versions, name)
        _file(version, "checkpoint.wsp.enc", envelope)
        _file(version, "manifest.json", raw)
        if metadata is not None:
            _file(version, "metadata.v2.json", metadata)
        os.fsync(version)
        # Completion marker is written ONLY after both files are durable.
        # Reader validates marker digest, file modes and ciphertext checksum.
        _file(version, "ready.sha256", (digest + "\n").encode("ascii"))
        os.fsync(version)
        os.fsync(versions)
        os.fsync(root)
        return digest
    except VersionedCheckpointError:
        raise
    except Exception:
        raise VersionedCheckpointError("SNAPSHOT_WRITE_DENIED") from None
    finally:
        for fd in (version, versions, root):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def read_unanchored_regtest_generation(
    directory: Path, generation: int, *,
    allow_unanchored_synthetic: bool = False,
) -> tuple[dict, bytes]:
    """Read a *specific* generation ONLY under explicit synthetic consent.

    No auto-latest. The manifest/hash chain is NOT an authenticated
    anti-rollback trust anchor and never qualifies a live wallet.
    """
    if allow_unanchored_synthetic is not True:
        raise VersionedCheckpointError("SNAPSHOT_TRUSTED_ANCHOR_REQUIRED")
    manifest, envelope, _ = _load_generation(directory, generation)
    return manifest, envelope


def _load_generation(directory: Path, generation: int, *,
                     authenticated: bool = False) -> tuple[dict, bytes, bytes | None]:
    name = _name(generation)
    root = None
    versions = None
    version = None
    try:
        root = _open_dir(directory)
        _lock(root, exclusive=False)
        versions = _child_dir(root, "versions")
        version = _child_dir(versions, name)
        commit = _read(version, "ready.sha256", 65)
        raw = _read(version, "manifest.json", 4096)
        envelope = _read(version, "checkpoint.wsp.enc", _MAX)
        metadata = _read(version, "metadata.v2.json", 4096) if authenticated else None
        manifest = json.loads(raw)
        if (type(manifest) is not dict or frozenset(manifest) != _MANIFEST_KEYS
                or _canonical(manifest) != raw
                or hashlib.sha256(raw).hexdigest().encode("ascii") + b"\n" != commit
                or type(manifest["schema"]) is not int
                or manifest["schema"] != 1 or manifest["network"] != "regtest"
                or manifest["source_pin"] != _SOURCE_PIN
                or type(manifest["generation"]) is not int
                or manifest["generation"] != generation
                or type(manifest["tip_height"]) is not int
                or not 0 <= manifest["tip_height"] <= 2**31
                or not _hex64(manifest["scope_digest"])
                or not _hex64(manifest["tip_hash"])
                or not _hex64(manifest["predecessor"])
                or not _hex64(manifest["checkpoint_sha256"])
                or (generation == 1 and manifest["predecessor"] != _ZERO)
                or (generation > 1 and manifest["predecessor"] == _ZERO)
                or not _well_formed(envelope)
                or hashlib.sha256(envelope).hexdigest()
                    != manifest["checkpoint_sha256"]):
            raise ValueError("invalid snapshot")
        return manifest, envelope, metadata
    except VersionedCheckpointError:
        raise
    except Exception:
        raise VersionedCheckpointError("SNAPSHOT_READ_DENIED") from None
    finally:
        for fd in (version, versions, root):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def write_authenticated_regtest_generation(
    directory: Path, generation: int, envelope: bytes, *,
    scope_digest: str, tip_height: int, tip_hash: str, predecessor_digest: str,
    checkpoint_schema: int, key_epoch: int, metadata_key: bytes,
) -> str:
    """Persist MAC-bound metadata before ready marker, without freshness claim.

    Metadata key must come from an independently random secret. No key or
    password is written. Existing v1 callers stay explicitly unanchored.
    """
    from .checkpoint_metadata_auth import (
        CheckpointExpectation, authenticate_checkpoint_metadata,
    )
    manifest = _generation_manifest(
        generation, envelope, scope_digest=scope_digest, tip_height=tip_height,
        tip_hash=tip_hash, predecessor_digest=predecessor_digest,
    )
    metadata = authenticate_checkpoint_metadata(
        manifest, envelope, key=metadata_key,
        expected=CheckpointExpectation(scope_digest, generation,
                                       checkpoint_schema, key_epoch),
    )
    return _persist_generation(directory, generation, envelope, manifest, metadata)


def read_authenticated_regtest_generation(
    directory: Path, generation: int, *, scope_digest: str,
    checkpoint_schema: int, key_epoch: int, metadata_key: bytes,
    allow_unanchored_synthetic: bool = False,
) -> tuple[dict, bytes]:
    """Authenticate selected generation; trusted/protected restore still denies.

    An entire older valid directory + matching old metadata key is replayable.
    No automatic latest, downgrade, key search or trust-provider activation.
    """
    if allow_unanchored_synthetic is not True:
        raise VersionedCheckpointError("SNAPSHOT_TRUSTED_ANCHOR_REQUIRED")
    from .checkpoint_metadata_auth import (
        CheckpointExpectation, verify_checkpoint_metadata, validate_checkpoint_binding,
    )
    expected = CheckpointExpectation(scope_digest, generation, checkpoint_schema, key_epoch)
    validate_checkpoint_binding(expected, metadata_key)
    manifest, envelope, metadata = _load_generation(directory, generation, authenticated=True)
    authenticated = verify_checkpoint_metadata(
        metadata, envelope, key=metadata_key,
        expected=expected,
    )
    if authenticated != manifest:
        raise VersionedCheckpointError("SNAPSHOT_AUTHENTICATED_MANIFEST_DENIED")
    return authenticated, envelope
