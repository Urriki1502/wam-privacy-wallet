"""Read-only *candidate* WAM Core Linux release audit; NO WAM execution.

This is a preflight for the NEXT official release described by DEV, NOT a
signature verifier. The expected SHA256 MUST independently come from the
already qualified official detached-signature + publisher trust workflow.
An arbitrary caller-supplied SHA is not publisher authentication.

Every regular file under bin/ must be ELF64 x86-64 with exactly one RW
PT_GNU_STACK and no RWX load segment. All archive members are structurally
inspected without extraction. The example conf must exist and be inert:
no active directives. This cannot establish help-option parity without
attested `wamd --help` emitted in the DEV build/release pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
from pathlib import Path
import re
import stat
import struct
import tarfile

_NAME = re.compile(r"wam-coin-(v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?)-x86_64-linux-gnu\.tar\.gz\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_MAX_ARCHIVE = 512 * 1024 * 1024
_MAX_MEMBER = 128 * 1024 * 1024
_MAX_TOTAL = 512 * 1024 * 1024
_MAX_MEMBERS = 256
_ELF_HEADER = struct.Struct("<HHIQQQIHHHHHH")
_ELF_PROGRAM = struct.Struct("<IIQQQQQQ")
_GNU_STACK = 0x6474E551


class CoreCandidateAuditError(ValueError):
    """Fixed non-sensitive error codes; never print unknown archive bytes."""


@dataclass(frozen=True, slots=True)
class CoreCandidateObservation:
    archive_sha256: str
    binary_names: tuple[str, ...]
    binary_sha256: tuple[str, ...]
    config_sha256: str
    status: str = "CANDIDATE_RELEASE_STATIC_INSPECTION_ONLY"
    signed_provenance_verified: bool = False
    help_parity_verified: bool = False
    dynamic_loader_verified: bool = False
    kernel_process_identity_verified: bool = False
    core_execution_allowed: bool = False
    real_regtest_qualified: bool = False
    signer_enabled: bool = False
    broadcast_allowed: bool = False
    mainnet_allowed: bool = False


def _check_elf(blob: bytes) -> None:
    if (len(blob) < 64 or blob[:7] != b"\x7fELF\x02\x01\x01"):
        raise CoreCandidateAuditError("CORE_CANDIDATE_ELF_HEADER_DENIED")
    try:
        (typ, arch, version, entry, phoff, _shoff, _flags,
         ehsize, phentsize, phnum, _shentsize, _shnum, _str) = (
             _ELF_HEADER.unpack_from(blob, 16)
         )
        if (typ not in (2, 3) or arch != 62 or version != 1
                or (typ == 2 and entry == 0) or ehsize != 64
                or phentsize != _ELF_PROGRAM.size
                or not 1 <= phnum <= 128
                or phoff < 64 or phoff + phnum * phentsize > len(blob)):
            raise CoreCandidateAuditError("CORE_CANDIDATE_ELF_HEADER_DENIED")
        stacks = 0
        loads = 0
        for n in range(phnum):
            (kind, flags, off, _va, _pa, size, memsz, _align) = (
                _ELF_PROGRAM.unpack_from(blob, phoff+n*phentsize)
            )
            if off > len(blob) or size > len(blob)-off:
                raise CoreCandidateAuditError("CORE_CANDIDATE_ELF_SEGMENT_DENIED")
            if kind == 1:
                loads += 1
                if size > memsz or flags & 3 == 3:
                    raise CoreCandidateAuditError("CORE_CANDIDATE_ELF_WX_DENIED")
            elif kind == _GNU_STACK:
                stacks += 1
                if flags & 1:
                    raise CoreCandidateAuditError("CORE_CANDIDATE_EXECSTACK_DENIED")
                if flags & 6 != 6:
                    raise CoreCandidateAuditError("CORE_CANDIDATE_STACK_MODE_DENIED")
        if stacks != 1 or loads == 0:
            raise CoreCandidateAuditError("CORE_CANDIDATE_STACK_HEADER_DENIED")
    except CoreCandidateAuditError:
        raise
    except (ValueError, struct.error, OverflowError):
        raise CoreCandidateAuditError("CORE_CANDIDATE_ELF_HEADER_DENIED") from None


def _check_example(payload: bytes) -> None:
    if not payload or len(payload) > 256 * 1024 or b"\x00" in payload:
        raise CoreCandidateAuditError("CORE_CANDIDATE_EXAMPLE_DENIED")
    try:
        decoded = payload.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise CoreCandidateAuditError("CORE_CANDIDATE_EXAMPLE_DENIED") from None
    if not decoded.strip():
        raise CoreCandidateAuditError("CORE_CANDIDATE_EXAMPLE_DENIED")
    for line in decoded.splitlines():
        stripped = line.strip()
        # A package sample should not activate P2P/RPC or a network
        # selector just because a user copied it into a data directory.
        if stripped and not stripped.startswith(("#", ";")):
            raise CoreCandidateAuditError("CORE_CANDIDATE_ACTIVE_CONFIG_DENIED")


def inspect_next_linux_release(archive: Path, expected_sha256: str) -> CoreCandidateObservation:
    """Examine one locally supplied archive; never load or launch Core.

    Hash expectation alone is NOT a signature. A separate DEV-reviewed
    signed provenance step and generated-help exact parity remain HOLD.
    """
    if (type(archive) is not type(Path()) or not archive.is_absolute()
            or type(expected_sha256) is not str or not _SHA.fullmatch(expected_sha256)):
        raise CoreCandidateAuditError("CORE_CANDIDATE_INPUT_DENIED")
    match = _NAME.fullmatch(archive.name)
    if match is None:
        raise CoreCandidateAuditError("CORE_CANDIDATE_NAME_DENIED")
    root = "wam-coin-" + match.group(1)
    try:
        st = archive.lstat()
        if not stat.S_ISREG(st.st_mode) or not 1 <= st.st_size <= _MAX_ARCHIVE:
            raise CoreCandidateAuditError("CORE_CANDIDATE_PATH_DENIED")
        blob = archive.read_bytes()
        if (len(blob) != st.st_size or
                hashlib.sha256(blob).hexdigest() != expected_sha256):
            raise CoreCandidateAuditError("CORE_CANDIDATE_DIGEST_DENIED")
        bin_hashes = {}
        example_hash = None
        total = 0
        seen = set()
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            for count, member in enumerate(tf, 1):
                if count > _MAX_MEMBERS:
                    raise CoreCandidateAuditError("CORE_CANDIDATE_BOUNDS_DENIED")
                if not (member.isdir() or member.isfile()):
                    raise CoreCandidateAuditError("CORE_CANDIDATE_TYPE_DENIED")
                name = member.name.rstrip("/") if member.isdir() else member.name
                parts = name.split("/")
                if (len(parts) > 8 or not parts or parts[0] != root
                        or any(part in ("", ".", "..") for part in parts)
                        or any("\\" in part or "\x00" in part for part in parts)
                        or name.startswith("/")):
                    raise CoreCandidateAuditError("CORE_CANDIDATE_PATH_DENIED")
                key = name.casefold()
                if key in seen:
                    raise CoreCandidateAuditError("CORE_CANDIDATE_DUPLICATE_DENIED")
                seen.add(key)
                if member.isdir():
                    if member.size != 0:
                        raise CoreCandidateAuditError("CORE_CANDIDATE_TYPE_DENIED")
                    continue
                if not 0 <= member.size <= _MAX_MEMBER:
                    raise CoreCandidateAuditError("CORE_CANDIDATE_BOUNDS_DENIED")
                total += member.size
                if total > _MAX_TOTAL:
                    raise CoreCandidateAuditError("CORE_CANDIDATE_BOUNDS_DENIED")
                is_example = name == root + "/share/examples/wam.conf"
                in_bin = len(parts) >= 3 and parts[1] == "bin"
                f = tf.extractfile(member)
                if f is None:
                    raise CoreCandidateAuditError("CORE_CANDIDATE_TYPE_DENIED")
                with f:
                    prefix = f.read(min(member.size, 7))
                    is_elf = prefix.startswith(b"\x7fELF")
                    if is_example or in_bin or is_elf:
                        content = prefix + f.read(member.size-len(prefix)+1)
                        if len(content) != member.size:
                            raise CoreCandidateAuditError("CORE_CANDIDATE_BOUNDS_DENIED")
                        if is_example:
                            _check_example(content)
                            example_hash = hashlib.sha256(content).hexdigest()
                        else:
                            # Every ELF anywhere in the tarball is checked,
                            # including nested bin and non-executable DSOs.
                            # Non-ELF files under bin fail closed.
                            _check_elf(content)
                            label = ("/".join(parts[2:]) if in_bin
                                     else "/".join(parts[1:]))
                            bin_hashes[label] = hashlib.sha256(content).hexdigest()
                    else:
                        # Still consume and bound all non-ELF documentation.
                        remaining = member.size-len(prefix)
                        while remaining:
                            part = f.read(min(65536, remaining))
                            if not part:
                                raise CoreCandidateAuditError("CORE_CANDIDATE_BOUNDS_DENIED")
                            remaining -= len(part)
        if "wamd" not in bin_hashes:
            raise CoreCandidateAuditError("CORE_CANDIDATE_DAEMON_MISSING")
        if example_hash is None:
            raise CoreCandidateAuditError("CORE_CANDIDATE_EXAMPLE_MISSING")
        return CoreCandidateObservation(
            archive_sha256=expected_sha256,
            binary_names=tuple(sorted(bin_hashes)),
            binary_sha256=tuple(bin_hashes[name] for name in sorted(bin_hashes)),
            config_sha256=example_hash,
        )
    except CoreCandidateAuditError:
        raise
    except (OSError, tarfile.TarError, EOFError, ValueError, OverflowError, MemoryError):
        raise CoreCandidateAuditError("CORE_CANDIDATE_ARCHIVE_DENIED") from None
