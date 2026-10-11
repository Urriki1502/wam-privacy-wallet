"""Offline Core artifact staging only; no executable-identity or launch approval.

A matching *operator-supplied* hash is not publisher provenance and copying
a file does not close verify-to-Popen TOCTOU on every OS. Staged bytes have
no execute bit on POSIX and are NEVER passed to subprocess here.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Iterator

_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_BYTES = 512 * 1024 * 1024
_CHUNK = 1024 * 1024


class CoreArtifactStagingError(ValueError):
    """Redacted non-authorizing evidence error."""


@dataclass(frozen=True, slots=True)
class CoreArtifactStagingEvidence:
    """Ephemeral path, intentionally suppressed from repr/logs."""

    snapshot_path: Path = field(repr=False)
    sha256: str = field(repr=False)
    byte_count: int = 0
    status: str = field(default="OFFLINE_STAGED_UNTRUSTED", init=False)
    publisher_verified: bool = field(default=False, init=False)
    execution_identity_bound: bool = field(default=False, init=False)
    core_execution_allowed: bool = field(default=False, init=False)
    mainnet_allowed: bool = field(default=False, init=False)
    wallet_enabled: bool = field(default=False, init=False)


def _source_reparse(info: os.stat_result) -> bool:
    """Reject Windows reparse-point metadata even for a regular-looking file."""
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    """Conservative descriptor identity with explicit Windows reparse denial."""
    return (
        stat.S_ISREG(left.st_mode) and stat.S_ISREG(right.st_mode)
        and not _source_reparse(left) and not _source_reparse(right)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_nlink == 1 and right.st_nlink == 1
    )


@contextmanager
def stage_untrusted_core_artifact(
    source: object, claimed_sha256: object, *, network: object = "regtest",
) -> Iterator[CoreArtifactStagingEvidence]:
    """Copy bounded bytes to a disposable nonexecuting snapshot.

    Reject obvious swaps and size mutations before/after same-fd streaming,
    but explicitly DO NOT certify release provenance, ACL enforcement or the
    file-to-process identity gap. Caller may inspect hashes; no launch permit
    exists. The temporary directory is destroyed when the context exits.
    """
    if type(network) is not str or network != "regtest":
        raise CoreArtifactStagingError("CORE_STAGE_NETWORK_DENIED")
    if type(claimed_sha256) is not str or _SHA.fullmatch(claimed_sha256) is None:
        raise CoreArtifactStagingError("CORE_STAGE_DIGEST_DENIED")
    # Arbitrary __fspath__ user code is outside the trusted API boundary.
    # pathlib.Path() constructs PosixPath or WindowsPath, not the Path
    # factory class itself. Accept only those exact native types and str.
    if type(source) not in (str, type(Path())):
        raise CoreArtifactStagingError("CORE_STAGE_SOURCE_DENIED")
    try:
        candidate = Path(source)
        before = candidate.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or _source_reparse(before)):
            raise CoreArtifactStagingError("CORE_STAGE_SOURCE_DENIED")
        if not 1 <= before.st_size <= _MAX_BYTES:
            raise CoreArtifactStagingError("CORE_STAGE_SIZE_DENIED")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        with os.fdopen(os.open(candidate, flags), "rb") as stream:
            descriptor_before = os.fstat(stream.fileno())
            if not _same_stat(before, descriptor_before):
                raise CoreArtifactStagingError("CORE_STAGE_SOURCE_CHANGED")
            with tempfile.TemporaryDirectory(prefix="wam-core-stage-") as root:
                target = Path(root) / "untrusted-core-bytes.dat"
                digest = hashlib.sha256()
                count = 0
                with target.open("xb") as dest:
                    while True:
                        chunk = stream.read(_CHUNK)
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > _MAX_BYTES:
                            raise CoreArtifactStagingError("CORE_STAGE_SIZE_DENIED")
                        dest.write(chunk)
                        digest.update(chunk)
                descriptor_after = os.fstat(stream.fileno())
                pathname_after = candidate.lstat()
                if (not _same_stat(descriptor_before, descriptor_after)
                        or not _same_stat(descriptor_after, pathname_after)
                        or count != descriptor_before.st_size):
                    raise CoreArtifactStagingError("CORE_STAGE_SOURCE_CHANGED")
                if digest.hexdigest() != claimed_sha256:
                    raise CoreArtifactStagingError("CORE_STAGE_DIGEST_MISMATCH")
                # Independent rehash catches accidental staging corruption.
                staged = hashlib.sha256()
                with target.open("rb") as check:
                    for piece in iter(lambda: check.read(_CHUNK), b""):
                        staged.update(piece)
                if staged.hexdigest() != claimed_sha256:
                    raise CoreArtifactStagingError("CORE_STAGE_SNAPSHOT_CHANGED")
                os.chmod(target, 0o400)
                snapshot_before = target.lstat()
                yield CoreArtifactStagingEvidence(
                    snapshot_path=target, sha256=claimed_sha256,
                    byte_count=count,
                )
                # The review context is not a launch permit. Nevertheless
                # detect changes while the caller was inspecting the staged
                # file, including replacement or same-size byte mutation.
                try:
                    snapshot_after = target.lstat()
                    if not _same_stat(snapshot_before, snapshot_after):
                        raise CoreArtifactStagingError("CORE_STAGE_SNAPSHOT_CHANGED")
                    held_digest = hashlib.sha256()
                    with target.open("rb") as check:
                        for piece in iter(lambda: check.read(_CHUNK), b""):
                            held_digest.update(piece)
                    if held_digest.hexdigest() != claimed_sha256:
                        raise CoreArtifactStagingError("CORE_STAGE_SNAPSHOT_CHANGED")
                except OSError:
                    raise CoreArtifactStagingError("CORE_STAGE_SNAPSHOT_CHANGED") from None
    except CoreArtifactStagingError:
        raise
    except (OSError, TypeError, ValueError):
        raise CoreArtifactStagingError("CORE_STAGE_IO_DENIED") from None
