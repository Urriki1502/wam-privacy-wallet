"""Nonexecuting Linux-kernel sealed snapshot for disposable regtest artifact review.

This exercises real Linux memfd F_ADD_SEALS with explicitly verified byte
digests, without executing WAM Core or producing a launch capability. Sealing
an operator-selected file does NOT authenticate WAM publisher provenance,
make a kernel-executed-image claim, or close the complete issue #36 gate.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import sys
from typing import Iterator

try:
    import fcntl
except ImportError:  # Windows: reject without any kernel operation.
    fcntl = None

from .core_artifact_staging import (
    CoreArtifactStagingError, stage_untrusted_core_artifact,
)

_MAX_SEAL_BYTES = 128 * 1024 * 1024
_CHUNK = 1024 * 1024


class LinuxCoreSealError(ValueError):
    """Redacted denial; never embeds source path, descriptor or file bytes."""


@dataclass(frozen=True, slots=True)
class KernelSealedEvidence:
    """Kernel immutability observation, deliberately NON-authorizing."""

    sha256: str = field(repr=False)
    byte_count: int
    seal_flags_verified: bool
    status: str = field(default="KERNEL_SEALED_UNTRUSTED_REVIEW_ONLY", init=False)
    publisher_authenticated: bool = field(default=False, init=False)
    execution_identity_bound: bool = field(default=False, init=False)
    core_execution_allowed: bool = field(default=False, init=False)
    real_wallet_allowed: bool = field(default=False, init=False)
    mainnet_allowed: bool = field(default=False, init=False)
    genuine_two_node_qualified: bool = field(default=False, init=False)


class KernelSealedReview:
    """Ephemeral closed-over fd; never exports an executable path or launch API."""

    __slots__ = ("_descriptor", "_digest", "_identity", "evidence", "_seals")

    def __init__(self, descriptor: int, digest: str, size: int, seals: int):
        # The review object is NOT a launch permit. Nevertheless, callers
        # cannot manufacture seal_flags_verified=True by passing seal mask 0
        # or an unsealed descriptor, even with matching synthetic bytes.
        if (fcntl is None
                or any(not hasattr(fcntl, key) for key in
                       ("F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL"))
                or type(descriptor) is not int or descriptor < 0
                or type(digest) is not str or len(digest) != 64
                or any(ch not in "0123456789abcdef" for ch in digest)
                or type(size) is not int or not 1 <= size <= _MAX_SEAL_BYTES
                or type(seals) is not int
                or seals != (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                             | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)):
            raise LinuxCoreSealError("CORE_SEAL_REVIEW_DENIED")
        self._descriptor = descriptor
        self._digest = digest
        self._seals = seals
        try:
            info = os.fstat(descriptor)
            self._identity = (info.st_dev, info.st_ino)
        except OSError:
            raise LinuxCoreSealError("CORE_SEAL_REVIEW_DENIED") from None
        self.evidence = KernelSealedEvidence(digest, size, True)
        # Bind the first receipt to an actual currently sealed kernel object.
        self.audit()

    def _invalidate(self) -> None:
        # Poison the numeric fd before the context closes it. An unrelated
        # future fd with the same number can never revive old evidence.
        self._descriptor = -1

    def audit(self) -> bool:
        """Check current kernel seal bits and bounded fd contents, no execution."""
        try:
            if self._descriptor < 0 or fcntl is None:
                raise LinuxCoreSealError("CORE_SEAL_CLOSED")
            held = fcntl.fcntl(self._descriptor, fcntl.F_GET_SEALS)
            info = os.fstat(self._descriptor)
            size = info.st_size
            if (held & self._seals != self._seals
                    or size != self.evidence.byte_count
                    or (info.st_dev, info.st_ino) != self._identity):
                raise LinuxCoreSealError("CORE_SEAL_CHANGED")
            digest = hashlib.sha256()
            position = 0
            while position < size:
                piece = os.pread(self._descriptor, min(_CHUNK, size - position), position)
                if not piece:
                    raise LinuxCoreSealError("CORE_SEAL_CHANGED")
                digest.update(piece)
                position += len(piece)
            if digest.hexdigest() != self._digest:
                raise LinuxCoreSealError("CORE_SEAL_CHANGED")
            return True
        except LinuxCoreSealError:
            raise
        except (OSError, ValueError, TypeError):
            raise LinuxCoreSealError("CORE_SEAL_CHANGED") from None


@contextmanager
def sealed_linux_regtest_review(
    source: object, claimed_sha256: object, *, network: object = "regtest",
) -> Iterator[KernelSealedReview]:
    """Build a real F_SEAL_WRITE + size-sealed memfd from untrusted bytes.

    This is a *review* primitive only. It has no subprocess/exec/fexecve path
    and does not expose a decision allowing anybody to run WAM Core. The fd
    is closed on every success/failure exit. macOS/Windows reject explicitly.
    """
    if type(network) is not str or network != "regtest":
        raise LinuxCoreSealError("CORE_SEAL_NETWORK_DENIED")
    if (sys.platform != "linux" or fcntl is None
            or not hasattr(os, "memfd_create")
            or not hasattr(os, "MFD_ALLOW_SEALING")
            or any(not hasattr(fcntl, name) for name in
                   ("F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE",
                    "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL"))):
        raise LinuxCoreSealError("CORE_SEAL_PLATFORM_DENIED")
    fd = -1
    review: KernelSealedReview | None = None
    try:
        with stage_untrusted_core_artifact(
            source, claimed_sha256, network="regtest",
        ) as staged:
            if not 1 <= staged.byte_count <= _MAX_SEAL_BYTES:
                raise LinuxCoreSealError("CORE_SEAL_SIZE_DENIED")
            fd = os.memfd_create(
                "wam-untrusted-regtest-review",
                os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
            )
            digest = hashlib.sha256()
            count = 0
            with Path(staged.snapshot_path).open("rb") as input_file:
                while True:
                    chunk = input_file.read(_CHUNK)
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > _MAX_SEAL_BYTES:
                        raise LinuxCoreSealError("CORE_SEAL_SIZE_DENIED")
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        amount = os.write(fd, view)
                        if amount <= 0:
                            raise LinuxCoreSealError("CORE_SEAL_WRITE_DENIED")
                        view = view[amount:]
            if count != staged.byte_count or digest.hexdigest() != staged.sha256:
                raise LinuxCoreSealError("CORE_SEAL_DIGEST_DENIED")
            seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                     | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            review = KernelSealedReview(fd, staged.sha256, count, seals)
            review.audit()
            yield review
            review.audit()
    except LinuxCoreSealError:
        raise
    except (CoreArtifactStagingError, OSError, TypeError, ValueError):
        raise LinuxCoreSealError("CORE_SEAL_INPUT_DENIED") from None
    finally:
        if review is not None:
            review._invalidate()
        if fd >= 0:
            os.close(fd)
