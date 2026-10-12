"""Bridge actual GnuPG-signed WAM Linux distribution to sealed Linux memory.

No Core spawn, executable file extraction, process-image claim, wallet keys,
launcher API or mainnet path. An authenticated archive plus an immutable fd
is NOT automatically authenticated running code: issue #36 remains blocked.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import sys
import tarfile
from typing import Iterator

from .core_signed_release import (
    CoreReleaseSignatureError, verify_wam_signed_distribution,
)
from .core_archive_inventory import (
    CoreArchiveInventoryError, inspect_wam_core_archive,
)
from .core_artifact_staging import (
    CoreArtifactStagingError, stage_untrusted_core_artifact,
)
from .core_linux_sealed_snapshot import (
    KernelSealedReview, LinuxCoreSealError, fcntl,
)

# Independently confirmed by native official signed archive verification
# https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38148529648
_LINUX_ARCHIVE = "wam-coin-v0.1.11-x86_64-linux-gnu.tar.gz"
_MEMBER = "wam-coin-v0.1.11/bin/wamd"
_ARCHIVE_SHA = "bd010ed615ab8063d5c12aa61236311ece7e9d19896d9541dacba1888dd9987a"
_MEMBER_SHA = "625609c08afef441e9dddd71330dcab1cec112d6fabe361769b9907f0efe7ab4"
_MAX_MEMBER_BYTES = 128 * 1024 * 1024
_CHUNK = 1 << 20
# Linux UAPI MFD_NOEXEC_SEAL: disallow executing the review descriptor. If
# the host does not support it, do not fall back to executable anonymous fd.
_MFD_NOEXEC_SEAL = 0x0008


class SignedNodeSealError(ValueError):
    """Fixed denial, never filename, key path, archive member or GPG output."""


@contextmanager
def sealed_signed_linux_wamd(
    *, archive: Path, key: Path, checksums: Path,
    signature: Path, gpg: Path,
) -> Iterator[KernelSealedReview]:
    """Independently verify official signature, archive, member, then seal fd.

    Re-review the same *fixed* signed distribution in every invocation;
    a caller-crafted SignedDistributionEvidence instance is not accepted.
    Every executable permission stays FALSE, and no opened fd/path escapes
    after context exit. Unsupported OS or non-regtest platform never falls
    back to a less protected ordinary file.
    """
    if (sys.platform != "linux" or fcntl is None
            or not hasattr(os, "memfd_create")
            or not hasattr(os, "MFD_ALLOW_SEALING")
            or not hasattr(os, "MFD_CLOEXEC")
            or any(not hasattr(fcntl, name) for name in
                   ("F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE",
                    "F_SEAL_SHRINK", "F_SEAL_GROW", "F_SEAL_SEAL"))):
        raise SignedNodeSealError("CORE_SIGNED_SEAL_PLATFORM_DENIED")
    if any(type(part) is not type(Path()) or not part.is_absolute()
           for part in (archive, key, checksums, signature, gpg)):
        raise SignedNodeSealError("CORE_SIGNED_SEAL_PATH_DENIED")
    if archive.name != _LINUX_ARCHIVE:
        raise SignedNodeSealError("CORE_SIGNED_SEAL_ASSET_DENIED")

    fd = -1
    review: KernelSealedReview | None = None
    try:
        # The verifier actually invokes GnuPG with the independently pinned
        # WAM primary signing fingerprint; SHA from caller alone is not trust.
        signed = verify_wam_signed_distribution(
            signing_key=key, sha256sums=checksums,
            detached_signature=signature, archive=archive,
            archive_name=_LINUX_ARCHIVE, gpg_executable=gpg,
        )
        if (signed.distribution_sha256 != _ARCHIVE_SHA
                or signed.core_execution_allowed is not False
                or signed.extracted_binary_verified is not False):
            raise SignedNodeSealError("CORE_SIGNED_SEAL_RELEASE_DENIED")

        inventory = inspect_wam_core_archive(
            archive=archive, signed_receipt=signed,
        )
        if (inventory.node_entry != _MEMBER
                or inventory.node_sha256 != _MEMBER_SHA
                or not 1 <= inventory.node_byte_count <= _MAX_MEMBER_BYTES
                or inventory.core_execution_allowed is not False):
            raise SignedNodeSealError("CORE_SIGNED_SEAL_MEMBER_DENIED")

        # Re-hash the entire archive into a disposable nonexecuting snapshot
        # before streaming the single approved member directly into memfd.
        with stage_untrusted_core_artifact(archive, _ARCHIVE_SHA) as staged:
            fd = os.memfd_create(
                "wam-signed-release-review-noexec",
                os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | _MFD_NOEXEC_SEAL,
            )
            digest = hashlib.sha256()
            count = 0
            found = 0
            with tarfile.open(staged.snapshot_path, mode="r:gz") as bundle:
                for entry in bundle:
                    if entry.name != _MEMBER:
                        continue
                    found += 1
                    if (found != 1 or not entry.isfile()
                            or entry.size != inventory.node_byte_count):
                        raise SignedNodeSealError("CORE_SIGNED_SEAL_MEMBER_DENIED")
                    stream = bundle.extractfile(entry)
                    if stream is None:
                        raise SignedNodeSealError("CORE_SIGNED_SEAL_MEMBER_DENIED")
                    with stream:
                        while count < entry.size:
                            part = stream.read(min(_CHUNK, entry.size - count))
                            if not part:
                                raise SignedNodeSealError("CORE_SIGNED_SEAL_MEMBER_DENIED")
                            count += len(part)
                            digest.update(part)
                            view = memoryview(part)
                            while view:
                                n = os.write(fd, view)
                                if n <= 0:
                                    raise SignedNodeSealError("CORE_SIGNED_SEAL_WRITE_DENIED")
                                view = view[n:]
                        if stream.read(1):
                            raise SignedNodeSealError("CORE_SIGNED_SEAL_MEMBER_DENIED")
            if found != 1 or count != inventory.node_byte_count:
                raise SignedNodeSealError("CORE_SIGNED_SEAL_MEMBER_DENIED")
            if digest.hexdigest() != _MEMBER_SHA:
                raise SignedNodeSealError("CORE_SIGNED_SEAL_DIGEST_DENIED")

            seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                     | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            review = KernelSealedReview(fd, _MEMBER_SHA, count, seals)
            review.audit()
            yield review
            review.audit()
    except SignedNodeSealError:
        raise
    except (CoreReleaseSignatureError, CoreArchiveInventoryError,
            CoreArtifactStagingError, LinuxCoreSealError, OSError,
            tarfile.TarError, EOFError, ValueError, TypeError, MemoryError):
        raise SignedNodeSealError("CORE_SIGNED_SEAL_DENIED") from None
    finally:
        if review is not None:
            review._invalidate()
        if fd >= 0:
            os.close(fd)
