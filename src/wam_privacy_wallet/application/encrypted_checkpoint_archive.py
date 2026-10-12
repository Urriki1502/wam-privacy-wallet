"""Linux-only create-once storage for ALREADY encrypted WSP-1 checkpoints.

EXPERIMENTAL synthetic/regtest-only, not production recovery.
Uses the source-pinned upstream Store.export_checkpoint/restore_checkpoint
AES-GCM protocol; this module implements no cryptography, decryption, keys,
signer or Core access. A fixed checkpoint name is immutable and cannot be
rotated/replaced. The archive is not authenticated *until* WSP restore.
No rollback detection, trusted clock, version chain, same-UID malware
protection, durable SQLite encryption or power-loss guarantee on every FS.
Windows/macOS intentionally refuse all persistence operations.
"""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat
import sys

# WSP upstream keystore.MAGIC under exact pinned source, not a crypto scheme.
_MAGIC = b"WAMSP02\x00"
_NAME = "wsp-checkpoint-v1.enc"
_MIN = 52
_MAX = 32 * 1024 * 1024 + 52


class EncryptedCheckpointArchiveError(ValueError):
    """Fixed failure codes without paths, credentials or archive bytes."""


def _open_private_dir(directory: Path) -> int:
    if (sys.platform != "linux"
            or type(directory) is not type(Path())
            or not directory.is_absolute()
            or not all(hasattr(os, n) for n in
                       ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"))):
        raise EncryptedCheckpointArchiveError("CHECKPOINT_PLATFORM_OR_PATH_DENIED")
    try:
        fd = os.open(
            directory,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        st = os.fstat(fd)
        if (not stat.S_ISDIR(st.st_mode)
                or stat.S_IMODE(st.st_mode) != 0o700
                or st.st_uid != os.geteuid()
                or st.st_nlink < 2):
            os.close(fd)
            raise EncryptedCheckpointArchiveError("CHECKPOINT_DIRECTORY_DENIED")
        return fd
    except EncryptedCheckpointArchiveError:
        raise
    except Exception:
        raise EncryptedCheckpointArchiveError("CHECKPOINT_DIRECTORY_DENIED") from None


def _well_formed(envelope: object) -> bool:
    return (
        type(envelope) is bytes
        and _MIN <= len(envelope) <= _MAX
        and envelope.startswith(_MAGIC)
    )


def store_encrypted_checkpoint(directory: Path, envelope: bytes) -> None:
    """Atomically publish one encrypted checkpoint without replacement.

    The status is successful ONLY after the temporary inode has been unlinked
    and the final directory fsync completed. A failed cleanup/durability step
    always returns a stable refusal, even if the canonical hard link now
    exists. Never unlink the canonical file after an ambiguous publication:
    another process might be using it and create-only semantics must hold.
    """
    if not _well_formed(envelope):
        raise EncryptedCheckpointArchiveError("CHECKPOINT_INPUT_DENIED")
    dfd = _open_private_dir(directory)
    stage = ".wsp-checkpoint-stage-" + secrets.token_hex(16)
    fd = None
    staged = False
    failed = False
    try:
        fd = os.open(
            stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=dfd,
        )
        staged = True
        os.fchmod(fd, 0o600)
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode)
                or stat.S_IMODE(meta.st_mode) != 0o600
                or meta.st_uid != os.geteuid()
                or meta.st_nlink != 1):
            raise OSError("invalid staged inode")
        offset = 0
        while offset < len(envelope):
            count = os.write(fd, envelope[offset:])
            if count <= 0:
                raise OSError("short write")
            offset += count
        os.fsync(fd)
        os.close(fd)
        fd = None
        # The canonical name is created ONLY when absent. No replacing it.
        # A canonical file is never exposed before the encrypted bytes sync.
        os.link(
            stage, _NAME,
            src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False,
        )
    except Exception:
        failed = True
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                failed = True
        if staged:
            try:
                os.unlink(stage, dir_fd=dfd)
            except OSError:
                # A published archive still linked to its stage has nlink=2,
                # which the reader rejects. Never silently declare success.
                failed = True
        try:
            # Synchronize the final directory state *after* stage removal.
            # A failure means durability is unknown, not successful.
            os.fsync(dfd)
        except OSError:
            failed = True
        try:
            os.close(dfd)
        except OSError:
            failed = True
    if failed:
        raise EncryptedCheckpointArchiveError("CHECKPOINT_STORE_DENIED") from None


def load_encrypted_checkpoint(directory: Path) -> bytes:
    """Return only bounded ciphertext from a private single-link regular file.

    Call source-verified WSP Store.restore_checkpoint to authenticate/decrypt
    this value. A successful read alone never authorizes wallet operations.
    """
    dfd = _open_private_dir(directory)
    fd = None
    try:
        fd = os.open(
            _NAME,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=dfd,
        )
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or not _MIN <= before.st_size <= _MAX):
            raise EncryptedCheckpointArchiveError("CHECKPOINT_FILE_DENIED")
        parts = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise EncryptedCheckpointArchiveError("CHECKPOINT_FILE_DENIED")
            parts.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if (before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns
                or after.st_nlink != 1):
            raise EncryptedCheckpointArchiveError("CHECKPOINT_FILE_DENIED")
        data = b"".join(parts)
        if not _well_formed(data):
            raise EncryptedCheckpointArchiveError("CHECKPOINT_FILE_DENIED")
        return data
    except EncryptedCheckpointArchiveError:
        raise
    except Exception:
        raise EncryptedCheckpointArchiveError("CHECKPOINT_LOAD_DENIED") from None
    finally:
        if fd is not None:
            os.close(fd)
        os.close(dfd)
