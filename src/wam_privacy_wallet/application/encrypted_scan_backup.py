"""Linux-only fail-closed storage for ALREADY encrypted WSP scan-only envelopes.

EXPERIMENTAL synthetic/regtest qualification, not production custody.
Cryptography is supplied by upstream pinned WSP-1 export_scan/import_scan, NEVER
implemented here. An upstream scan-only backup can contain scan secrets when
decrypted; this module only handles ciphertext. It never stores spending keys,
seeds, passphrases, decrypted accounts, or WSP SQLite.

Create-only: no overwrite, rotate, delete, mutable manifests or auto-migration.
Atomic hard-link publication after fsync avoids exposing partially written
envelopes under the canonical name. This does NOT defend against same-UID
malware, power loss on all filesystems, ACL/mount policy tricks, rollback of the
whole private directory, or a compromised OS. Linux and private directories
only; Windows/macOS require separately reviewed implementations.
"""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat
import sys

_ENVELOPE = "scan-only.wsp.enc"
_MAX_ENVELOPE = 1_048_576
_MIN_ENVELOPE = 52


class EncryptedScanBackupError(ValueError):
    """Stable non-sensitive refusal vocabulary."""


def _directory(directory: Path) -> int:
    if (sys.platform != "linux"
            or type(directory) is not type(Path()) or not directory.is_absolute()
            or not all(hasattr(os, f) for f in
                       ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"))):
        raise EncryptedScanBackupError("SCAN_BACKUP_PLATFORM_OR_PATH_DENIED")
    try:
        fd = os.open(
            directory, os.O_RDONLY | os.O_DIRECTORY
            | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        s = os.fstat(fd)
        if (not stat.S_ISDIR(s.st_mode)
                or stat.S_IMODE(s.st_mode) != 0o700
                or s.st_uid != os.geteuid()
                or s.st_nlink < 2):
            os.close(fd)
            raise EncryptedScanBackupError("SCAN_BACKUP_PRIVATE_DIR_DENIED")
        return fd
    except EncryptedScanBackupError:
        raise
    except Exception:
        raise EncryptedScanBackupError("SCAN_BACKUP_PRIVATE_DIR_DENIED") from None


def _valid_payload(payload: object) -> bool:
    return type(payload) is bytes and _MIN_ENVELOPE <= len(payload) <= _MAX_ENVELOPE


def provision_encrypted_scan_backup(directory: Path, encrypted_scan: bytes) -> None:
    """Atomically publish one encrypted scan-only without replacement.

    The status is successful ONLY after the temporary inode has been unlinked
    and the final directory fsync completed. A failed cleanup/durability step
    always returns a stable refusal, even if the canonical hard link now
    exists. Never unlink the canonical file after an ambiguous publication:
    another process might be using it and create-only semantics must hold.
    """
    if not _valid_payload(encrypted_scan):
        raise EncryptedScanBackupError("SCAN_BACKUP_INPUT_DENIED")
    dfd = _directory(directory)
    temp = ".scan-only-stage-" + secrets.token_hex(16)
    fd = None
    staged = False
    failed = False
    try:
        fd = os.open(
            temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
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
        while offset < len(encrypted_scan):
            count = os.write(fd, encrypted_scan[offset:])
            if count <= 0:
                raise OSError("short write")
            offset += count
        os.fsync(fd)
        os.close(fd)
        fd = None
        # The canonical name is created ONLY when absent. No replacing it.
        # A canonical file is never exposed before the encrypted bytes sync.
        os.link(
            temp, _ENVELOPE,
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
                os.unlink(temp, dir_fd=dfd)
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
        raise EncryptedScanBackupError("SCAN_BACKUP_STORE_DENIED") from None


def load_encrypted_scan_backup(directory: Path) -> bytes:
    """Read ONLY a private, single-link regular encrypted scan-only envelope.

    Full size and file identity checked around the bounded read; no WSP import
    or decryption occurs here. Never log paths, file content or upstream errors.
    """
    dfd = _directory(directory)
    fd = None
    try:
        fd = os.open(
            _ENVELOPE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            | os.O_NONBLOCK, dir_fd=dfd,
        )
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or not _MIN_ENVELOPE <= before.st_size <= _MAX_ENVELOPE):
            raise EncryptedScanBackupError("SCAN_BACKUP_FILE_DENIED")
        chunks = []
        remaining = before.st_size
        while remaining:
            part = os.read(fd, remaining)
            if not part:
                raise EncryptedScanBackupError("SCAN_BACKUP_FILE_DENIED")
            chunks.append(part)
            remaining -= len(part)
        after = os.fstat(fd)
        if (before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns
                or after.st_nlink != 1):
            raise EncryptedScanBackupError("SCAN_BACKUP_FILE_DENIED")
        payload = b"".join(chunks)
        if not _valid_payload(payload):
            raise EncryptedScanBackupError("SCAN_BACKUP_FILE_DENIED")
        return payload
    except EncryptedScanBackupError:
        raise
    except Exception:
        raise EncryptedScanBackupError("SCAN_BACKUP_LOAD_DENIED") from None
    finally:
        if fd is not None:
            os.close(fd)
        os.close(dfd)
