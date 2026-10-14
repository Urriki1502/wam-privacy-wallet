"""Create-once macOS custody for already-encrypted WSP scan-only envelopes.

EXPERIMENTAL disposable REGTEST preparation. No encryption, keys, WSP imports,
SQLite, signer or Core. Native flush success is not a universal power-loss
guarantee, an independent freshness anchor or protection from same-UID malware.
"""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat
import sys
try:
    import fcntl
except ImportError:
    fcntl = None

from .macos_private_directory import (
    _require_absent_acl, open_macos_private_directory,
    validate_macos_private_directory,
)

_NAME = "scan-only.wsp.enc"
_MAGIC = b"WAMSP02\x00"
_MIN = 52
_MAX = 1_048_576


class MacosEncryptedScanBackupError(ValueError):
    """Fixed non-sensitive refusal vocabulary."""


def _capabilities() -> None:
    support = getattr(os, "supports_dir_fd", None)
    if (sys.platform != "darwin" or fcntl is None
            or not hasattr(fcntl, "F_FULLFSYNC")
            or not all(hasattr(fcntl, flag) for flag in ("LOCK_EX", "LOCK_NB"))
            or not callable(getattr(fcntl, "fcntl", None))
            or not callable(getattr(fcntl, "flock", None))
            or not all(hasattr(os, flag) for flag in
                       ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "O_DIRECTORY"))
            or type(support) is not set
            or any(function not in support for function in
                   (os.open, os.stat, os.link, os.unlink))
            or os.link not in os.supports_follow_symlinks):
        raise MacosEncryptedScanBackupError("MACOS_SCAN_BACKUP_CAPABILITY_DENIED")


def _valid(payload: object) -> bool:
    return (type(payload) is bytes and _MIN <= len(payload) <= _MAX
            and payload.startswith(_MAGIC))


def _identity(info) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _inspect_file(fd: int, links: int, *, size: int | None = None):
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.geteuid() or before.st_nlink != links
            or os.get_inheritable(fd)
            or (size is None and not _MIN <= before.st_size <= _MAX)
            or (size is not None and before.st_size != size)):
        raise MacosEncryptedScanBackupError("MACOS_SCAN_BACKUP_FILE_DENIED")
    # The Darwin directory module supplies the same descriptor ACL boundary
    # for regular files. No chmod/pathname ACL subprocess is used here.
    _require_absent_acl(fd)
    if _identity(before) != _identity(os.fstat(fd)):
        raise MacosEncryptedScanBackupError("MACOS_SCAN_BACKUP_FILE_DENIED")
    return before


def _named_inode(directory: int, name: str, expected) -> None:
    observed = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if _identity(observed) != _identity(expected):
        raise MacosEncryptedScanBackupError("MACOS_SCAN_BACKUP_FILE_DENIED")


def _remove_owned_stage(directory: int, name: str, fd: int) -> None:
    # Never clean up a replacement inode merely because it has our old name.
    _named_inode(directory, name, os.fstat(fd))
    os.unlink(name, dir_fd=directory)


def _full_flush(fd: int) -> None:
    if fcntl.fcntl(fd, fcntl.F_FULLFSYNC) != 0:
        raise OSError("native full flush denied")


def provision_macos_encrypted_scan_backup(directory: Path, encrypted_scan: bytes) -> None:
    """Publish one bounded encrypted scan envelope without replacement.

    Keep the staged descriptor through publication and verify both names refer
    to that inode. Success requires stage removal and final directory fsync.
    On ambiguous publication, never unlink the canonical name or claim success.
    """
    _capabilities()
    if not _valid(encrypted_scan):
        raise MacosEncryptedScanBackupError("MACOS_SCAN_BACKUP_INPUT_DENIED")
    directory_fd = file_fd = None
    stage = None
    staged = False
    failed = False
    final = None
    try:
        directory_fd = open_macos_private_directory(directory)
        # Hold a native nonblocking directory lease until descriptor close;
        # no mutable lockfile or no-op fallback. Advisory, not a trust anchor.
        fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stage = ".macos-scan-stage-" + secrets.token_hex(16)
        file_fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                          | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                          dir_fd=directory_fd)
        staged = True
        os.fchmod(file_fd, 0o600)
        _named_inode(directory_fd, stage, _inspect_file(file_fd, 1, size=0))
        offset = 0
        while offset < len(encrypted_scan):
            written = os.write(file_fd, encrypted_scan[offset:])
            if not 1 <= written <= len(encrypted_scan) - offset:
                raise OSError("short write")
            offset += written
        _full_flush(file_fd)
        prepared = _inspect_file(file_fd, 1, size=len(encrypted_scan))
        _named_inode(directory_fd, stage, prepared)
        validate_macos_private_directory(directory_fd)
        os.link(stage, _NAME, src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                follow_symlinks=False)
        linked = _inspect_file(file_fd, 2, size=len(encrypted_scan))
        _named_inode(directory_fd, stage, linked)
        _named_inode(directory_fd, _NAME, linked)
        validate_macos_private_directory(directory_fd)
        _remove_owned_stage(directory_fd, stage, file_fd)
        staged = False
        final = _inspect_file(file_fd, 1, size=len(encrypted_scan))
        _named_inode(directory_fd, _NAME, final)
    except Exception:
        failed = True
    finally:
        if staged and directory_fd is not None and file_fd is not None:
            try:
                _remove_owned_stage(directory_fd, stage, file_fd)
            except Exception:
                failed = True
        if directory_fd is not None:
            try:
                # Persist publication and stage removal, including cleanup on
                # failed attempts. A failed fsync must not produce success.
                os.fsync(directory_fd)
                if not failed:
                    validate_macos_private_directory(directory_fd)
                    after = _inspect_file(file_fd, 1, size=len(encrypted_scan))
                    if _identity(final) != _identity(after):
                        raise ValueError("published inode changed")
                    _named_inode(directory_fd, _NAME, after)
            except Exception:
                failed = True
        for descriptor in (file_fd, directory_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    failed = True
    if failed:
        raise MacosEncryptedScanBackupError("MACOS_SCAN_BACKUP_STORE_DENIED") from None


def load_macos_encrypted_scan_backup(directory: Path) -> bytes:
    """Return bounded opaque ciphertext from one unchanged private inode.

    Shape validation is not AES-GCM authentication. Only the independently
    source-qualified upstream import_scan may authenticate/decrypt the bytes.
    """
    _capabilities()
    directory_fd = file_fd = None
    failed = False
    payload = None
    try:
        directory_fd = open_macos_private_directory(directory)
        file_fd = os.open(_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                          | os.O_NONBLOCK, dir_fd=directory_fd)
        before = _inspect_file(file_fd, 1)
        _named_inode(directory_fd, _NAME, before)
        chunks = []
        remaining = before.st_size
        while remaining:
            part = os.read(file_fd, min(65536, remaining))
            if not part:
                raise ValueError("truncated envelope")
            chunks.append(part)
            remaining -= len(part)
        after = _inspect_file(file_fd, 1)
        if _identity(before) != _identity(after):
            raise ValueError("envelope changed during read")
        _named_inode(directory_fd, _NAME, after)
        validate_macos_private_directory(directory_fd)
        payload = b"".join(chunks)
        if not _valid(payload):
            raise ValueError("invalid envelope")
    except Exception:
        failed = True
    finally:
        for descriptor in (file_fd, directory_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    failed = True
    if failed:
        raise MacosEncryptedScanBackupError("MACOS_SCAN_BACKUP_LOAD_DENIED") from None
    return payload
