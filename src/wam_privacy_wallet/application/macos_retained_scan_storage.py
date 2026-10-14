"""Native macOS retained WSP SQLite custody for DISPOSABLE REGTEST ONLY.

Keep the actual SQLite inode open while the upstream WSP Scanner uses its
pathname. The final 0700 private directory remains descriptor-held and
advisory-flock-locked for the lifetime of the scanner operation.

Not a race-free SQLite FD handoff: SQLite opens a separate pathname, and a
same-UID malicious process could substitute that name. This adapter checks the
dev/inode again before releasing scan results; it is NOT production custody or
trusted anti-rollback (#148/#151). Never use real seeds/funds.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import stat
import struct
import sys
try:
    import fcntl
except ImportError:
    fcntl = None

from .macos_private_directory import (
    _require_absent_acl, open_macos_private_directory,
    validate_macos_private_directory,
)

_DB = "scan-only-state.sqlite"
_LIMIT = 1024 ** 3


class MacosRetainedScanStoreError(ValueError):
    """Redacted fixed denial, never private path, schema, or account contents."""


def _capability() -> None:
    if (sys.platform != "darwin" or struct.calcsize("P") != 8
            or platform.machine().lower() != "arm64" or fcntl is None
            or not all(hasattr(os, k) for k in
                       ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "O_DIRECTORY"))
            or not all(hasattr(fcntl, k) for k in ("LOCK_EX", "LOCK_NB"))
            or os.open not in getattr(os, "supports_dir_fd", ())):
        raise MacosRetainedScanStoreError("MACOS_SCAN_DB_PLATFORM_DENIED")


def _check_db(fd: int, dir_fd: int):
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or before.st_size > _LIMIT
            or os.get_inheritable(fd)):
        raise MacosRetainedScanStoreError("MACOS_SCAN_DB_FILE_DENIED")
    _require_absent_acl(fd)
    named = os.stat(_DB, dir_fd=dir_fd, follow_symlinks=False)
    if (not stat.S_ISREG(named.st_mode)
            or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
            or (before.st_mode, before.st_uid, before.st_nlink) !=
               (named.st_mode, named.st_uid, named.st_nlink)):
        raise MacosRetainedScanStoreError("MACOS_SCAN_DB_IDENTITY_DENIED")
    final = os.fstat(fd)
    if ((before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_nlink)
            != (final.st_dev, final.st_ino, final.st_mode, final.st_uid, final.st_nlink)):
        raise MacosRetainedScanStoreError("MACOS_SCAN_DB_IDENTITY_DENIED")
    return (before.st_dev, before.st_ino)


class MacosRetainedScanStore:
    """Holds validated directory + sqlite inode FDs across actual scanner work."""

    __slots__ = ("path", "_directory", "_database", "_identity", "_closed")

    def __init__(self, directory: Path):
        _capability()
        if (type(directory) is not type(Path()) or not directory.is_absolute()
                or ".." in directory.parts):
            raise MacosRetainedScanStoreError("MACOS_SCAN_DB_INPUT_DENIED")
        self._directory = self._database = None
        self._closed = True
        self.path = directory / _DB
        self._identity = None
        try:
            self._directory = open_macos_private_directory(directory)
            fcntl.flock(self._directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
            validate_macos_private_directory(self._directory)
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            try:
                self._database = os.open(
                    _DB, flags | os.O_CREAT | os.O_EXCL, 0o600,
                    dir_fd=self._directory,
                )
            except FileExistsError:
                self._database = os.open(
                    _DB, flags, dir_fd=self._directory,
                )
            self._identity = _check_db(self._database, self._directory)
            validate_macos_private_directory(self._directory)
            self._closed = False
        except Exception:
            self._release()
            raise MacosRetainedScanStoreError("MACOS_SCAN_DB_OPEN_DENIED") from None

    def verify(self) -> None:
        if self._closed or self._directory is None or self._database is None:
            raise MacosRetainedScanStoreError("MACOS_SCAN_DB_CLOSED")
        try:
            validate_macos_private_directory(self._directory)
            if _check_db(self._database, self._directory) != self._identity:
                raise MacosRetainedScanStoreError("MACOS_SCAN_DB_IDENTITY_DENIED")
        except Exception:
            raise MacosRetainedScanStoreError("MACOS_SCAN_DB_CHANGED_DENIED") from None

    def _release(self) -> None:
        self._closed = True
        failed = False
        for name in ("_database", "_directory"):
            fd = getattr(self, name, None)
            setattr(self, name, None)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    failed = True
        if failed:
            raise MacosRetainedScanStoreError("MACOS_SCAN_DB_CLOSE_DENIED")

    def close(self) -> None:
        if self._closed:
            return
        failed = False
        try:
            self.verify()
        except Exception:
            failed = True
        finally:
            try:
                self._release()
            except Exception:
                failed = True
        if failed:
            raise MacosRetainedScanStoreError("MACOS_SCAN_DB_CLOSE_DENIED")
