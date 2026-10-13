"""Native macOS descriptor custody for disposable REGTEST preparation.

This standalone boundary does not enable scanner, backup, checkpoint or GUI
operations. Linux storage remains separately qualified. No directory is
created or chmodded here. The caller owns the returned descriptor.
"""
from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import stat
import sys

_LIBSYSTEM = "/usr/lib/libSystem.B.dylib"
_ACL_TYPE_EXTENDED = 0x00000100  # Apple's public sys/acl.h, not a Linux ACL type.
_MAX_COMPONENTS = 256


class MacosPrivateDirectoryError(ValueError):
    """Fixed refusal vocabulary without paths or native diagnostic details."""


def _native_capabilities() -> None:
    dir_fd_support = getattr(os, "supports_dir_fd", None)
    if (sys.platform != "darwin"
            or not all(hasattr(os, name) for name in
                       ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"))
            or not all(callable(getattr(os, name, None)) for name in
                       ("open", "close", "fstat", "geteuid", "get_inheritable"))
            or type(dir_fd_support) is not set
            or os.open not in dir_fd_support):
        raise MacosPrivateDirectoryError("MACOS_PRIVATE_DIRECTORY_CAPABILITY_DENIED")


def _load_acl_api():
    # Absolute system-library path; no search-path discovery, shell helper or
    # pathname ACL query. Loading happens only after the Darwin capability gate.
    library = ctypes.CDLL(_LIBSYSTEM, use_errno=True)
    library.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    library.acl_get_fd_np.restype = ctypes.c_void_p
    library.acl_free.argtypes = [ctypes.c_void_p]
    library.acl_free.restype = ctypes.c_int
    return library


def _require_absent_acl(fd: int) -> None:
    library = _load_acl_api()
    ctypes.set_errno(0)
    acl = library.acl_get_fd_np(fd, _ACL_TYPE_EXTENDED)
    error = ctypes.get_errno()
    if acl:
        # Conservative: reject all explicit ACLs, including empty ACL objects.
        # acl_get_fd_np allocates an independent copy; always free that copy.
        try:
            library.acl_free(acl)
        finally:
            raise MacosPrivateDirectoryError("MACOS_PRIVATE_DIRECTORY_ACL_DENIED")
    # Apple Libc maps an absent FILESEC_ACL property to ENOENT. Other errors
    # (including an unsupported filesystem) must never mean 'no access ACL'.
    if error != errno.ENOENT:
        raise MacosPrivateDirectoryError("MACOS_PRIVATE_DIRECTORY_ACL_DENIED")


def _identity(info) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)


def validate_macos_private_directory(fd: int) -> None:
    """Check the held descriptor's native ownership, mode and absent ACL.

    ACL and metadata checks describe the inode at validation time. They cannot
    prevent later changes by its owner or a compromised OS. Revalidate before
    future uses; this is not an independent freshness or anti-rollback anchor.
    """
    _native_capabilities()
    if type(fd) is not int or fd < 0:
        raise MacosPrivateDirectoryError("MACOS_PRIVATE_DIRECTORY_DESCRIPTOR_DENIED")
    try:
        before = os.fstat(fd)
        if (not stat.S_ISDIR(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o700
                or before.st_uid != os.geteuid() or before.st_nlink < 1
                or os.get_inheritable(fd)):
            raise MacosPrivateDirectoryError("MACOS_PRIVATE_DIRECTORY_METADATA_DENIED")
        _require_absent_acl(fd)
        if _identity(before) != _identity(os.fstat(fd)):
            raise MacosPrivateDirectoryError("MACOS_PRIVATE_DIRECTORY_CHANGED")
    except MacosPrivateDirectoryError:
        raise
    except Exception:
        raise MacosPrivateDirectoryError("MACOS_PRIVATE_DIRECTORY_INSPECTION_DENIED") from None


def _open_component(name: str, parent: int | None) -> int:
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                   | os.O_CLOEXEC, dir_fd=parent)


def open_macos_private_directory(directory: Path) -> int:
    """Return a caller-owned descriptor after walking every ancestor no-follow.

    Retaining ancestor descriptors prevents concurrent pathname replacement
    from redirecting a later component. Shared system ancestors need not be
    owned by this UID or private; the final directory must pass native checks.
    No resolve(), permission changes, SQLite open, encryption or wallet import.
    """
    _native_capabilities()
    if (type(directory) is not type(Path()) or not directory.is_absolute()
            or directory.anchor != "/" or ".." in directory.parts
            or not 2 <= len(directory.parts) <= _MAX_COMPONENTS):
        raise MacosPrivateDirectoryError("MACOS_PRIVATE_DIRECTORY_PATH_DENIED")
    owned: list[int] = []
    result = None
    try:
        owned.append(_open_component(directory.anchor, None))
        for component in directory.parts[1:]:
            owned.append(_open_component(component, owned[-1]))
        validate_macos_private_directory(owned[-1])
        result = owned[-1]
    except MacosPrivateDirectoryError:
        raise
    except Exception:
        raise MacosPrivateDirectoryError("MACOS_PRIVATE_DIRECTORY_OPEN_DENIED") from None
    finally:
        cleanup_failed = False
        for descriptor in reversed(owned if result is None else owned[:-1]):
            try:
                os.close(descriptor)
            except OSError:
                cleanup_failed = True
        if cleanup_failed:
            if result is not None:
                try:
                    os.close(result)
                except OSError:
                    pass
            raise MacosPrivateDirectoryError("MACOS_PRIVATE_DIRECTORY_CLOSE_DENIED") from None
    return result
