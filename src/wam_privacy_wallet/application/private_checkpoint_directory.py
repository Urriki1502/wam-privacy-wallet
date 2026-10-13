"""Linux descriptor custody shared by encrypted backup/checkpoint storage.

Reuses the versioned journal's component-by-component no-follow walk. It
rejects symlinks in EVERY ancestor, not merely the last path component.
This is a local file boundary, never an independent anti-rollback anchor or
protection against a compromised OS, mount policy or malicious same-UID code.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys


class PrivateCheckpointDirectoryError(ValueError):
    """Stable refusal without private paths."""


def validate_private_directory(fd: int) -> None:
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.geteuid()):
        raise PrivateCheckpointDirectoryError("PRIVATE_CHECKPOINT_DIRECTORY_DENIED")


def open_private_checkpoint_directory(directory: Path) -> int:
    """Return one caller-owned CLOEXEC descriptor; never resolve a symlink.

    Every traversal is relative to the preceding held directory descriptor.
    A concurrent rename cannot redirect an already-open component to a new
    pathname target. The final directory must be private and owned by this UID.
    Intermediate directory ownership/mounts and later pathname-based SQLite
    access are separate concerns; no whole-host trust claim is made.
    """
    if (sys.platform != "linux" or type(directory) is not type(Path())
            or not directory.is_absolute() or ".." in directory.parts
            or not all(hasattr(os, name) for name in
                       ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"))):
        raise PrivateCheckpointDirectoryError("PRIVATE_CHECKPOINT_PATH_DENIED")
    fd = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(directory.anchor, flags)
        for part in directory.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            previous, fd = fd, child
            os.close(previous)
        validate_private_directory(fd)
        result, fd = fd, None
        return result
    except PrivateCheckpointDirectoryError:
        raise
    except Exception:
        raise PrivateCheckpointDirectoryError("PRIVATE_CHECKPOINT_DIRECTORY_DENIED") from None
    finally:
        if fd is not None:
            os.close(fd)
