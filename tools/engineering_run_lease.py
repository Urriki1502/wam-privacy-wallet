"""Nonblocking POSIX directory lease for cooperating local engineering runs.

This is scheduling concurrency control, not a wallet custody or security gate.
No PID guessing, mutable lockfile, stale-lock deletion or automatic takeover.
All runs must use the SAME stable private directory in the primary checkout.
Directory replacement or a malicious same-UID process is outside this boundary.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys
try:
    import fcntl
except ImportError:
    fcntl = None


class EngineeringLeaseError(RuntimeError):
    """Fixed refusal without private paths or operating-system exception text."""


class EngineeringRunLease:
    def __init__(self, fd: int):
        self._fd = fd

    def close(self) -> None:
        # Keep ownership of the descriptor until close actually succeeds.
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                raise EngineeringLeaseError("ENGINEERING_LEASE_CLOSE_DENIED") from None
            self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def acquire_run_lease(directory: Path) -> EngineeringRunLease:
    """Acquire one owner-held flock, failing promptly if another run owns it.

    Callers provision the directory once (0700) and never replace/remove it.
    Walk every component without following symlinks. Kernel process teardown
    releases the lease; a scheduled continuation must never steal a live lease.
    No files are created, opened or modified inside the leased directory.
    """
    if (sys.platform not in ("darwin", "linux") or fcntl is None
            or type(directory) is not type(Path())
            or not directory.is_absolute() or ".." in directory.parts
            or not all(hasattr(os, key) for key in
                       ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"))
            or os.open not in os.supports_dir_fd):
        raise EngineeringLeaseError("ENGINEERING_LEASE_PATH_OR_PLATFORM_DENIED")
    fd = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(directory.anchor, flags)
        for part in directory.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            previous, fd = fd, child
            os.close(previous)
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or os.get_inheritable(fd)):
            raise EngineeringLeaseError("ENGINEERING_LEASE_DIRECTORY_DENIED")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise EngineeringLeaseError("ENGINEERING_RUN_ALREADY_ACTIVE") from None
        lease = EngineeringRunLease(fd)
        fd = None
        return lease
    except EngineeringLeaseError:
        raise
    except Exception:
        raise EngineeringLeaseError("ENGINEERING_LEASE_ACQUIRE_DENIED") from None
    finally:
        if fd is not None:
            os.close(fd)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    try:
        with acquire_run_lease(args.directory):
            print("ENGINEERING_LEASE_ACQUIRED", flush=True)
            # Keep this process and its stdin open throughout the run. A newline
            # or EOF releases ownership. No daemon, timer or privileged service.
            sys.stdin.readline()
        print("ENGINEERING_LEASE_RELEASED", flush=True)
        return 0
    except EngineeringLeaseError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
