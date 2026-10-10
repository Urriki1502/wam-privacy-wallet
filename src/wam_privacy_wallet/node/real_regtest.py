"""Isolated WAM regtest identity diagnostic; never a mainnet or wallet test.

Requires caller-supplied WAM Core executable and independently verified SHA256.
Never downloads binary, reads an existing WAM datadir, or accesses user funds.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass

from .attestation import RegtestIdentityError
from .core_profile import CoreProfileError
from .endpoint import LocalRegtestEndpoint
from .read_rpc import ExplicitRpcAuth
from .regtest_gateway import LocalRegtestIdentityGateway

_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)

# On Windows, CRT fstat() can report st_ctime_ns differently from Path.lstat().
# It is not a portable file identity property on that platform. Preserve
# dev/inode, size, mtime, byte count and mandatory SHA-256 for every platform.
_WINDOWS = os.name == "nt"


def _same_binary_file_metadata(first: os.stat_result, second: os.stat_result) -> bool:
    """Compare metadata fields stable across pathname and fd stat APIs."""
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if not _WINDOWS:
        fields += ("st_ctime_ns",)
    return all(getattr(first, name) == getattr(second, name) for name in fields)



class RealRegtestError(RuntimeError):
    """Stable, non-sensitive failure status."""


@dataclass(frozen=True, slots=True)
class RealRegtestEvidence:
    binary_sha256: str
    network: str
    height: int
    genesis: str
    tip: str


def verify_binary(path: str | os.PathLike[str], sha256: str) -> Path:
    """Hash a single checked file descriptor; this does NOT pin launch bytes.

    Reject a replaced path or changed file metadata during hash verification.
    The later subprocess.Popen(path) is still a separate, unsafe path lookup;
    its verify-to-execute TOCTOU gate remains BLOCKED pending native review.
    """
    if type(sha256) is not str or _SHA.fullmatch(sha256) is None:
        raise RealRegtestError("CORE_SHA256_INVALID")
    try:
        src = Path(path)
        before = src.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise RealRegtestError("CORE_BINARY_NOT_REGULAR")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        digest = hashlib.sha256()
        counted = 0
        with os.fdopen(os.open(src, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode)
                    or not _same_binary_file_metadata(before, opened)):
                raise RealRegtestError("CORE_BINARY_CHANGED")
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                counted += len(chunk)
                digest.update(chunk)
            finished = os.fstat(stream.fileno())
            if (not _same_binary_file_metadata(opened, finished)
                    or counted != opened.st_size):
                raise RealRegtestError("CORE_BINARY_CHANGED")
        current = src.lstat()
        if (not stat.S_ISREG(current.st_mode)
                or not _same_binary_file_metadata(opened, current)):
            raise RealRegtestError("CORE_BINARY_CHANGED")
        if digest.hexdigest() != sha256:
            raise RealRegtestError("CORE_SHA256_MISMATCH")
        return src.resolve(strict=True)
    except RealRegtestError:
        raise
    except (OSError, TypeError, ValueError):
        raise RealRegtestError("CORE_BINARY_UNAVAILABLE") from None


def _free_local_port() -> int:
    # A bind/startup race remains; cookie authentication and exact genesis
    # validation must both succeed before any result is reported.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        return int(server.getsockname()[1])


def _read_cookie(path: Path) -> ExplicitRpcAuth:
    """Read an isolated RPC cookie from one validated file descriptor.

    The pathname is never re-opened for the actual read. Reject symlinks,
    oversized files, changed inode/size/content metadata, and path swaps.
    POSIX uses O_NOFOLLOW; non-POSIX needs a separate OS-security review for
    native reparse-point and access-control guarantees.
    """
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= 1024:
            raise RealRegtestError("CORE_COOKIE_INVALID")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                    or opened.st_size != before.st_size):
                raise RealRegtestError("CORE_COOKIE_INVALID")
            raw = stream.read(1025)
            after = os.fstat(stream.fileno())
            if (not 1 <= len(raw) <= 1024
                    or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                    or after.st_size != len(raw)
                    or after.st_mtime_ns != opened.st_mtime_ns):
                raise RealRegtestError("CORE_COOKIE_INVALID")
        current = path.lstat()
        if (not stat.S_ISREG(current.st_mode)
                or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)):
            raise RealRegtestError("CORE_COOKIE_INVALID")
        username, password = raw.decode("ascii").strip().split(":", 1)
        return ExplicitRpcAuth(username, password)
    except RealRegtestError:
        raise
    except (OSError, ValueError, UnicodeDecodeError, TypeError):
        raise RealRegtestError("CORE_COOKIE_UNAVAILABLE") from None


def _write_private_conf(path: Path, rpc_port: int, p2p_port: int) -> None:
    """Generate a new, regtest-only node configuration with no external peers."""
    content = "\n".join((
        "regtest=1",
        "server=1",
        "daemon=0",
        "listen=0",
        "dns=0",
        "dnsseed=0",
        "discover=0",
        "upnp=0",
        "natpmp=0",
        "listenonion=0",
        "proxy=0",
        "onion=0",
        "connect=0",
        "debug=0",
        "printtoconsole=0",
        "txindex=0",
        "[regtest]",
        "rpcbind=127.0.0.1",
        "rpcallowip=127.0.0.1",
        f"rpcport={rpc_port}",
        f"port={p2p_port}",
        "",
    ))
    with path.open("x", encoding="ascii") as output:
        output.write(content)
    if os.name != "nt":
        path.chmod(0o600)


def _clean_env(home: Path) -> dict[str, str]:
    """Discard inherited proxy, WAM, wallet and credential environment vars."""
    environment = {
        key: os.environ[key]
        for key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATH")
        if key in os.environ
    }
    environment.update({
        "HOME": str(home), "TMP": str(home),
        "TEMP": str(home), "TMPDIR": str(home),
    })
    return environment


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    """Stop only our child process handle, not existing WAM processes."""
    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=8)


def check_real_regtest(
    binary: str | os.PathLike[str],
    sha256: str,
    *,
    startup_timeout: float = 45,
) -> RealRegtestEvidence:
    """Start a disposable node, attest regtest identity, stop and erase state.

    No automatic download or mock fallback. Successful identity is only a
    read-only point-in-time check; not a crypto/consensus security attestation.
    """
    if type(startup_timeout) not in (int, float) or not 1 <= startup_timeout <= 120:
        raise RealRegtestError("CORE_TIMEOUT_INVALID")
    executable = verify_binary(binary, sha256)
    with tempfile.TemporaryDirectory(prefix="wam-regtest-check-") as workspace:
        datadir = Path(workspace).resolve()
        rpc_port = _free_local_port()
        p2p_port = _free_local_port()
        while p2p_port == rpc_port:
            p2p_port = _free_local_port()
        config = datadir / "wam.conf"
        _write_private_conf(config, rpc_port, p2p_port)

        command = [
            str(executable), "-regtest", f"-datadir={datadir}", f"-conf={config}",
            "-daemon=0", "-nodebuglogfile", "-printtoconsole=0",
        ]
        try:
            process = subprocess.Popen(
                command,
                cwd=datadir,
                env=_clean_env(datadir),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
            )
        except OSError:
            raise RealRegtestError("CORE_START_FAILED") from None

        try:
            deadline = time.monotonic() + float(startup_timeout)
            cookie = datadir / "regtest" / ".cookie"
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RealRegtestError("CORE_EARLY_EXIT")
                if cookie.is_file():
                    try:
                        auth = _read_cookie(cookie)
                        gateway = LocalRegtestIdentityGateway(
                            LocalRegtestEndpoint("127.0.0.1", rpc_port),
                            auth,
                            timeout=2,
                        )
                        profile = gateway.probe_core_profile()
                        identity = profile.identity
                        return RealRegtestEvidence(
                            binary_sha256=sha256,
                            network="regtest",
                            height=identity.height,
                            genesis=identity.genesis,
                            tip=identity.best_block_hash,
                        )
                    except RegtestIdentityError as exc:
                        if str(exc) != "WAM_NODE_PROBE_TRANSPORT_ERROR":
                            raise RealRegtestError("CORE_IDENTITY_REJECTED") from None
                    except CoreProfileError:
                        raise RealRegtestError("CORE_PROFILE_REJECTED") from None
                    except RealRegtestError as exc:
                        if str(exc) != "CORE_COOKIE_UNAVAILABLE":
                            raise
                time.sleep(0.2)
            raise RealRegtestError("CORE_START_TIMEOUT")
        finally:
            try:
                _stop_process(process)
            except (OSError, subprocess.TimeoutExpired):
                raise RealRegtestError("CORE_STOP_FAILED") from None
