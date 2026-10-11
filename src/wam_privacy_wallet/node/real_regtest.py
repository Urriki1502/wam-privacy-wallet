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
    """Verify a regular executable file against an operator-supplied SHA256."""
    if type(sha256) is not str or _SHA.fullmatch(sha256) is None:
        raise RealRegtestError("CORE_SHA256_INVALID")
    try:
        src = Path(path)
        info = src.lstat()
        if not stat.S_ISREG(info.st_mode) or src.is_symlink():
            raise RealRegtestError("CORE_BINARY_NOT_REGULAR")
        digest = hashlib.sha256()
        with src.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != sha256:
            raise RealRegtestError("CORE_SHA256_MISMATCH")
        return src.resolve(strict=True)
    except (OSError, TypeError, ValueError):
        raise RealRegtestError("CORE_BINARY_UNAVAILABLE") from None


def _free_local_port() -> int:
    # A bind/startup race remains; cookie authentication and exact genesis
    # validation must both succeed before any result is reported.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        return int(server.getsockname()[1])


def _read_cookie(path: Path) -> ExplicitRpcAuth:
    """Read our isolated regtest cookie from one verified file descriptor.

    Never open the pathname a second time for the content. Check the inode,
    device, size, time and Windows reparse metadata before/after same-fd
    bounded read and against the pathname after completion. Fail closed on
    symlinks, hardlinks and any visible path/file replacement. This does not
    authorize Core launch or prove the OS process image (#36).
    """
    if type(path) is not type(Path()) or not path.is_absolute():
        raise RealRegtestError("CORE_COOKIE_INVALID")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    def valid(info: os.stat_result) -> bool:
        return (
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and 1 <= info.st_size <= 1024
            and not (getattr(info, "st_file_attributes", 0)
                     & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            and (os.name == "nt" or info.st_mode & 0o077 == 0)
        )

    def identical(first: os.stat_result, other: os.stat_result) -> bool:
        return (
            first.st_dev == other.st_dev
            and first.st_ino == other.st_ino
            and first.st_size == other.st_size
            and first.st_mtime_ns == other.st_mtime_ns
            # On Windows, native stat APIs can expose creation/change time
            # differently between pathname and descriptor observations.
            # Preserve inode/dev/size/mtime checks; ctime is additionally
            # required where POSIX specifies it consistently.
            and (os.name == "nt" or first.st_ctime_ns == other.st_ctime_ns)
            and valid(other)
        )

    try:
        before = path.lstat()
        if not valid(before):
            raise RealRegtestError("CORE_COOKIE_INVALID")
        with os.fdopen(os.open(path, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not identical(before, opened):
                raise RealRegtestError("CORE_COOKIE_CHANGED")
            raw = stream.read(1025)
            held = os.fstat(stream.fileno())
            after = path.lstat()
            if (not identical(opened, held) or not identical(held, after)
                    or len(raw) != opened.st_size):
                raise RealRegtestError("CORE_COOKIE_CHANGED")
        if (not 1 <= len(raw) <= 1024
                or raw.count(b":") != 1
                or any(ch in raw for ch in (b"\x00", b"\r"))):
            raise RealRegtestError("CORE_COOKIE_INVALID")
        # WAM/Bitcoin cookies are ASCII "<username>:<password>", with no
        # trailing newline in the generated file; do not strip whitespace or
        # silently reinterpret malformed credential bytes.
        credential_bytes = raw[:-1] if raw.endswith(b"\n") else raw
        if b"\n" in credential_bytes:
            raise RealRegtestError("CORE_COOKIE_INVALID")
        username, password = credential_bytes.decode("ascii").split(":", 1)
        return ExplicitRpcAuth(username, password)
    except RealRegtestError:
        raise
    except (OSError, TypeError, UnicodeError, ValueError, OverflowError):
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


def _require_reviewed_core_launch() -> None:
    """Fail-closed launch interlock until #36 has a reviewed binding solution.

    File SHA256 by pathname is insufficient to prove that the bytes later
    executed by Popen(path) are the bytes checked. No environment variable,
    command-line flag or user-provided digest can override this interlock.
    Tests may patch the interlock *only with Popen mocked*, never real Core.
    """
    raise RealRegtestError("CORE_EXECUTION_REVIEW_REQUIRED") from None


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
    _require_reviewed_core_launch()
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
