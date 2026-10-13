"""CI ONLY: execute actual pinned upstream offline signer as a separate TTY process.

This runs only with a disposable encrypted regtest keyring and synthetic-chain
CI intent. Neither an application runtime entrypoint nor an OS network
sandbox. All TTY output stays PRIVATE and is never printed to CI logs.
"""
from __future__ import annotations

import os
import pty
import select
import subprocess
import sys
import time
from pathlib import Path


def run_offline_signer_tty(
    source_root: Path, keys: Path, request: Path, output: Path, *,
    key_password: bytes, request_password: bytes, approve: bool,
) -> bool:
    if (sys.platform != "linux" or os.name != "posix"
            or any(type(x) is not type(Path()) or not x.is_absolute()
                   for x in (source_root, keys, request, output))
            or not source_root.is_dir()
            or any(type(x) is not bytes or not 12 <= len(x) <= 1024
                   or b"\n" in x or b"\r" in x
                   for x in (key_password, request_password))
            or type(approve) is not bool or output.exists() or output.is_symlink()
            or not keys.is_file() or not request.is_file()
            or keys.parent != request.parent or output.parent != keys.parent):
        raise RuntimeError("CI_UPSTREAM_SIGNER_SCOPE_DENIED")
    master, slave = pty.openpty()
    child = None
    prompts = (
        (b"Key backup passphrase:", key_password + b"\n"),
        (b"Request passphrase:", request_password + b"\n"),
        (b"Type SIGN to approve exactly this payment:",
         b"SIGN\n" if approve else b"DECLINE\n"),
    )
    stage = 0
    transcript = bytearray()
    deadline = time.monotonic() + 65
    # Intentionally drop parent ambient PYTHONPATH, test credentials and
    # unrelated environment variables; use only the source-verified WSP root.
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(source_root / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "HOME": str(keys.parent),
    }
    try:
        child = subprocess.Popen(
            [sys.executable, "-B", "-m", "wam_sp.offline_signer",
             "--keys", str(keys), "--request", str(request),
             "--output", str(output)],
            stdin=slave, stdout=slave, stderr=slave,
            close_fds=True, env=env, start_new_session=True,
        )
        os.close(slave)
        slave = -1
        if child.pid == os.getpid():
            raise RuntimeError("CI_UPSTREAM_SIGNER_PROCESS_DENIED")
        while stage < len(prompts):
            left = deadline - time.monotonic()
            if left <= 0 or child.poll() is not None:
                raise RuntimeError("CI_UPSTREAM_SIGNER_PROMPT_DENIED")
            if not select.select([master], [], [], min(left, 1.0))[0]:
                continue
            try:
                chunk = os.read(master, 4096)
            except OSError:
                raise RuntimeError("CI_UPSTREAM_SIGNER_TTY_CLOSED") from None
            if not chunk:
                raise RuntimeError("CI_UPSTREAM_SIGNER_TTY_CLOSED")
            transcript.extend(chunk)
            if len(transcript) > 8192:
                raise RuntimeError("CI_UPSTREAM_SIGNER_TTY_BOUNDS_DENIED")
            if prompts[stage][0] in transcript:
                os.write(master, prompts[stage][1])
                transcript.clear()
                stage += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("CI_UPSTREAM_SIGNER_TIMEOUT")
        code = child.wait(timeout=remaining)
        if approve:
            if code != 0 or not output.is_file():
                raise RuntimeError("CI_UPSTREAM_SIGNER_APPROVAL_DENIED")
        else:
            if code != 1 or output.exists() or output.is_symlink():
                raise RuntimeError("CI_UPSTREAM_SIGNER_REFUSAL_DENIED")
        return approve
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("CI_UPSTREAM_SIGNER_PROCESS_DENIED") from None
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        if slave >= 0:
            os.close(slave)
        os.close(master)
        # Never echo the PTY, raw PSBT, address, passwords or source paths.
