"""Synthetic Linux post-exec identity/loader observations, never WAM Core.

These tests execute ONLY two locally generated benign C fixtures. A pinned
execveat(memfd, AT_EMPTY_PATH) selects original bytes even after pathname
replacement; procfs observations are strictly NON-AUTHORIZING, especially for
the dynamic loader and transitive shared libraries.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import platform
import select
import shutil
import subprocess
import sys
import tempfile
import unittest

from wam_privacy_wallet.node.real_regtest import _require_reviewed_core_launch

_CHILD = r'''
import ctypes
import fcntl
import hashlib
import os
from pathlib import Path
import sys

src, replacement, expected = sys.argv[1:]
payload = Path(src).read_bytes()
assert 1 <= len(payload) <= 1024 * 1024
assert hashlib.sha256(payload).hexdigest() == expected
fd = os.memfd_create("synthetic-process-id-NOT-WAM",
    os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | 0x10)
try:
    assert os.write(fd, payload) == len(payload)
    os.fchmod(fd, 0o500)
    required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | \
               fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, required)
    assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) & required == required
    assert hashlib.sha256(os.pread(fd, len(payload), 0)).hexdigest() == expected
    os.replace(replacement, src)
    assert hashlib.sha256(Path(src).read_bytes()).hexdigest() != expected
    argv = (ctypes.c_char_p * 2)(b"synthetic-inspect", None)
    envp = (ctypes.c_char_p * 3)(b"PATH=/usr/bin:/bin", b"LC_ALL=C", None)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    rc = libc.syscall(ctypes.c_long(322), ctypes.c_int(fd),
            ctypes.c_char_p(b""), argv, envp, ctypes.c_int(0x1000))
    assert rc == -1, "syscall must not return after success"
    sys.exit(70)
finally:
    os.close(fd)
'''


def _linux_x64() -> bool:
    return (sys.platform == "linux" and platform.machine() == "x86_64"
            and hasattr(os, "memfd_create") and hasattr(os, "pidfd_open"))


def _build(root: Path, name: str, token: str, *, hold: bool = True) -> Path:
    cc = shutil.which("cc")
    if cc is None:
        raise AssertionError("SYNTHETIC_CC_MISSING")
    binary = root / name
    source = root / (name + ".c")
    suffix = "char c; return read(0, &c, 1) == 1 ? 0 : 21;" if hold else "return 0;"
    source.write_text(
        "#include <unistd.h>\n"
        "int main(void) {\n"
        f'  const char ready[] = "{token}\\n";\n'
        "  if (write(1, ready, sizeof(ready)-1) != sizeof(ready)-1) return 29;\n"
        f"  {suffix}\n"
        "}\n", encoding="ascii",
    )
    result = subprocess.run(
        [cc, "-O0", "-fPIE", "-pie", "-Wl,-z,noexecstack",
         "-o", str(binary), str(source)],
        cwd=str(root), env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        capture_output=True, timeout=15, check=False,
    )
    if result.returncode != 0:
        raise AssertionError("SYNTHETIC_CC_FAILED")
    return binary


@contextmanager
def _running_fixture():
    with tempfile.TemporaryDirectory(prefix="wam-synthetic-proc-identity-") as d:
        root = Path(d)
        source = _build(root, "primary", "SYNTHETIC_PROCESS_READY")
        other = _build(root, "attacker", "SYNTHETIC_ATTACKER_READY", hold=False)
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        process = subprocess.Popen(
            [sys.executable, "-c", _CHILD, str(source), str(other), digest],
            cwd=str(root),
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                 "PYTHONHASHSEED": "0"},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        pidfd = -1
        try:
            readable, _, _ = select.select([process.stdout], [], [], 10)
            if not readable:
                raise AssertionError("SYNTHETIC_READY_TIMEOUT")
            line = process.stdout.readline()
            if line != b"SYNTHETIC_PROCESS_READY\n":
                raise AssertionError("SYNTHETIC_READY_DENIED")
            pidfd = os.pidfd_open(process.pid)
            if process.poll() is not None:
                raise AssertionError("SYNTHETIC_CHILD_EXITED_EARLY")
            yield process, pidfd, source, digest
        finally:
            if process.poll() is None:
                try:
                    process.stdin.write(b"x")
                    process.stdin.flush()
                    process.wait(timeout=5)
                except (BrokenPipeError, OSError, subprocess.TimeoutExpired):
                    process.kill()
                    process.wait(timeout=5)
            if pidfd >= 0:
                os.close(pidfd)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


def _mapped_file_identities(pid: int) -> dict[str, tuple[int, int]]:
    """Read only mapped executable loader and C runtime, never claim trust."""
    matched: dict[str, tuple[int, int]] = {}
    for line in Path(f"/proc/{pid}/maps").read_text(encoding="utf-8").splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or "x" not in fields[1]:
            continue
        mapped_path = fields[5]
        if not mapped_path.startswith("/") or mapped_path.endswith(" (deleted)"):
            continue
        if not ("libc.so" in mapped_path or "ld-linux" in mapped_path
                or "ld-musl" in mapped_path):
            continue
        try:
            disk = os.stat(mapped_path)
            device = fields[3]
            maj, minor = (int(s, 16) for s in device.split(":"))
            recorded = int(fields[4])
            if (os.major(disk.st_dev), os.minor(disk.st_dev), disk.st_ino) != (
                maj, minor, recorded
            ):
                raise AssertionError("SYNTHETIC_LOADER_FILE_CHANGED")
        except (OSError, ValueError):
            raise AssertionError("SYNTHETIC_LOADER_FILE_UNAVAILABLE") from None
        key = "libc" if "libc.so" in mapped_path else "loader"
        matched[key] = (disk.st_dev, disk.st_ino)
    return matched


class SyntheticLinuxProcIdentityTests(unittest.TestCase):
    def test_proc_exe_image_digest_matches_fd_not_replaced_path(self):
        if not _linux_x64():
            self.assertFalse(_linux_x64())
            return
        with _running_fixture() as (proc, _pidfd, source, expected):
            with open(f"/proc/{proc.pid}/exe", "rb") as executable:
                digest = hashlib.sha256(executable.read()).hexdigest()
            self.assertEqual(digest, expected)
            self.assertNotEqual(
                hashlib.sha256(source.read_bytes()).hexdigest(), expected,
            )
            self.assertIn("memfd:", os.readlink(f"/proc/{proc.pid}/exe"))
            self.assertEqual(proc.poll(), None)

    def test_loader_and_libc_mappings_are_external_and_not_authenticated(self):
        if not _linux_x64():
            self.assertFalse(_linux_x64())
            return
        with _running_fixture() as (proc, _pidfd, _, _digest):
            mappings = _mapped_file_identities(proc.pid)
            self.assertIn("loader", mappings)
            self.assertIn("libc", mappings)
            # Their mapped metadata is visible but not pinned by the memfd.
            self.assertNotEqual(mappings["loader"], mappings["libc"])

    def test_pidfd_pins_lifetime_before_and_after_child_exit(self):
        if not _linux_x64():
            self.assertFalse(_linux_x64())
            return
        with _running_fixture() as (proc, pidfd, _, _digest):
            poll = select.poll()
            poll.register(pidfd, select.POLLIN)
            self.assertEqual(poll.poll(0), [])
            proc.stdin.write(b"x")
            proc.stdin.flush()
            self.assertEqual(proc.wait(timeout=5), 0)
            self.assertNotEqual(poll.poll(1000), [])

    def test_real_core_execution_gate_is_not_modified(self):
        with self.assertRaisesRegex(
            Exception, "^CORE_EXECUTION_REVIEW_REQUIRED$",
        ):
            _require_reviewed_core_launch()


if __name__ == "__main__":
    unittest.main()
