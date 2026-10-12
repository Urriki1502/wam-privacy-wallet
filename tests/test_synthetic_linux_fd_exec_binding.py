"""Linux-only synthetic descriptor->kernel execveat proof; NEVER executes WAM Core.

This is a disposable, harmless C witness compiled for the test. It demonstrates
fd-directed Linux kernel semantics ONLY, not publisher provenance, dynamic
loader trust, WAM Core approval, or a wallet operational launch API.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node.real_regtest import (
    RealRegtestError, _require_reviewed_core_launch,
)

# Runs only in a completely separate Python test child, never this interpreter.
# There is no caller-supplied WAM Core path or production execution API.
_CHILD = r'''
import ctypes
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import sys

source, attacker, sha, mode = sys.argv[1:]
assert mode in ("sealed-fd", "noexec-denied")
assert Path(source).is_absolute() and Path(attacker).is_absolute()
assert sha == hashlib.sha256(Path(source).read_bytes()).hexdigest()

# The child owns the fixture. This is not a reusable executable launcher.
with open(source, "rb") as f:
    original = f.read(1024 * 1024 + 1)
assert 1 <= len(original) <= 1024 * 1024
assert hashlib.sha256(original).hexdigest() == sha
# Linux UAPI MFD_EXEC (0x10) for a specifically synthetic executable; the
# NOEXEC path deliberately supplies 0x08 and never sets an executable bit.
flag = 0x10 if mode == "sealed-fd" else 0x08
fd = os.memfd_create("synthetic-execveat-proof-NOT-WAM-CORE",
                     os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | flag)
try:
    assert os.write(fd, original) == len(original)
    if mode == "sealed-fd":
        os.fchmod(fd, 0o500)
    else:
        assert os.fstat(fd).st_mode & 0o111 == 0
        assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) & 0x20
    required = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, required)
    assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) & required == required
    assert hashlib.sha256(os.pread(fd, len(original), 0)).hexdigest() == sha

    # Swap the *pathname* after fd staging and sealing. A path-based launch
    # would now run the attacker's different harmless C witness. execveat
    # below is tied to the held fd, NOT to source or /proc/self/fd pathname.
    os.replace(attacker, source)
    assert hashlib.sha256(Path(source).read_bytes()).hexdigest() != sha

    argv = (ctypes.c_char_p * 2)(b"synthetic-witness", None)
    envp = (ctypes.c_char_p * 2)(b"PATH=/usr/bin:/bin", None)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    # Linux x86_64 execveat SYS=322, AT_EMPTY_PATH=0x1000.
    rc = libc.syscall(ctypes.c_long(322), ctypes.c_int(fd),
                      ctypes.c_char_p(b""), argv, envp, ctypes.c_int(0x1000))
    assert rc == -1
    code = ctypes.get_errno()
    if mode == "noexec-denied" and code in (errno.EACCES, errno.ENOENT):
        print("SYNTHETIC_NOEXEC_DENIED")
        sys.exit(0)
    print("SYNTHETIC_KERNEL_EXEC_DENIED:" + str(code), file=sys.stderr)
    sys.exit(72)
finally:
    os.close(fd)
'''


def _supported() -> bool:
    return (
        sys.platform == "linux"
        and platform.machine() == "x86_64"
        and hasattr(os, "memfd_create")
        and hasattr(os, "MFD_ALLOW_SEALING")
    )


class SyntheticKernelDescriptorBindingTests(unittest.TestCase):
    """Three adversarial contracts with no WAM Core executable ever supplied."""

    def _compile(self, root: Path, token: str, name: str) -> Path:
        cc = shutil.which("cc")
        self.assertIsNotNone(cc, "SYNTHETIC_CC_REQUIRED_ON_LINUX_RUNNER")
        src = root / (name + ".c")
        binary = root / name
        src.write_text(
            '#include <unistd.h>\n'
            'int main(void) {\n'
            f'  const char m[] = "{token}\\n";\n'
            '  return write(1, m, sizeof(m)-1) == sizeof(m)-1 ? 0 : 42;\n'
            '}\n',
            encoding="ascii",
        )
        compiled = subprocess.run(
            [cc, "-O0", "-fPIE", "-pie", "-Wl,-z,noexecstack",
             "-o", str(binary), str(src)],
            cwd=str(root), env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
            check=False,
        )
        self.assertEqual(compiled.returncode, 0, "SYNTHETIC_CC_FAILED")
        return binary

    def _witness(self, mode: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="wam-synthetic-fd-proof-") as d:
            root = Path(d)
            original = self._compile(root, "SYNTHETIC_FD_BINDING_OK",
                                     "original-fixture")
            attacker = self._compile(root, "SYNTHETIC_PATH_SWAP_ATTACKER",
                                     "replacement-fixture")
            expected = hashlib.sha256(original.read_bytes()).hexdigest()
            return subprocess.run(
                [sys.executable, "-c", _CHILD, str(original), str(attacker),
                 expected, mode],
                cwd=str(root),
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                     "PYTHONHASHSEED": "0"},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                timeout=15, check=False,
            )

    def test_fd_directed_kernel_exec_ignores_late_path_replacement(self):
        if not _supported():
            # No cross-platform fallback; Windows/macOS never run this fixture.
            self.assertFalse(_supported())
            return
        result = self._witness("sealed-fd")
        self.assertEqual(result.returncode, 0, result.stderr[-600:])
        self.assertEqual(result.stdout, "SYNTHETIC_FD_BINDING_OK\n")
        self.assertNotIn("ATTACKER", result.stdout)

    def test_noexec_sealed_fd_kernel_denies_even_synthetic_fixture(self):
        if not _supported():
            self.assertFalse(_supported())
            return
        result = self._witness("noexec-denied")
        self.assertEqual(result.returncode, 0, result.stderr[-600:])
        self.assertEqual(result.stdout.strip(), "SYNTHETIC_NOEXEC_DENIED")
        self.assertNotIn("SYNTHETIC_FD_BINDING_OK", result.stdout)

    def test_production_wam_core_launch_gate_still_unconditionally_blocks(self):
        with patch("wam_privacy_wallet.node.real_regtest.subprocess.Popen") as process:
            with self.assertRaisesRegex(
                RealRegtestError, "^CORE_EXECUTION_REVIEW_REQUIRED$",
            ):
                _require_reviewed_core_launch()
            process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
