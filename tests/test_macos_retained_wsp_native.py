"""Boundary tests; native positive proof executes only on a macOS CI runner."""
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from tools import ci_macos_retained_wsp_native as proof


class MacosRetainedWspNativeBoundaryTests(unittest.TestCase):
    def test_non_macos_rejected_before_source_import(self):
        for platform in ("linux", "win32", "unknown"):
            with self.subTest(platform=platform), \
                 patch.object(proof.sys, "platform", platform), \
                 patch.object(proof, "_qualify") as source:
                with self.assertRaisesRegex(RuntimeError, "MACOS_RETAINED_WSP_PLATFORM_DENIED"):
                    proof.run(Path.cwd())
                source.assert_not_called()

    def test_32bit_rejected_before_source_import(self):
        with patch.object(proof.sys, "platform", "darwin"), \
             patch.object(proof.struct, "calcsize", return_value=4), \
             patch.object(proof, "_qualify") as source:
            with self.assertRaisesRegex(RuntimeError, "MACOS_RETAINED_WSP_PLATFORM_DENIED"):
                proof.run(Path.cwd())
            source.assert_not_called()

    def test_python_optimized_mode_denied(self):
        outcome = subprocess.run(
            [sys.executable, "-O", "-B", "-m", "tools.ci_macos_retained_wsp_native",
             "--source-root", str(Path.cwd())],
            env=os.environ.copy(), capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(outcome.returncode, 2)
        self.assertEqual(outcome.stdout, "")
        self.assertEqual(outcome.stderr, "MACOS_RETAINED_WSP_NATIVE_DENIED\n")


if __name__ == "__main__":
    unittest.main()
