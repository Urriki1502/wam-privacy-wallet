"""Native crypto proof boundaries; synthetic refusals are not crypto evidence."""
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from tools import ci_macos_scan_backup_native as proof


class MacosScanBackupNativeBoundaryTests(unittest.TestCase):
    def test_other_platforms_deny_before_source_or_storage(self):
        for platform in ("linux", "win32", "unknown"):
            with self.subTest(platform=platform), patch.object(proof.sys, "platform", platform), \
                 patch.object(proof, "_qualify") as qualify, \
                 patch.object(proof, "provision_macos_encrypted_scan_backup") as store:
                with self.assertRaisesRegex(RuntimeError, "^MACOS_SCAN_CRYPTO_PLATFORM_UNQUALIFIED$"):
                    proof.run(Path.cwd())
                qualify.assert_not_called()
                store.assert_not_called()

    def test_32bit_denies_before_source_or_storage(self):
        with patch.object(proof.sys, "platform", "darwin"), \
             patch.object(proof.struct, "calcsize", return_value=4), \
             patch.object(proof, "_qualify") as qualify, \
             patch.object(proof, "provision_macos_encrypted_scan_backup") as store:
            with self.assertRaisesRegex(RuntimeError, "^MACOS_SCAN_CRYPTO_PLATFORM_UNQUALIFIED$"):
                proof.run(Path.cwd())
            qualify.assert_not_called()
            store.assert_not_called()

    def test_optimized_interpreter_cannot_disable_crypto_proof_assertions(self):
        result = subprocess.run(
            [sys.executable, "-O", "-B", "-m", "tools.ci_macos_scan_backup_native",
             "--source-root", str(Path.cwd())], env=os.environ.copy(),
            capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "MACOS_SCAN_CRYPTO_PROOF_DENIED\n")


if __name__ == "__main__":
    unittest.main()
