"""Fail-closed source/platform boundary of the native-only process proof.

These negative tests are not substitute native OS lock qualification; the
additive workflow executes the actual separate-process WSP proof.
"""
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import ci_wsp1_scanner_process_lock as proof


class NativeProcessLockBoundaryTests(unittest.TestCase):
    # Source/dependency/origin fixtures model 64-bit refusal paths. They never
    # import WSP or qualify a 32-bit runtime; the real 32-bit gate is tested
    # independently before any source read and by the native Windows CI job.
    def setUp(self):
        self.root = Path.cwd().resolve()

    def test_32bit_denies_before_source_dependency_or_wsp_reads(self):
        with patch.object(proof.struct, "calcsize", return_value=4), \
             patch.object(proof, "verify_wsp1_full_source_closure") as source, \
             patch.object(proof.importlib.metadata, "version") as dependency:
            with self.assertRaisesRegex(RuntimeError, "PLATFORM_UNQUALIFIED"):
                proof._qualify(self.root)
            source.assert_not_called()
            dependency.assert_not_called()

    def test_unknown_native_platform_denies_before_source_reads(self):
        with patch.object(proof.sys, "platform", "unqualified"), \
             patch.object(proof, "verify_wsp1_full_source_closure") as source:
            with self.assertRaisesRegex(RuntimeError, "PLATFORM_UNQUALIFIED"):
                proof._qualify(self.root)
            source.assert_not_called()

    @patch.object(proof.struct, "calcsize", return_value=8)
    def test_relative_source_denies_before_source_or_dependency_reads(self, _pointer_width):
        with patch.object(proof, "verify_wsp1_full_source_closure") as source, \
             patch.object(proof.importlib.metadata, "version") as dependency:
            with self.assertRaisesRegex(RuntimeError, "SOURCE_DENIED"):
                proof._qualify(Path("unreviewed"))
            source.assert_not_called()
            dependency.assert_not_called()

    @patch.object(proof.struct, "calcsize", return_value=8)
    def test_preloaded_wsp_denies_before_source_or_native_dependency_reads(self, _pointer_width):
        with patch.dict(sys.modules, {"wam_sp.scanner": object()}), \
             patch.object(proof, "verify_wsp1_full_source_closure") as source, \
             patch.object(proof.importlib.metadata, "version") as dependency:
            with self.assertRaisesRegex(RuntimeError, "SOURCE_DENIED"):
                proof._qualify(self.root)
            source.assert_not_called()
            dependency.assert_not_called()

    @patch.object(proof.struct, "calcsize", return_value=8)
    def test_changed_pin_denies_before_dependency_reads_or_native_imports(self, _pointer_width):
        with patch.object(proof, "verify_wsp1_full_source_closure", return_value={
                "pinned_commit": "0" * 40, "scanner_enabled": False}), \
             patch.object(proof.importlib.metadata, "version") as dependency, \
             patch.object(proof.importlib.util, "find_spec") as origin:
            with self.assertRaisesRegex(RuntimeError, "SOURCE_DENIED"):
                proof._qualify(self.root)
            dependency.assert_not_called()
            origin.assert_not_called()

    @patch.object(proof.struct, "calcsize", return_value=8)
    def test_changed_dependency_denies_before_package_origin_or_imports(self, _pointer_width):
        with patch.object(proof, "verify_wsp1_full_source_closure", return_value={
                "pinned_commit": proof.PIN, "scanner_enabled": False}), \
             patch.object(proof.importlib.metadata, "version", return_value="0.0.0"), \
             patch.object(proof.importlib.util, "find_spec") as origin:
            with self.assertRaisesRegex(RuntimeError, "DEPENDENCY_DENIED"):
                proof._qualify(self.root)
            origin.assert_not_called()

    @patch.object(proof.struct, "calcsize", return_value=8)
    def test_wrong_installed_origin_cannot_qualify_unreviewed_native_code(self, _pointer_width):
        versions = {"coincurve": "21.0.0", "cryptography": "50.0.0", "pycryptodome": "3.23.0"}
        with patch.object(proof, "verify_wsp1_full_source_closure", return_value={
                "pinned_commit": proof.PIN, "scanner_enabled": False}), \
             patch.object(proof.importlib.metadata, "version", side_effect=versions.__getitem__), \
             patch.object(proof.importlib.util, "find_spec", return_value=SimpleNamespace(
                 origin=str(self.root / "unreviewed/wam_sp/__init__.py"))):
            with self.assertRaisesRegex(RuntimeError, "INSTALLED_SOURCE_DENIED"):
                proof._qualify(self.root)

    def test_optimized_python_cannot_silently_disable_native_proof_assertions(self):
        env = {key: os.environ[key] for key in
               ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR")
               if key in os.environ}
        env["PYTHONPATH"] = str(proof.ROOT / "src")
        result = subprocess.run([sys.executable, "-O", "-B", "-m",
                                 "tools.ci_wsp1_scanner_process_lock",
                                 "--source-root", str(self.root)], cwd=proof.ROOT,
                                env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr.strip(), "WSP_NATIVE_PROCESS_LOCK_DENIED")


if __name__ == "__main__":
    unittest.main()
