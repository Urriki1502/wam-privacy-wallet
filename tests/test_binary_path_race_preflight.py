"""Non-executing binary preflight regression tests (#36)."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node.real_regtest import RealRegtestError, verify_binary, check_real_regtest


class BinaryPathRacePreflightTests(unittest.TestCase):
    def test_exact_bytes_pass_without_launch(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "wamd"
            path.write_bytes(b"synthetic-only-not-a-core-binary")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(verify_binary(path, digest), path.resolve())

    def test_wrong_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "wamd"
            path.write_bytes(b"synthetic")
            with self.assertRaisesRegex(RealRegtestError, "CORE_SHA256_MISMATCH"):
                verify_binary(path, "0" * 64)

    def test_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "wamd"
            path.write_bytes(b"synthetic")
            link = Path(d) / "link"
            try:
                link.symlink_to(path)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(RealRegtestError, "CORE_BINARY_NOT_REGULAR"):
                verify_binary(link, hashlib.sha256(b"synthetic").hexdigest())

    def test_path_replacement_during_open_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "wamd"
            path.write_bytes(b"original")
            replacement = Path(d) / "other"
            replacement.write_bytes(b"replacement")
            native_open = os.open
            def replace_then_open(target, flags, *args, **kwargs):
                os.replace(replacement, path)
                return native_open(target, flags, *args, **kwargs)
            with patch("wam_privacy_wallet.node.real_regtest.os.open", side_effect=replace_then_open):
                with self.assertRaisesRegex(RealRegtestError, "CORE_BINARY_CHANGED"):
                    verify_binary(path, hashlib.sha256(b"original").hexdigest())

    def test_launcher_remains_interlocked_even_with_correct_digest(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "wamd"
            path.write_bytes(b"synthetic")
            with patch("wam_privacy_wallet.node.real_regtest.subprocess.Popen",
                       side_effect=AssertionError("MUST_NOT_LAUNCH")):
                with self.assertRaisesRegex(RealRegtestError, "CORE_EXECUTION_REVIEW_REQUIRED"):
                    check_real_regtest(path, hashlib.sha256(b"synthetic").hexdigest())


if __name__ == "__main__":
    unittest.main()
