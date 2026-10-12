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

    def test_same_bytes_path_replaced_during_resolve_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "wamd"
            replacement = Path(d) / "replacement"
            path.write_bytes(b"identical-synthetic-artifact")
            replacement.write_bytes(b"identical-synthetic-artifact")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            original_resolve = type(path).resolve

            def swap_after_hash(current, *args, **kwargs):
                if current == path:
                    # Descriptor has been closed, so Windows can also rename.
                    os.replace(replacement, path)
                return original_resolve(current, *args, **kwargs)

            with patch.object(type(path), "resolve", swap_after_hash):
                with self.assertRaisesRegex(RealRegtestError, "CORE_BINARY_CHANGED"):
                    verify_binary(path, digest)

    def test_path_deleted_during_resolve_cannot_qualify(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "wamd"
            path.write_bytes(b"synthetic")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            original_resolve = type(path).resolve

            def delete_after_hash(current, *args, **kwargs):
                if current == path:
                    path.unlink()
                return original_resolve(current, *args, **kwargs)

            with patch.object(type(path), "resolve", delete_after_hash):
                with self.assertRaisesRegex(RealRegtestError, "CORE_BINARY_UNAVAILABLE"):
                    verify_binary(path, digest)

    def test_custom_fspath_cannot_execute_hooks(self):
        class Hostile:
            def __fspath__(self):
                raise AssertionError("UNTRUSTED_PATH_HOOK_CALLED")
        with self.assertRaisesRegex(RealRegtestError, "^CORE_BINARY_PATH_DENIED$"):
            verify_binary(Hostile(), "0" * 64)

    def test_relative_path_denied_before_filesystem_access(self):
        with patch("wam_privacy_wallet.node.real_regtest.os.open",
                   side_effect=AssertionError("MUST_NOT_OPEN")):
            with self.assertRaisesRegex(RealRegtestError, "^CORE_BINARY_PATH_DENIED$"):
                verify_binary("relative-wamd", "0" * 64)

    def test_hardlinked_binary_denied_even_with_correct_digest(self):
        with tempfile.TemporaryDirectory() as d:
            path, alias = Path(d) / "wamd", Path(d) / "alias"
            path.write_bytes(b"synthetic-hardlink")
            try:
                os.link(path, alias)
                linked = path.stat().st_nlink >= 2
            except (OSError, NotImplementedError):
                linked = False
            if linked:
                with self.assertRaisesRegex(RealRegtestError, "^CORE_BINARY_NOT_REGULAR$"):
                    verify_binary(path, hashlib.sha256(path.read_bytes()).hexdigest())
            else:
                # Some runner filesystems cannot create/measure hardlinks.
                # Exercise the exact rejection boundary without a CI skip.
                from types import SimpleNamespace
                current = path.stat()
                fake = SimpleNamespace(
                    st_mode=current.st_mode, st_nlink=2,
                    st_size=current.st_size, st_file_attributes=0,
                )
                with patch.object(type(path), "lstat", return_value=fake):
                    with self.assertRaisesRegex(RealRegtestError, "^CORE_BINARY_NOT_REGULAR$"):
                        verify_binary(path, hashlib.sha256(b"synthetic-hardlink").hexdigest())

    def test_empty_binary_denied_without_launch(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "empty-wamd"
            path.write_bytes(b"")
            with patch("wam_privacy_wallet.node.real_regtest.subprocess.Popen",
                       side_effect=AssertionError("MUST_NOT_LAUNCH")):
                with self.assertRaisesRegex(RealRegtestError, "^CORE_BINARY_NOT_REGULAR$"):
                    verify_binary(path, hashlib.sha256(b"").hexdigest())

    def test_oversize_metadata_rejected_without_open(self):
        import stat
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "synthetic-wamd"
            fake = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1,
                                   st_size=512 * 1024 * 1024 + 1,
                                   st_file_attributes=0)
            with patch.object(type(path), "lstat", return_value=fake), patch(
                "wam_privacy_wallet.node.real_regtest.os.open",
                side_effect=AssertionError("MUST_NOT_OPEN")
            ):
                with self.assertRaisesRegex(RealRegtestError, "^CORE_BINARY_NOT_REGULAR$"):
                    verify_binary(path, "0" * 64)

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
