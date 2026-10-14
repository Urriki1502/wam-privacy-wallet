"""macOS retained SQLite identity/lease tests; no wallet keys or Core launch."""
import os
from pathlib import Path
import platform
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import macos_retained_scan_storage as subject


class MacosStorageBoundaryTests(unittest.TestCase):
    def test_unsupported_platform_does_not_touch_user_directories(self):
        for plat in ("linux", "win32", "unknown"):
            with self.subTest(plat=plat), patch.object(subject.sys, "platform", plat):
                with patch.object(subject, "open_macos_private_directory") as directory:
                    with self.assertRaisesRegex(subject.MacosRetainedScanStoreError,
                                                "^MACOS_SCAN_DB_PLATFORM_DENIED$"):
                        subject.MacosRetainedScanStore(Path.cwd())
                    directory.assert_not_called()

    def test_32bit_and_non_arm64_architecture_denied_before_disk(self):
        with patch.object(subject.sys, "platform", "darwin"):
            with patch.object(subject.struct, "calcsize", return_value=4):
                with self.assertRaises(subject.MacosRetainedScanStoreError):
                    subject.MacosRetainedScanStore(Path.cwd())
            with patch.object(subject.platform, "machine", return_value="x86_64"):
                with self.assertRaises(subject.MacosRetainedScanStoreError):
                    subject.MacosRetainedScanStore(Path.cwd())


@unittest.skipUnless(sys.platform == "darwin" and platform.machine().lower() == "arm64",
                     "real Darwin ARM64 syscall/inode test")
class ActualNativeMacosStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="macos-native-store-", dir="/private/tmp")
        self.folder = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_database_inode_and_lock_live_until_release(self):
        handle = subject.MacosRetainedScanStore(self.folder)
        try:
            self.assertEqual(handle.path.name, "scan-only-state.sqlite")
            self.assertTrue(handle.path.is_file())
            self.assertEqual(stat.S_IMODE(handle.path.stat().st_mode), 0o600)
            handle.verify()
            with self.assertRaisesRegex(subject.MacosRetainedScanStoreError,
                                        "^MACOS_SCAN_DB_OPEN_DENIED$"):
                subject.MacosRetainedScanStore(self.folder)
            with handle.path.open("ab") as f:
                f.write(b"test-disposable-state")
            handle.verify()
        finally:
            handle.close()
        second = subject.MacosRetainedScanStore(self.folder)
        second.verify()
        second.close()

    def test_replace_existing_name_is_detected_before_claiming_success(self):
        handle = subject.MacosRetainedScanStore(self.folder)
        foreign = self.folder / "replacement.sqlite"
        foreign.write_bytes(b"test-bad-state")
        foreign.chmod(0o600)
        os.replace(foreign, handle.path)
        with self.assertRaisesRegex(subject.MacosRetainedScanStoreError,
                                    "^MACOS_SCAN_DB_CHANGED_DENIED$"):
            handle.verify()
        with self.assertRaisesRegex(subject.MacosRetainedScanStoreError,
                                    "^MACOS_SCAN_DB_CLOSE_DENIED$"):
            handle.close()

    def test_symlinked_or_multilinked_existing_db_is_rejected(self):
        name = self.folder / "scan-only-state.sqlite"
        target = self.folder / "target.sqlite"
        target.write_bytes(b"data")
        target.chmod(0o600)
        name.symlink_to(target)
        with self.assertRaises(subject.MacosRetainedScanStoreError):
            subject.MacosRetainedScanStore(self.folder)
        name.unlink()
        os.link(target, name)
        with self.assertRaises(subject.MacosRetainedScanStoreError):
            subject.MacosRetainedScanStore(self.folder)

    def test_non_private_directory_denied_without_chmod_side_effect(self):
        self.folder.chmod(0o755)
        with self.assertRaises(subject.MacosRetainedScanStoreError):
            subject.MacosRetainedScanStore(self.folder)
        self.assertEqual(stat.S_IMODE(self.folder.stat().st_mode), 0o755)


if __name__ == "__main__":
    unittest.main()
