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



if __name__ == "__main__":
    unittest.main()
