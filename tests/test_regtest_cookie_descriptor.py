"""Native regression tests for FD-bound regtest cookie handling, no Core run.

Only ephemeral synthetic cookies are used; the code never touches an actual
WAM user datadir, wallet, stored key, subprocess or network node.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from wam_privacy_wallet.node import real_regtest as source
from wam_privacy_wallet.node.real_regtest import RealRegtestError


class RegtestCookieDescriptorTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory(prefix="wam-cookie-fd-")
        self.addCleanup(workspace.cleanup)
        self.folder = Path(workspace.name)
        self.cookie = self.folder / ".cookie"
        self.cookie.write_bytes(b"__cookie__:TEST_SECRET")
        if os.name != "nt":
            self.cookie.chmod(0o600)

    def _read(self):
        return source._read_cookie(self.cookie)

    def test_cookie_auth_uses_single_valid_descriptor_and_redacted_repr(self):
        auth = self._read()
        self.assertEqual(auth.username, "__cookie__")
        self.assertEqual(auth.password, "TEST_SECRET")
        self.assertNotIn("TEST_SECRET", repr(auth))
        self.assertNotIn(str(self.cookie), repr(auth))

    def test_single_terminal_linefeed_is_supported_but_embedded_denied(self):
        self.cookie.write_bytes(b"__cookie__:TEST_SECRET\n")
        self.assertEqual(self._read().password, "TEST_SECRET")
        self.cookie.write_bytes(b"__cookie__:ABC\nDEF")
        with self.assertRaises(RealRegtestError):
            self._read()

    def test_empty_oversize_and_bad_auth_denied(self):
        for raw in (b"", b"x" * 1025, b"no-colon", b":TEST_SECRET",
                    b"__cookie__:", b"\xff:bad", b"__cookie__:\x00ABC",
                    b"__cookie__:hello\r\n"):
            with self.subTest(length=len(raw)), self.assertRaises(RealRegtestError):
                self.cookie.write_bytes(raw)
                self._read()

    def test_relative_and_non_native_path_denied_before_fs(self):
        for candidate in ("cookie", Path("cookie"), object(), None):
            with self.subTest(value=type(candidate).__name__), self.assertRaisesRegex(
                RealRegtestError, "^CORE_COOKIE_INVALID$",
            ):
                source._read_cookie(candidate)

    def test_symlink_cookie_refused_even_when_pointing_to_valid_private_data(self):
        link = self.folder / "link"
        try:
            link.symlink_to(self.cookie)
        except (OSError, NotImplementedError):
            return
        with self.assertRaisesRegex(RealRegtestError, "^CORE_COOKIE_INVALID$"):
            source._read_cookie(link)

    def test_hardlink_cookie_refused_on_supported_filesystem(self):
        other = self.folder / "hardlink"
        try:
            os.link(self.cookie, other)
        except (OSError, NotImplementedError):
            return
        with self.assertRaisesRegex(RealRegtestError, "^CORE_COOKIE_INVALID$"):
            self._read()

    def test_posix_world_readable_cookie_is_denied(self):
        if os.name == "nt":
            self.assertEqual(self._read().username, "__cookie__")
            return
        self.cookie.chmod(0o644)
        with self.assertRaisesRegex(RealRegtestError, "^CORE_COOKIE_INVALID$"):
            self._read()

    def test_swap_between_lstat_and_fd_open_is_rejected(self):
        replacement = self.folder / "replacement"
        replacement.write_bytes(b"__cookie__:OTHER_SECR")
        if os.name != "nt":
            replacement.chmod(0o600)
        original = os.open
        moved = []
        def swap_then_open(path, flags, *args):
            if not moved:
                moved.append("swapped")
                os.replace(replacement, self.cookie)
            return original(path, flags, *args)
        with patch.object(source.os, "open", side_effect=swap_then_open), \
             self.assertRaisesRegex(RealRegtestError, "^CORE_COOKIE_CHANGED$"):
            self._read()
        self.assertEqual(moved, ["swapped"])

    def test_swap_after_same_fd_read_is_rejected(self):
        replacement = self.folder / "new"
        replacement.write_bytes(b"__cookie__:OTHER_SECR")
        if os.name != "nt":
            replacement.chmod(0o600)
        original = os.fstat
        calls = []
        def swap_before_second_fstat(fd):
            calls.append(fd)
            if len(calls) == 2:
                os.replace(replacement, self.cookie)
            return original(fd)
        with patch.object(source.os, "fstat", side_effect=swap_before_second_fstat), \
             self.assertRaisesRegex(RealRegtestError, "^CORE_COOKIE_CHANGED$"):
            self._read()
        self.assertEqual(len(calls), 2)

    def test_same_size_inplace_mutation_detected_during_read_window(self):
        orig = os.fstat
        count = []
        def mutate(fd):
            count.append(fd)
            if len(count) == 2:
                self.cookie.write_bytes(b"__cookie__:ALTERED_SE")
                os.utime(self.cookie, ns=(1000000000, 1000000000))
            return orig(fd)
        with patch.object(source.os, "fstat", side_effect=mutate), \
             self.assertRaisesRegex(RealRegtestError, "^CORE_COOKIE_CHANGED$"):
            self._read()

    def test_windows_reparse_attribute_denied_even_when_regular_metadata(self):
        before = self.cookie.lstat()
        attributes = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        values = {key: getattr(before, key) for key in (
            "st_mode", "st_nlink", "st_size", "st_dev", "st_ino",
            "st_mtime_ns", "st_ctime_ns",
        )}
        values["st_file_attributes"] = attributes
        with patch.object(Path, "lstat", return_value=SimpleNamespace(**values)), \
             patch.object(source.os, "open", side_effect=AssertionError("MUST_NOT_OPEN")), \
             self.assertRaisesRegex(RealRegtestError, "^CORE_COOKIE_INVALID$"):
            self._read()

    def test_read_never_launches_core_or_calls_arbitrary_auth_hook(self):
        with patch.object(subprocess, "Popen", side_effect=AssertionError("NO_CORE_EXEC")):
            self.assertEqual(self._read().password, "TEST_SECRET")

    def test_no_follow_bit_is_used_when_platform_supports_it(self):
        if not hasattr(os, "O_NOFOLLOW"):
            self.assertEqual(self._read().username, "__cookie__")
            return
        original = os.open
        flags_used = []
        def record(path, flags, *args):
            flags_used.append(flags)
            return original(path, flags, *args)
        with patch.object(source.os, "open", side_effect=record):
            self._read()
        self.assertTrue(flags_used[0] & os.O_NOFOLLOW)


if __name__ == "__main__":
    unittest.main()
