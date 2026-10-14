"""Real-process scheduling lease tests; no Core binary or wallet state."""
from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import engineering_run_lease as lease_tool


ROOT = Path(__file__).resolve().parents[1]


class EngineeringRunLeaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wam-engineering-lease-")
        self.addCleanup(self.temporary.cleanup)
        # macOS may expose its temporary root through the /var symlink.
        self.root = Path(self.temporary.name).resolve()
        self.directory = self.root / "lease"
        self.directory.mkdir(mode=0o700)

    def native(self):
        if sys.platform in ("darwin", "linux"):
            return True
        with patch.object(lease_tool.os, "open") as opened:
            with self.assertRaisesRegex(lease_tool.EngineeringLeaseError,
                                        "^ENGINEERING_LEASE_PATH_OR_PLATFORM_DENIED$"):
                lease_tool.acquire_run_lease(self.directory)
            opened.assert_not_called()
        return False

    def contender(self):
        # The sole child executable is this interpreter running the lease tool.
        return subprocess.run(
            [sys.executable, "-B", "-m", "tools.engineering_run_lease",
             str(self.directory)], cwd=ROOT, input="\n", text=True,
            capture_output=True, timeout=5, check=False,
        )

    def child_owner(self):
        child = subprocess.Popen(
            [sys.executable, "-B", "-m", "tools.engineering_run_lease",
             str(self.directory)], cwd=ROOT, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            close_fds=True,
        )
        self.addCleanup(self.stop_child, child)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(timeout=5), "lease owner did not respond")
        self.assertEqual(child.stdout.readline(), "ENGINEERING_LEASE_ACQUIRED\n")
        self.assertIsNone(child.poll())
        return child

    @staticmethod
    def stop_child(child):
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None:
                stream.close()

    def assert_active(self):
        with self.assertRaisesRegex(lease_tool.EngineeringLeaseError,
                                    "^ENGINEERING_RUN_ALREADY_ACTIVE$"):
            lease_tool.acquire_run_lease(self.directory)

    def test_native_private_directory_lease_creates_no_lockfile(self):
        if not self.native():
            return
        before = self.directory.stat()
        with lease_tool.acquire_run_lease(self.directory) as owner:
            self.assertFalse(os.get_inheritable(owner._fd))
            self.assertEqual(os.fstat(owner._fd).st_ino, before.st_ino)
            self.assertEqual(list(self.directory.iterdir()), [])
            self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(self.directory.stat().st_ino, before.st_ino)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_same_process_contender_denied_until_owner_closes(self):
        if not self.native():
            return
        with lease_tool.acquire_run_lease(self.directory):
            self.assert_active()
        with lease_tool.acquire_run_lease(self.directory):
            self.assert_active()

    def test_actual_child_contender_cannot_release_parent_owner(self):
        if not self.native():
            return
        with lease_tool.acquire_run_lease(self.directory):
            result = self.contender()
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "ENGINEERING_RUN_ALREADY_ACTIVE\n")
            self.assert_active()
        result = self.contender()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout,
                         "ENGINEERING_LEASE_ACQUIRED\nENGINEERING_LEASE_RELEASED\n")

    def test_actual_owner_blocks_contender_and_normal_exit_releases(self):
        if not self.native():
            return
        child = self.child_owner()
        self.assert_active()
        result = self.contender()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, "ENGINEERING_RUN_ALREADY_ACTIVE\n")
        self.assertIsNone(child.poll())
        out, err = child.communicate("\n", timeout=5)
        self.assertEqual(child.returncode, 0, err)
        self.assertEqual(out, "ENGINEERING_LEASE_RELEASED\n")
        self.assertEqual(err, "")
        with lease_tool.acquire_run_lease(self.directory):
            self.assertEqual(list(self.directory.iterdir()), [])

    def test_actual_owner_eof_releases_without_directory_replacement(self):
        if not self.native():
            return
        identity = self.directory.stat().st_ino
        child = self.child_owner()
        out, err = child.communicate("", timeout=5)
        self.assertEqual(child.returncode, 0, err)
        self.assertEqual(out, "ENGINEERING_LEASE_RELEASED\n")
        with lease_tool.acquire_run_lease(self.directory):
            self.assertEqual(self.directory.stat().st_ino, identity)

    def test_terminated_owner_releases_without_stale_lock_deletion(self):
        if not self.native():
            return
        sentinel = self.directory / "checkpoint-fixture.txt"
        sentinel.write_text("public test checkpoint\n", encoding="ascii")
        before = self.directory.stat()
        child = self.child_owner()
        self.assert_active()
        child.terminate()
        child.wait(timeout=5)
        self.assertNotEqual(child.returncode, 0)
        with lease_tool.acquire_run_lease(self.directory):
            self.assertEqual(self.directory.stat().st_ino, before.st_ino)
            self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
            self.assertEqual(sentinel.read_text(encoding="ascii"),
                             "public test checkpoint\n")
            self.assertEqual(list(self.directory.iterdir()), [sentinel])

    def test_context_exception_closes_owner_and_allows_next_run(self):
        if not self.native():
            return
        with self.assertRaisesRegex(ValueError, "^public fixture exception$"):
            with lease_tool.acquire_run_lease(self.directory):
                raise ValueError("public fixture exception")
        with lease_tool.acquire_run_lease(self.directory):
            self.assert_active()

    def test_close_is_idempotent_and_does_not_close_unrelated_descriptor(self):
        if not self.native():
            return
        owner = lease_tool.acquire_run_lease(self.directory)
        owner.close()
        separate = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            owner.close()
            self.assertTrue(stat.S_ISDIR(os.fstat(separate).st_mode))
        finally:
            os.close(separate)

    def test_different_directories_do_not_share_lease(self):
        if not self.native():
            return
        other = self.root / "different-directory"
        other.mkdir(mode=0o700)
        with lease_tool.acquire_run_lease(self.directory):
            with lease_tool.acquire_run_lease(other):
                self.assert_active()

    def test_windows_denied_before_any_directory_io(self):
        with patch.object(lease_tool.sys, "platform", "win32"), \
             patch.object(lease_tool.os, "open") as opened, \
             patch.object(lease_tool.os, "fstat") as inspected:
            with self.assertRaisesRegex(lease_tool.EngineeringLeaseError,
                                        "^ENGINEERING_LEASE_PATH_OR_PLATFORM_DENIED$"):
                lease_tool.acquire_run_lease(self.directory)
            opened.assert_not_called()
            inspected.assert_not_called()

    def test_missing_fcntl_denied_before_any_directory_io(self):
        with patch.object(lease_tool, "fcntl", None), \
             patch.object(lease_tool.os, "open") as opened:
            with self.assertRaisesRegex(lease_tool.EngineeringLeaseError,
                                        "^ENGINEERING_LEASE_PATH_OR_PLATFORM_DENIED$"):
                lease_tool.acquire_run_lease(self.directory)
            opened.assert_not_called()

    def test_non_path_relative_and_parent_traversal_denied_before_io(self):
        for value in (None, str(self.directory), Path("relative"),
                      self.root / ".." / "lease"):
            with self.subTest(kind=type(value).__name__), \
                 patch.object(lease_tool.os, "open") as opened:
                with self.assertRaisesRegex(lease_tool.EngineeringLeaseError,
                                            "^ENGINEERING_LEASE_PATH_OR_PLATFORM_DENIED$"):
                    lease_tool.acquire_run_lease(value)
                opened.assert_not_called()

    def test_final_and_parent_symlinks_denied(self):
        if not self.native():
            return
        link = self.root / "linked-directory"
        link.symlink_to(self.directory, target_is_directory=True)
        parent = self.root / "linked-parent"
        parent.symlink_to(self.root, target_is_directory=True)
        for directory in (link, parent / "lease"):
            with self.subTest(path_kind=directory.name):
                with self.assertRaisesRegex(lease_tool.EngineeringLeaseError,
                                            "^ENGINEERING_LEASE_ACQUIRE_DENIED$"):
                    lease_tool.acquire_run_lease(directory)
        with lease_tool.acquire_run_lease(self.directory):
            self.assertEqual(list(self.directory.iterdir()), [])

    def test_non_private_directory_mode_denied(self):
        if not self.native():
            return
        self.directory.chmod(0o755)
        with self.assertRaisesRegex(lease_tool.EngineeringLeaseError,
                                    "^ENGINEERING_LEASE_DIRECTORY_DENIED$"):
            lease_tool.acquire_run_lease(self.directory)

    def test_wrong_owner_denied_and_descriptor_closed(self):
        if not self.native():
            return
        actual = self.directory.stat()
        foreign = SimpleNamespace(st_mode=actual.st_mode,
                                  st_uid=os.geteuid() + 1)
        original_close = os.close
        with patch.object(lease_tool.os, "fstat", return_value=foreign), \
             patch.object(lease_tool.os, "close", wraps=original_close) as closed:
            with self.assertRaisesRegex(lease_tool.EngineeringLeaseError,
                                        "^ENGINEERING_LEASE_DIRECTORY_DENIED$"):
                lease_tool.acquire_run_lease(self.directory)
            final_fd = closed.call_args.args[0]
        with self.assertRaises(OSError):
            os.fstat(final_fd)

    def test_missing_directory_and_regular_file_errors_are_redacted(self):
        if not self.native():
            return
        file = self.root / "ordinary-file"
        file.write_text("public fixture", encoding="ascii")
        for directory in (self.root / "missing-private-path", file):
            with self.subTest(kind=directory.name):
                with self.assertRaisesRegex(lease_tool.EngineeringLeaseError,
                                            "^ENGINEERING_LEASE_ACQUIRE_DENIED$"):
                    lease_tool.acquire_run_lease(directory)

    def test_open_error_has_fixed_message_without_private_path(self):
        if not self.native():
            return
        with patch.object(lease_tool.os, "open",
                          side_effect=OSError("private fixture path must not escape")) as opened:
            with patch.object(lease_tool.os, "supports_dir_fd", {opened}):
                with self.assertRaisesRegex(lease_tool.EngineeringLeaseError,
                                            "^ENGINEERING_LEASE_ACQUIRE_DENIED$"):
                    lease_tool.acquire_run_lease(self.directory)

    def test_non_contention_flock_error_closes_descriptor(self):
        if not self.native():
            return
        original_close = os.close
        with patch.object(lease_tool.fcntl, "flock", side_effect=OSError("private error")), \
             patch.object(lease_tool.os, "close", wraps=original_close) as closed:
            with self.assertRaisesRegex(lease_tool.EngineeringLeaseError,
                                        "^ENGINEERING_LEASE_ACQUIRE_DENIED$"):
                lease_tool.acquire_run_lease(self.directory)
            final_fd = closed.call_args.args[0]
        with self.assertRaises(OSError):
            os.fstat(final_fd)
        with lease_tool.acquire_run_lease(self.directory):
            self.assert_active()

    def test_close_failure_preserves_owner_for_explicit_retry(self):
        if not self.native():
            return
        owner = lease_tool.acquire_run_lease(self.directory)
        self.addCleanup(owner.close)
        with patch.object(lease_tool.os, "close", side_effect=OSError("private error")):
            with self.assertRaisesRegex(lease_tool.EngineeringLeaseError,
                                        "^ENGINEERING_LEASE_CLOSE_DENIED$"):
                owner.close()
        self.assert_active()
        owner.close()
        with lease_tool.acquire_run_lease(self.directory):
            self.assert_active()

    def test_cli_refusal_prints_only_fixed_error(self):
        output, error = io.StringIO(), io.StringIO()
        with patch.object(lease_tool.sys, "platform", "win32"), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            self.assertEqual(lease_tool.main([str(self.directory)]), 2)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(error.getvalue(), "ENGINEERING_LEASE_PATH_OR_PLATFORM_DENIED\n")


if __name__ == "__main__":
    unittest.main()
