"""Non-production harness tests: no WAM Core process ever executes."""

import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from wam_privacy_wallet.node.real_regtest import (
    RealRegtestError, _clean_env, _read_cookie, _write_private_conf,
    check_real_regtest, verify_binary,
)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.binary = self.root / "NOT-A-WAM-DAEMON"
        self.binary.write_bytes(b"SYNTHETIC TEST BYTES")
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()

    def test_exact_binary_sha_required(self):
        self.assertEqual(verify_binary(self.binary, self.digest), self.binary.resolve())
        for sha in (None, "bad", self.digest.upper(), "0" * 64):
            with self.subTest(sha=sha), self.assertRaises(RealRegtestError):
                verify_binary(self.binary, sha)

    def test_binary_swap_between_metadata_check_and_open_denied(self):
        """Synthetic replacement before fd open must never be hashed as original."""
        original_open = os.open

        def swap_first(name, flags, *args, **kwargs):
            self.binary.unlink()
            self.binary.write_bytes(b"REPLACEMENT SYNTHETIC FILE")
            return original_open(name, flags, *args, **kwargs)

        with patch("wam_privacy_wallet.node.real_regtest.os.open",
                   side_effect=swap_first):
            with self.assertRaisesRegex(RealRegtestError, "^CORE_BINARY_CHANGED$"):
                verify_binary(self.binary, self.digest)

    def test_binary_metadata_change_during_hash_denied(self):
        """A changed descriptor mtime after hashing invalidates verification."""
        original_fstat = os.fstat
        calls = 0

        def changed_second_stat(fd):
            nonlocal calls
            calls += 1
            current = original_fstat(fd)
            if calls != 2:
                return current
            return SimpleNamespace(
                st_mode=current.st_mode,
                st_dev=current.st_dev,
                st_ino=current.st_ino,
                st_size=current.st_size,
                st_mtime_ns=current.st_mtime_ns + 1,
                st_ctime_ns=current.st_ctime_ns,
            )

        with patch("wam_privacy_wallet.node.real_regtest.os.fstat",
                   side_effect=changed_second_stat):
            with self.assertRaisesRegex(RealRegtestError, "^CORE_BINARY_CHANGED$"):
                verify_binary(self.binary, self.digest)
        self.assertEqual(calls, 2)

    def test_binary_hash_never_reopens_path_for_bytes(self):
        """Path.open is not used after the descriptor identity check."""
        with patch.object(Path, "open", side_effect=AssertionError("UNSAFE_REOPEN")):
            self.assertEqual(verify_binary(self.binary, self.digest),
                             self.binary.resolve())

    def test_binary_native_stat_fd_consistency_repeated(self):
        """Expose exact metadata fields if native stat/fstat ever disagree."""
        for attempt in range(24):
            before = self.binary.lstat()
            fd = os.open(self.binary, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            try:
                opened = os.fstat(fd)
            finally:
                os.close(fd)
            current = self.binary.lstat()
            diffs = [
                name for name in ("st_dev", "st_ino", "st_size",
                                  "st_mtime_ns", "st_ctime_ns")
                if (getattr(before, name) != getattr(opened, name)
                    or getattr(opened, name) != getattr(current, name))
            ]
            self.assertEqual(diffs, [], "stat/fstat field mismatch at attempt "
                             + str(attempt) + ": " + ", ".join(diffs))
            self.assertEqual(verify_binary(self.binary, self.digest),
                             self.binary.resolve())

    def test_no_symlinks_or_missing_binaries(self):
        with self.assertRaisesRegex(RealRegtestError, "CORE_BINARY_UNAVAILABLE"):
            verify_binary(self.root / "missing", self.digest)
        link = self.root / "link"
        try:
            link.symlink_to(self.binary)
        except (OSError, NotImplementedError):
            pass
        else:
            with self.assertRaisesRegex(RealRegtestError, "CORE_BINARY_NOT_REGULAR"):
                verify_binary(link, self.digest)

    def test_regtest_only_private_config(self):
        conf = self.root / "wam.conf"
        _write_private_conf(conf, 30001, 30002)
        data = conf.read_text(encoding="ascii")
        for value in ("regtest=1", "[regtest]", "connect=0", "listen=0", "daemon=0",
                      "rpcbind=127.0.0.1", "rpcallowip=127.0.0.1", "rpcport=30001"):
            self.assertIn(value, data)
        self.assertNotIn("mainnet", data)
        self.assertNotIn(str(Path.home()), data)
        with self.assertRaises(FileExistsError):
            _write_private_conf(conf, 1, 2)
        if os.name != "nt":
            self.assertEqual(conf.stat().st_mode & 0o077, 0)

    def test_cookie_and_secret_repr(self):
        path = self.root / ".cookie"
        path.write_text("__cookie__:synthetic-test-secret\n", encoding="ascii")
        auth = _read_cookie(path)
        self.assertEqual(auth.username, "__cookie__")
        self.assertNotIn("synthetic-test-secret", repr(auth))
        path.write_bytes(b"x" * 1025)
        with self.assertRaises(RealRegtestError):
            _read_cookie(path)
        path.write_bytes(b"malformed")
        with self.assertRaises(RealRegtestError):
            _read_cookie(path)

    def test_cookie_symlink_never_read(self):
        target = self.root / "real-cookie"
        target.write_text("__cookie__:synthetic-only", encoding="ascii")
        link = self.root / ".cookie-link"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable on this host")
        with self.assertRaisesRegex(RealRegtestError, "^CORE_COOKIE_INVALID$"):
            _read_cookie(link)

    def test_cookie_path_swap_between_lstat_and_open_is_denied(self):
        path = self.root / ".cookie-race"
        path.write_text("__cookie__:before", encoding="ascii")
        original_open = os.open

        def swap_then_open(name, flags, *args, **kwargs):
            path.unlink()
            path.write_text("__cookie__:after", encoding="ascii")
            return original_open(name, flags, *args, **kwargs)

        with patch("wam_privacy_wallet.node.real_regtest.os.open",
                   side_effect=swap_then_open):
            with self.assertRaisesRegex(RealRegtestError, "^CORE_COOKIE_INVALID$"):
                _read_cookie(path)

    def test_clean_environment(self):
        with patch.dict(os.environ, {"WAM_RPC_PASS": "SECRET", "HTTPS_PROXY": "SECRET",
                                     "LD_PRELOAD": "SECRET", "HOME": "SECRET"}):
            env = _clean_env(self.root)
            self.assertEqual(env["HOME"], str(self.root))
            for name in ("WAM_RPC_PASS", "HTTPS_PROXY", "LD_PRELOAD"):
                self.assertNotIn(name, env)

    def test_digest_mismatch_cannot_spawn(self):
        with patch("wam_privacy_wallet.node.real_regtest.subprocess.Popen") as proc:
            with self.assertRaisesRegex(RealRegtestError, "CORE_SHA256_MISMATCH"):
                check_real_regtest(self.binary, "1" * 64)
            proc.assert_not_called()

    def test_spawn_failure_redacted_and_isolated(self):
        with patch("wam_privacy_wallet.node.real_regtest.subprocess.Popen",
                   side_effect=OSError("sensitive")) as proc:
            with self.assertRaisesRegex(RealRegtestError, "^CORE_START_FAILED$"):
                check_real_regtest(self.binary, self.digest)
            args, options = proc.call_args
            self.assertFalse(options["shell"])
            self.assertIn("-regtest", args[0])
            self.assertTrue(any(x.startswith("-datadir=") for x in args[0]))
            self.assertTrue(any(x.startswith("-conf=") for x in args[0]))
            self.assertNotEqual(options["cwd"], Path.home())

    def test_early_exit_is_not_success(self):
        with patch("wam_privacy_wallet.node.real_regtest.subprocess.Popen") as proc:
            proc.return_value.poll.return_value = 7
            with self.assertRaisesRegex(RealRegtestError, "CORE_EARLY_EXIT"):
                check_real_regtest(self.binary, self.digest)

    def test_timeout_stops_own_child(self):
        with patch("wam_privacy_wallet.node.real_regtest.subprocess.Popen") as proc, patch(
            "wam_privacy_wallet.node.real_regtest.time.monotonic", side_effect=[1.0, 100.0]
        ):
            proc.return_value.poll.return_value = None
            with self.assertRaisesRegex(RealRegtestError, "CORE_START_TIMEOUT"):
                check_real_regtest(self.binary, self.digest, startup_timeout=1)
            proc.return_value.terminate.assert_called_once()
            proc.return_value.wait.assert_called_once_with(timeout=8)

    def test_invalid_timeout_blocks_launch(self):
        for timeout in (True, None, "45", 0, 121, float("nan"), float("inf")):
            with self.subTest(timeout=timeout), patch(
                "wam_privacy_wallet.node.real_regtest.subprocess.Popen"
            ) as proc:
                with self.assertRaises(RealRegtestError):
                    check_real_regtest(self.binary, self.digest, startup_timeout=timeout)
                proc.assert_not_called()


if __name__ == "__main__":
    unittest.main()
