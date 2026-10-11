"""Non-production harness tests: no WAM Core process ever executes."""

import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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
        if os.name != "nt":
            path.chmod(0o600)  # Real Core cookie must be private on POSIX.
        auth = _read_cookie(path)
        self.assertEqual(auth.username, "__cookie__")
        self.assertNotIn("synthetic-test-secret", repr(auth))
        path.write_bytes(b"x" * 1025)
        with self.assertRaises(RealRegtestError):
            _read_cookie(path)
        path.write_bytes(b"malformed")
        with self.assertRaises(RealRegtestError):
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

    def test_verified_binary_still_cannot_spawn_before_binding_review(self):
        with patch("wam_privacy_wallet.node.real_regtest.subprocess.Popen") as proc:
            with self.assertRaisesRegex(RealRegtestError,
                                        "^CORE_EXECUTION_REVIEW_REQUIRED$"):
                check_real_regtest(self.binary, self.digest)
            proc.assert_not_called()

    def test_launch_gate_precedes_workspace_creation_and_socket_bind(self):
        with patch("wam_privacy_wallet.node.real_regtest.tempfile.TemporaryDirectory"
                   ) as workspace, patch(
                   "wam_privacy_wallet.node.real_regtest._free_local_port"
                   ) as bind, patch(
                   "wam_privacy_wallet.node.real_regtest.subprocess.Popen"
                   ) as process:
            with self.assertRaisesRegex(RealRegtestError,
                                        "^CORE_EXECUTION_REVIEW_REQUIRED$"):
                check_real_regtest(self.binary, self.digest)
            workspace.assert_not_called()
            bind.assert_not_called()
            process.assert_not_called()

    def test_no_environment_flag_can_bypass_launch_interlock(self):
        with patch.dict(os.environ, {
            "WAM_REAL_CORE_ALLOW": "1", "WAM_NETWORK": "regtest",
            "WAM_CORE_SHA256": self.digest,
        }), patch("wam_privacy_wallet.node.real_regtest.subprocess.Popen") as proc:
            with self.assertRaisesRegex(RealRegtestError,
                                        "^CORE_EXECUTION_REVIEW_REQUIRED$"):
                check_real_regtest(self.binary, self.digest)
            proc.assert_not_called()

    def test_spawn_failure_redacted_and_isolated(self):
        with patch("wam_privacy_wallet.node.real_regtest._require_reviewed_core_launch"), \
             patch("wam_privacy_wallet.node.real_regtest.subprocess.Popen",
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
        with patch("wam_privacy_wallet.node.real_regtest._require_reviewed_core_launch"), \
             patch("wam_privacy_wallet.node.real_regtest.subprocess.Popen") as proc:
            proc.return_value.poll.return_value = 7
            with self.assertRaisesRegex(RealRegtestError, "CORE_EARLY_EXIT"):
                check_real_regtest(self.binary, self.digest)

    def test_timeout_stops_own_child(self):
        with patch("wam_privacy_wallet.node.real_regtest._require_reviewed_core_launch"), \
             patch("wam_privacy_wallet.node.real_regtest.subprocess.Popen") as proc, patch(
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
