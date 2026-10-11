"""Real loopback-wire tests of the opt-in WAM regtest diagnostic CLI.

The peer here is a deterministic HTTP fixture, not a WAM Core executable.
These tests must never attest publisher identity or authorize wallet actions.
"""
import contextlib
import io
import json
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from tools import probe_existing_regtest as cli
from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth

TIP = "a" * 64
TXID = "b" * 64
PASS = "regtest-only-test-secret"


class _LocalHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        data = json.loads(raw)
        self.server.calls.append(data)
        if self.headers.get("Authorization") != self.server.expected_authorization:
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        method = data["method"]
        if method == "getblockhash":
            value = WAM_REGTEST_GENESIS if data["params"] == [0] else TIP
        elif method == "getblockcount":
            value = 1
        elif method == "getbestblockhash":
            value = TIP
        elif method == "getblockchaininfo":
            value = {"chain": self.server.chain, "blocks": 1, "headers": 1,
                     "bestblockhash": TIP, "pruned": False}
        elif method == "getrawmempool":
            value = [TXID]
        elif method == "getblock":
            value = {"hash": TIP, "previousblockhash": WAM_REGTEST_GENESIS,
                     "height": 1, "tx": [{"txid": TXID}]}
        else:
            value = None
        wire = json.dumps({"result": value, "error": None, "id": 1}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(wire)))
        self.end_headers()
        self.wfile.write(wire)

    def log_message(self, *_args):
        pass


class ExistingRegtestCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import base64
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalHandler)
        cls.server.expected_authorization = (
            "Basic " + base64.b64encode(("regtest:" + PASS).encode()).decode()
        )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        self.server.calls = []
        self.server.chain = "regtest"
        self.port = self.server.server_port
        self.auth = ExplicitRpcAuth("regtest", PASS)

    def _call(self, **options):
        return cli.probe_existing_regtest(
            host="127.0.0.1", port=self.port, auth=self.auth, **options,
        )

    def test_actual_loopback_mempool_wire_has_no_mock_transport_hook(self):
        result = self._call()
        self.assertEqual((result["phase"], result["item_count"]), ("mempool", 1))
        calls = [c["method"] for c in self.server.calls]
        self.assertEqual(calls.count("getrawmempool"), 1)
        self.assertGreaterEqual(calls.count("getblockchaininfo"), 2)

    def test_block_wire_is_real_getblock_verbosity_three(self):
        result = self._call(
            block_height=1, previous_block_hash=WAM_REGTEST_GENESIS,
        )
        self.assertEqual((result["phase"], result["height"]), ("confirmed", 1))
        req = next(c for c in self.server.calls if c["method"] == "getblock")
        self.assertEqual(req["params"], [TIP, 3])

    def test_all_operational_authority_remains_false(self):
        report = self._call()
        for flag in ("binary_publisher_authenticated", "real_two_node_regtest_qualified",
                     "scanner_enabled", "wallet_ready", "signing_allowed",
                     "broadcast_allowed", "mainnet_allowed"):
            self.assertIs(report[flag], False)
        self.assertNotIn("token", json.dumps(report))
        self.assertNotIn(PASS, json.dumps(report))

    def test_wrong_chain_denied_before_any_scanner_method(self):
        self.server.chain = "main"
        with self.assertRaisesRegex(
            cli.RegtestLiveProbeError, "^REGTEST_PROBE_DENIED$"
        ):
            self._call()
        self.assertNotIn("getrawmempool", [c["method"] for c in self.server.calls])

    def test_wrong_previous_hash_and_wrong_height_denied(self):
        for height, prev in ((1, TXID), (2, WAM_REGTEST_GENESIS),
                             (True, WAM_REGTEST_GENESIS)):
            with self.subTest(height=height, prev=prev), self.assertRaisesRegex(
                cli.RegtestLiveProbeError, "^REGTEST_PROBE_DENIED$"
            ):
                self._call(block_height=height, previous_block_hash=prev)

    def test_block_argument_pair_required_before_any_socket(self):
        for kw in ({"block_height": 1}, {"previous_block_hash": WAM_REGTEST_GENESIS}):
            with self.subTest(kw=kw), self.assertRaisesRegex(
                cli.RegtestLiveProbeError, "^REGTEST_PROBE_BLOCK_PAIR_DENIED$"
            ):
                self._call(**kw)
        self.assertFalse(self.server.calls)

    def test_remote_and_named_hosts_rejected_before_network_access(self):
        for host in ("localhost", "example.org", "8.8.8.8", "0.0.0.0"):
            with self.subTest(host=host), self.assertRaisesRegex(
                cli.RegtestLiveProbeError, "^REGTEST_PROBE_DENIED$"
            ):
                cli.probe_existing_regtest(host=host, port=self.port, auth=self.auth)
        self.assertFalse(self.server.calls)

    def test_auth_failure_does_not_expose_password(self):
        bad = ExplicitRpcAuth("regtest", "different-private")
        with self.assertRaises(cli.RegtestLiveProbeError) as caught:
            cli.probe_existing_regtest(host="127.0.0.1", port=self.port, auth=bad)
        self.assertEqual(str(caught.exception), "REGTEST_PROBE_DENIED")
        self.assertNotIn("different-private", str(caught.exception))

    def test_cli_noninteractive_stdin_denied_before_secret_prompt(self):
        args = ["--port", str(self.port), "--rpc-user", "regtest"]
        err = io.StringIO()
        with patch.object(sys, "stdin", io.StringIO("NEVER READ ME")), \
             patch.object(cli.getpass, "getpass",
                          side_effect=AssertionError("MUST_NOT_PROMPT")), \
             contextlib.redirect_stderr(err):
            result = cli.main(args)
        self.assertEqual(result, 2)
        self.assertEqual(err.getvalue().strip(), "REGTEST_PROBE_TERMINAL_REQUIRED")
        self.assertFalse(self.server.calls)

    def test_cli_true_tty_path_never_prints_rpc_password(self):
        args = ["--port", str(self.port), "--rpc-user", "regtest"]
        terminal = io.StringIO()
        terminal.isatty = lambda: True
        stdout = io.StringIO()
        with patch.object(sys, "stdin", terminal), \
             patch.object(cli.getpass, "getpass", return_value=PASS), \
             contextlib.redirect_stdout(stdout):
            status = cli.main(args)
        self.assertEqual(status, 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["status"], "LOCAL_REGTEST_RPC_UNTRUSTED_READ_ONLY")
        self.assertNotIn(PASS, stdout.getvalue())
        self.assertNotIn("Authorization", stdout.getvalue())

    def test_process_launch_forbidden_even_on_successful_wire_read(self):
        with patch.object(subprocess, "Popen", side_effect=AssertionError("NO_CORE_LAUNCH")):
            report = self._call()
        self.assertEqual(report["transport"], "NUMERIC_LOOPBACK_ONLY")


if __name__ == "__main__":
    unittest.main()
