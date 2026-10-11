"""Native loopback HTTP regressions for the two-endpoint regtest observer.

HTTP peers here are protocol fixtures, NOT genuine WAM Core nodes. They test
the real socket/auth/deny path; production and real-two-node claims stay false.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from tools import probe_two_node_regtest as probe
from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth

TIP = "a" * 64
OTHER_TIP = "c" * 64
TXID = "b" * 64
SECRET_A = "disposable-secret-A"
SECRET_B = "disposable-secret-B"


class _Peer(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        request = json.loads(raw)
        self.server.calls.append(request)
        if self.headers.get("Authorization") != self.server.expected_auth:
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        method = request["method"]
        if method == "getblockhash":
            if request["params"] == [0]:
                result = WAM_REGTEST_GENESIS
            elif self.server.height == 2 and request["params"] == [1]:
                result = self.server.parent_hash
            else:
                result = self.server.tip
        elif method == "getblockcount":
            result = self.server.height
        elif method == "getbestblockhash":
            result = self.server.tip
        elif method == "getblockchaininfo":
            result = {
                "chain": self.server.chain, "blocks": self.server.height,
                "headers": self.server.height, "bestblockhash": self.server.tip,
                "pruned": False,
            }
        elif method == "getblock":
            result = {
                "hash": self.server.tip, "height": self.server.height,
                "previousblockhash": (
                    self.server.parent_hash if self.server.height == 2
                    else WAM_REGTEST_GENESIS
                ),
                "tx": [{"txid": TXID}],
            }
            if self.server.mutate_parent_after_block:
                self.server.parent_hash = OTHER_TIP
        elif method == "getrawmempool":
            result = [TXID]
            if self.server.mutate_after_mempool:
                self.server.tip = OTHER_TIP
        else:
            result = None
        reply = json.dumps({"result": result, "error": None, "id": 1}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *_args):
        pass


class TwoNodeRegtestWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = []
        cls.threads = []
        for password in (SECRET_A, SECRET_B):
            server = ThreadingHTTPServer(("127.0.0.1", 0), _Peer)
            server.expected_auth = "Basic " + base64.b64encode(
                ("regtest:" + password).encode()
            ).decode()
            cls.servers.append(server)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            cls.threads.append(worker)

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        for worker in cls.threads:
            worker.join(timeout=5)

    def setUp(self):
        for server in self.servers:
            server.calls = []
            server.chain = "regtest"
            server.tip = TIP
            server.height = 1
            server.parent_hash = "d" * 64
            server.mutate_parent_after_block = False
            server.mutate_after_mempool = False
        self.params = {
            "node_a_host": "127.0.0.1",
            "node_a_port": self.servers[0].server_port,
            "node_a_auth": ExplicitRpcAuth("regtest", SECRET_A),
            "node_b_host": "127.0.0.1",
            "node_b_port": self.servers[1].server_port,
            "node_b_auth": ExplicitRpcAuth("regtest", SECRET_B),
        }

    def _probe(self, **updates):
        return probe.probe_two_existing_regtest(**(self.params | updates))

    def _cli_args(self):
        return [
            "--node-a-host", "127.0.0.1",
            "--node-a-port", str(self.servers[0].server_port),
            "--node-a-rpc-user", "regtest",
            "--node-b-host", "127.0.0.1",
            "--node-b-port", str(self.servers[1].server_port),
            "--node-b-rpc-user", "regtest",
        ]

    def test_both_endpoints_actually_receive_separate_http_rpc(self):
        report = self._probe()
        self.assertTrue(report["same_reported_tip"])
        self.assertEqual(report["height"], 1)
        for server in self.servers:
            methods = [call["method"] for call in server.calls]
            self.assertIn("getblockchaininfo", methods)
            self.assertEqual(methods.count("getrawmempool"), 1)

    def test_zero_operational_authority_and_no_tip_txid_or_secret(self):
        report = self._probe()
        for flag in (
            "genuine_core_binary_verified", "independent_processes_verified",
            "real_two_node_regtest_qualified", "scanner_enabled",
            "wallet_ready", "signing_allowed", "broadcast_allowed",
            "mainnet_allowed",
        ):
            self.assertIs(report[flag], False)
        rendered = json.dumps(report)
        for secret in (TIP, TXID, SECRET_A, SECRET_B, "Authorization"):
            self.assertNotIn(secret, rendered)

    def test_mempool_count_from_each_real_socket(self):
        self.assertEqual(
            (self._probe()["node_a_mempool_count"], self._probe()["node_b_mempool_count"]),
            (1, 1),
        )

    def test_duplicate_endpoint_rejected_before_network(self):
        with self.assertRaisesRegex(probe.TwoNodeRegtestProbeError, "^TWO_NODE_ENDPOINTS_MUST_DIFFER$"):
            self._probe(
                node_b_port=self.params["node_a_port"],
                node_b_auth=self.params["node_a_auth"],
            )
        self.assertFalse(self.servers[0].calls)
        self.assertFalse(self.servers[1].calls)

    def test_remote_and_named_endpoint_denied_before_network(self):
        for host in ("localhost", "example.org", "0.0.0.0", "8.8.8.8"):
            with self.subTest(host=host), self.assertRaisesRegex(
                probe.TwoNodeRegtestProbeError, "^TWO_NODE_RPC_DENIED$",
            ):
                self._probe(node_b_host=host)
        self.assertFalse(self.servers[0].calls)

    def test_wrong_chain_rejected_before_mempool_reads(self):
        self.servers[1].chain = "main"
        with self.assertRaisesRegex(
            probe.TwoNodeRegtestProbeError, "^TWO_NODE_RPC_DENIED$",
        ):
            self._probe()
        self.assertFalse(any(x["method"] == "getrawmempool" for s in self.servers for x in s.calls))

    def test_divergent_tip_rejected_without_mempool_access(self):
        self.servers[1].tip = OTHER_TIP
        with self.assertRaisesRegex(
            probe.TwoNodeRegtestProbeError, "^TWO_NODE_CHAIN_DIVERGED$",
        ):
            self._probe()
        self.assertFalse(any(x["method"] == "getrawmempool" for s in self.servers for x in s.calls))

    def test_divergent_height_rejected_before_scanner_methods(self):
        self.servers[1].height = 2
        with self.assertRaisesRegex(
            probe.TwoNodeRegtestProbeError, "^TWO_NODE_CHAIN_DIVERGED$",
        ):
            self._probe()
        self.assertFalse(any(x["method"] == "getrawmempool" for s in self.servers for x in s.calls))

    def test_wrong_secondary_password_has_fixed_redacted_error(self):
        with self.assertRaises(probe.TwoNodeRegtestProbeError) as caught:
            self._probe(node_b_auth=ExplicitRpcAuth("regtest", "do-not-expose"))
        self.assertEqual(str(caught.exception), "TWO_NODE_RPC_DENIED")
        self.assertNotIn("do-not-expose", str(caught.exception))

    def test_mutation_mid_read_fails_closed_without_authority(self):
        self.servers[0].mutate_after_mempool = True
        with self.assertRaisesRegex(
            probe.TwoNodeRegtestProbeError, "^TWO_NODE_RPC_DENIED$",
        ):
            self._probe()

    def test_confirmed_block_two_real_sockets_derive_parent_from_rpc(self):
        for server in self.servers:
            server.height = 2
        report = self._probe(block_height=2)
        self.assertEqual(report["mode"], "confirmed")
        self.assertEqual((report["node_a_block_tx_count"], report["node_b_block_tx_count"]), (1, 1))
        self.assertIsNone(report["node_a_mempool_count"])
        for server in self.servers:
            methods = [entry["method"] for entry in server.calls]
            self.assertIn("getblock", methods)
            parents = [entry["params"] for entry in server.calls
                       if entry["method"] == "getblockhash"]
            self.assertGreaterEqual(parents.count([1]), 3)

    def test_same_tip_different_parent_rejected_across_nodes(self):
        for server in self.servers:
            server.height = 2
        self.servers[1].parent_hash = "e" * 64
        with self.assertRaisesRegex(
            probe.TwoNodeRegtestProbeError, "^TWO_NODE_ANCESTRY_DIVERGED$",
        ):
            self._probe(block_height=2)

    def test_confirmed_height_ahead_rejected_without_block_fetch(self):
        with self.assertRaisesRegex(
            probe.TwoNodeRegtestProbeError, "^TWO_NODE_HEIGHT_AHEAD$",
        ):
            self._probe(block_height=2)
        self.assertFalse(any(
            call["method"] == "getblock" for server in self.servers for call in server.calls
        ))

    def test_invalid_confirmed_height_denied_before_any_network(self):
        for height in (True, 0, -1, 1.0, 100_000_001):
            with self.subTest(height=height), self.assertRaisesRegex(
                probe.TwoNodeRegtestProbeError, "^TWO_NODE_HEIGHT_DENIED$",
            ):
                self._probe(block_height=height)
        self.assertFalse(self.servers[0].calls)
        self.assertFalse(self.servers[1].calls)

    def test_same_tip_parent_reorg_mid_block_denied(self):
        for server in self.servers:
            server.height = 2
        self.servers[0].mutate_parent_after_block = True
        with self.assertRaisesRegex(
            probe.TwoNodeRegtestProbeError, "^TWO_NODE_RPC_DENIED$",
        ):
            self._probe(block_height=2)

    def test_malformed_live_ancestor_denied_without_leaking_response(self):
        for server in self.servers:
            server.height = 2
        self.servers[1].parent_hash = "invalid-secret-parent"
        with self.assertRaises(probe.TwoNodeRegtestProbeError) as caught:
            self._probe(block_height=2)
        self.assertEqual(str(caught.exception), "TWO_NODE_RPC_DENIED")
        self.assertNotIn("invalid-secret-parent", str(caught.exception))

    def test_interactive_confirmed_cli_no_user_supplied_hash(self):
        tty = io.StringIO()
        tty.isatty = lambda: True
        out = io.StringIO()
        with patch.object(sys, "stdin", tty), \
             patch.object(probe.getpass, "getpass", side_effect=[SECRET_A, SECRET_B]), \
             contextlib.redirect_stdout(out):
            self.assertEqual(probe.main(self._cli_args() + ["--block-height", "1"]), 0)
        report = json.loads(out.getvalue())
        self.assertEqual(report["mode"], "confirmed")
        self.assertIs(report["wallet_ready"], False)
        self.assertNotIn(TIP, out.getvalue())
        self.assertNotIn(TXID, out.getvalue())

    def test_no_core_process_launch_during_real_socket_observation(self):
        with patch.object(subprocess, "Popen", side_effect=AssertionError("NO_EXEC")):
            report = self._probe()
        self.assertEqual(report["transport"], "NUMERIC_LOOPBACK_ONLY")

    def test_noninteractive_cli_denied_before_password_prompt_or_rpc(self):
        err = io.StringIO()
        with patch.object(sys, "stdin", io.StringIO("should-never-read")), \
             patch.object(probe.getpass, "getpass", side_effect=AssertionError("NO_PROMPT")), \
             contextlib.redirect_stderr(err):
            self.assertEqual(probe.main(self._cli_args()), 2)
        self.assertEqual(err.getvalue().strip(), "TWO_NODE_INTERACTIVE_TTY_REQUIRED")
        self.assertFalse(self.servers[0].calls)
        self.assertFalse(self.servers[1].calls)

    def test_interactive_cli_uses_two_secrets_and_redacted_stdout(self):
        terminal = io.StringIO()
        terminal.isatty = lambda: True
        out = io.StringIO()
        with patch.object(sys, "stdin", terminal), \
             patch.object(probe.getpass, "getpass", side_effect=[SECRET_A, SECRET_B]) as prompt, \
             contextlib.redirect_stdout(out):
            self.assertEqual(probe.main(self._cli_args()), 0)
        self.assertEqual(prompt.call_count, 2)
        report = json.loads(out.getvalue())
        self.assertEqual(report["status"], "TWO_ENDPOINT_REGTEST_UNTRUSTED_READ_ONLY")
        self.assertNotIn(SECRET_A, out.getvalue())
        self.assertNotIn(SECRET_B, out.getvalue())

    def test_invalid_auth_type_cannot_trigger_rpc(self):
        with self.assertRaisesRegex(
            probe.TwoNodeRegtestProbeError, "^TWO_NODE_AUTH_REQUIRED$",
        ):
            self._probe(node_b_auth=object())
        self.assertFalse(self.servers[0].calls)
        self.assertFalse(self.servers[1].calls)


if __name__ == "__main__":
    unittest.main()
