"""Actual TCP loopback HTTP tests for the two-node regtest transition observer.

Fixtures emulate JSON-RPC only; they do NOT attest or execute WAM Core.
Operational module constructs its own real socket-bound HTTP RPC transports,
never a callback/mock transport or simulated chain passed by the caller.
"""
from __future__ import annotations

import base64
import json
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
from wam_privacy_wallet.node.two_node_live_transition import (
    RegtestTransitionError, TwoNodeLiveTransitionObserver,
)

TIP1 = "a" * 64
TIP2 = "b" * 64
TIP3 = "c" * 64
FORK = "d" * 64
PASS_A = "TEMP_TEST_PASSWORD_A"
PASS_B = "TEMP_TEST_PASSWORD_B"


class _Peer(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        request = json.loads(raw)
        self.server.calls.append(request["method"])
        if self.headers.get("Authorization") != self.server.expected_auth:
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        method = request["method"]
        params = request["params"]
        h = self.server.height
        history = self.server.history
        if method == "getblockhash":
            result = history.get(params[0])
        elif method == "getblockcount":
            result = h
        elif method == "getbestblockhash":
            result = history[h]
        elif method == "getblockchaininfo":
            result = {
                "chain": self.server.chain, "blocks": h, "headers": h,
                "bestblockhash": history[h], "pruned": False,
            }
        else:
            result = None
        if method == self.server.flip_on and (method != "getblockhash" or params == [h]):
            self.server.history[h] = FORK
            self.server.flip_on = None
        reply = json.dumps({"result": result, "error": None, "id": 1}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *_args):
        pass


class TwoNodeLiveTransitionWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = []
        cls.workers = []
        for secret in (PASS_A, PASS_B):
            srv = ThreadingHTTPServer(("127.0.0.1", 0), _Peer)
            srv.expected_auth = "Basic " + base64.b64encode(
                ("regtest:" + secret).encode("ascii"),
            ).decode("ascii")
            worker = threading.Thread(target=srv.serve_forever, daemon=True)
            worker.start()
            cls.servers.append(srv)
            cls.workers.append(worker)

    @classmethod
    def tearDownClass(cls):
        for srv in cls.servers:
            srv.shutdown()
            srv.server_close()
        for worker in cls.workers:
            worker.join(timeout=5)

    def setUp(self):
        for srv in self.servers:
            srv.calls = []
            srv.height = 1
            srv.history = {0: WAM_REGTEST_GENESIS, 1: TIP1, 2: TIP2, 3: TIP3}
            srv.chain = "regtest"
            srv.flip_on = None
        self.a = LocalRegtestEndpoint("127.0.0.1", self.servers[0].server_port)
        self.b = LocalRegtestEndpoint("127.0.0.1", self.servers[1].server_port)
        self.auth_a = ExplicitRpcAuth("regtest", PASS_A)
        self.auth_b = ExplicitRpcAuth("regtest", PASS_B)
        self.observer = self._new()

    def _new(self, **kwargs):
        vals = {
            "node_a": self.a, "auth_a": self.auth_a,
            "node_b": self.b, "auth_b": self.auth_b,
        }
        vals.update(kwargs)
        return TwoNodeLiveTransitionObserver(**vals)

    def _change(self, operation):
        def apply(_seconds):
            operation()
        with patch("wam_privacy_wallet.node.two_node_live_transition.time.sleep",
                   side_effect=apply):
            return self.observer.observe(interval_seconds=0.2)

    def test_two_real_independent_localhost_sockets_report_unchanged(self):
        result = self.observer.observe()
        self.assertEqual(result["transition"], "UNCHANGED")
        self.assertEqual((result["height_before"], result["height_after"]), (1, 1))
        for srv in self.servers:
            self.assertGreater(srv.calls.count("getblockhash"), 2)
            self.assertIn("getblockchaininfo", srv.calls)

    def test_both_nodes_extend_without_false_reorg(self):
        def advance():
            for srv in self.servers:
                srv.height = 2
        report = self._change(advance)
        self.assertEqual(report["transition"], "EXTENSION")
        self.assertEqual((report["height_before"], report["height_after"]), (1, 2))
        self.assertIs(report["requires_rescan"], False)

    def test_same_height_reorg_reports_rescan_required(self):
        def reorg():
            for srv in self.servers:
                srv.history[1] = FORK
        report = self._change(reorg)
        self.assertEqual(report["transition"], "REORG_RESCAN_REQUIRED")
        self.assertIs(report["reorg_observed"], True)
        self.assertIs(report["requires_rescan"], True)

    def test_higher_tip_with_rewritten_old_height_is_reorg(self):
        def reorg():
            for srv in self.servers:
                srv.history[1] = FORK
                srv.height = 2
        report = self._change(reorg)
        self.assertEqual(report["transition"], "REORG_RESCAN_REQUIRED")
        self.assertEqual(report["height_after"], 2)

    def test_chain_height_decrease_is_reorg(self):
        for srv in self.servers:
            srv.height = 2
        def rewind():
            for srv in self.servers:
                srv.height = 1
        report = self._change(rewind)
        self.assertEqual(report["transition"], "REORG_RESCAN_REQUIRED")
        self.assertIs(report["requires_rescan"], True)

    def test_divergent_peer_tip_denied(self):
        self.servers[1].history[1] = FORK
        with self.assertRaisesRegex(
            RegtestTransitionError, "^REGTEST_TRANSITION_PEER_DIVERGENCE$",
        ):
            self.observer.observe()

    def test_same_tip_but_different_parent_denied(self):
        for srv in self.servers:
            srv.height = 2
        self.servers[1].history[1] = FORK
        with self.assertRaisesRegex(
            RegtestTransitionError, "^REGTEST_TRANSITION_ANCESTRY_DIVERGENCE$",
        ):
            self.observer.observe()

    def test_wrong_regtest_genesis_denied(self):
        self.servers[0].history[0] = FORK
        with self.assertRaises(RegtestTransitionError):
            self.observer.observe()
        self.assertNotIn("getblockchaininfo", self.servers[1].calls)

    def test_wrong_chain_rejected_without_authority(self):
        self.servers[1].chain = "main"
        with self.assertRaisesRegex(
            RegtestTransitionError, "^REGTEST_TRANSITION_RPC_DENIED$",
        ):
            self.observer.observe()

    def test_wrong_password_is_redacted(self):
        wrong = self._new(auth_b=ExplicitRpcAuth("regtest", "NO_EXPOSE_SECRET"))
        with self.assertRaises(RegtestTransitionError) as caught:
            wrong.observe()
        self.assertNotIn("NO_EXPOSE_SECRET", str(caught.exception))

    def test_mutation_during_live_rpc_read_fails_closed(self):
        self.servers[0].flip_on = "getblockhash"
        with self.assertRaises(RegtestTransitionError):
            self.observer.observe()

    def test_interval_validation_prevents_any_network(self):
        for interval in (-1, 6, True, None, float("nan"), float("inf"), "0"):
            with self.subTest(interval=interval), self.assertRaisesRegex(
                RegtestTransitionError, "^REGTEST_TRANSITION_INTERVAL_DENIED$",
            ):
                self.observer.observe(interval_seconds=interval)
        self.assertFalse(self.servers[0].calls)
        self.assertFalse(self.servers[1].calls)

    def test_duplicate_endpoint_denied_before_network(self):
        with self.assertRaisesRegex(
            RegtestTransitionError, "^REGTEST_TRANSITION_DUPLICATE_ENDPOINT$",
        ):
            self._new(node_b=self.a)
        self.assertFalse(self.servers[0].calls)

    def test_no_hashes_credentials_or_wallet_authority_in_report(self):
        report = self.observer.observe()
        for key in ("genuine_core_processes_verified", "two_node_regtest_qualified",
                    "scanner_enabled", "wallet_ready", "signing_allowed",
                    "broadcast_allowed", "mainnet_allowed"):
            self.assertIs(report[key], False)
        rendered = json.dumps(report)
        for forbidden in (TIP1, WAM_REGTEST_GENESIS, PASS_A, PASS_B, "Authorization"):
            self.assertNotIn(forbidden, rendered)

    def test_no_core_subprocess_on_successful_live_http_observation(self):
        with patch.object(subprocess, "Popen",
                          side_effect=AssertionError("NO_CORE_LAUNCH")):
            report = self.observer.observe()
        self.assertIs(report["two_node_regtest_qualified"], False)


if __name__ == "__main__":
    unittest.main()
