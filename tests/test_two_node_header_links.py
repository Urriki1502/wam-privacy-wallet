"""Real localhost TCP contract regressions for non-authorizing header-link audit.

Fixture HTTP peers model untrusted RPC only: never actual WAM Core executables,
no keys, transaction creation, P2P routing, wallets or external endpoints.
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
from wam_privacy_wallet.node.two_node_header_links import (
    TwoNodeHeaderLinkAuditor, TwoNodeHeaderLinkError,
)

HISTORY = {0: WAM_REGTEST_GENESIS, 1: "a" * 64, 2: "b" * 64, 3: "c" * 64}
FORK = "d" * 64
PASSWORD_A = "SYNTHETIC_HEADER_SECRET_A"
PASSWORD_B = "SYNTHETIC_HEADER_SECRET_B"


class _Peer(BaseHTTPRequestHandler):
    def do_POST(self):
        srv = self.server
        body = self.rfile.read(int(self.headers["Content-Length"]))
        request = json.loads(body)
        method = request["method"]
        args = request["params"]
        srv.methods.append(method)
        if self.headers.get("Authorization") != srv.authorization:
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        h = srv.height
        if method == "getblockhash":
            at = args[0]
            srv.read_counts[at] = srv.read_counts.get(at, 0) + 1
            if at == srv.mutate_at and srv.read_counts[at] >= srv.mutate_after:
                srv.history[at] = FORK
            result = srv.history.get(at)
        elif method == "getblockcount":
            result = h
        elif method == "getbestblockhash":
            result = srv.history.get(h)
        elif method == "getblockchaininfo":
            result = {
                "chain": srv.chain, "blocks": h, "headers": h,
                "bestblockhash": srv.history.get(h), "pruned": srv.pruned,
            }
        elif method == "getblockheader":
            requested = args[0]
            at = next((key for key, value in srv.history.items()
                       if value == requested), None)
            if at is None:
                result = None
            else:
                result = {"hash": requested, "height": at}
                if at:
                    result["previousblockhash"] = srv.history[at - 1]
                if srv.corrupt_at == at:
                    if srv.corrupt == "wrong_parent":
                        result["previousblockhash"] = FORK
                    elif srv.corrupt == "no_parent":
                        result.pop("previousblockhash", None)
                    elif srv.corrupt == "bad_height":
                        result["height"] = True
                    elif srv.corrupt == "bad_hash":
                        result["hash"] = "e" * 64
                    elif srv.corrupt == "genesis_parent":
                        result["previousblockhash"] = FORK
                    elif srv.corrupt == "not_object":
                        result = []
                if srv.mutate_after_header == at:
                    srv.history[at] = FORK
                    srv.mutate_after_header = None
        else:
            result = None
        reply = json.dumps({"id": 1, "error": None, "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *_args):
        pass


class TwoNodeHeaderLinkWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers, cls.threads = [], []
        for password in (PASSWORD_A, PASSWORD_B):
            server = ThreadingHTTPServer(("127.0.0.1", 0), _Peer)
            server.authorization = "Basic " + base64.b64encode(
                ("regtest:" + password).encode("ascii"),
            ).decode("ascii")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.servers.append(server)
            cls.threads.append(thread)

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(timeout=5)

    def setUp(self):
        for server in self.servers:
            server.history = dict(HISTORY)
            server.height = 3
            server.chain = "regtest"
            server.pruned = False
            server.methods = []
            server.read_counts = {}
            server.mutate_at = -1
            server.mutate_after = 1000
            server.mutate_after_header = None
            server.corrupt_at = -1
            server.corrupt = None
        self.a = LocalRegtestEndpoint("127.0.0.1", self.servers[0].server_port)
        self.b = LocalRegtestEndpoint("127.0.0.1", self.servers[1].server_port)
        self.auth_a = ExplicitRpcAuth("regtest", PASSWORD_A)
        self.auth_b = ExplicitRpcAuth("regtest", PASSWORD_B)
        self.audit = TwoNodeHeaderLinkAuditor(
            self.a, self.auth_a, self.b, self.auth_b,
        )

    def test_independent_real_tcp_header_rpc_double_pass(self):
        report = self.audit.audit(window_size=3)
        self.assertEqual((report["window_start"], report["window_count"]), (1, 3))
        self.assertTrue(report["rpc_reported_parent_links_match"])
        for server in self.servers:
            self.assertEqual(server.methods.count("getblockheader"), 6)
            self.assertIn("getblockchaininfo", server.methods)

    def test_window_start_positive_anchors_to_previous_height(self):
        self.audit.audit(window_size=2)
        for server in self.servers:
            self.assertGreaterEqual(server.read_counts.get(1, 0), 2)
            self.assertEqual(server.methods.count("getblockheader"), 4)

    def test_genesis_parent_is_omitted_and_checked(self):
        report = self.audit.audit(window_size=16)
        self.assertEqual((report["window_start"], report["window_count"]), (0, 4))

    def test_single_genesis_header_supported(self):
        for server in self.servers:
            server.height = 0
        report = self.audit.audit()
        self.assertEqual((report["height"], report["window_count"]), (0, 1))

    def test_misreported_header_parent_rejected_even_if_both_nodes_agree(self):
        for server in self.servers:
            server.corrupt_at = 2
            server.corrupt = "wrong_parent"
        with self.assertRaisesRegex(
            TwoNodeHeaderLinkError, "^REGTEST_HEADER_PARENT_DENIED$",
        ):
            self.audit.audit(window_size=3)

    def test_missing_parent_field_denied(self):
        self.servers[0].corrupt_at = 2
        self.servers[0].corrupt = "no_parent"
        with self.assertRaises(TwoNodeHeaderLinkError):
            self.audit.audit(window_size=3)

    def test_wrong_header_identity_hash_height_and_shape_denied(self):
        for mistake in ("bad_height", "bad_hash", "not_object"):
            with self.subTest(mistake=mistake):
                self.servers[0].corrupt_at = 2
                self.servers[0].corrupt = mistake
                with self.assertRaises(TwoNodeHeaderLinkError):
                    self.audit.audit(window_size=3)

    def test_genesis_extra_parent_fails_closed(self):
        self.servers[0].corrupt_at = 0
        self.servers[0].corrupt = "genesis_parent"
        with self.assertRaisesRegex(
            TwoNodeHeaderLinkError, "^REGTEST_HEADER_GENESIS_PARENT_DENIED$",
        ):
            self.audit.audit(window_size=16)

    def test_divergent_internal_block_with_stable_tip_denied(self):
        self.servers[1].history[2] = FORK
        with self.assertRaisesRegex(
            TwoNodeHeaderLinkError, "^REGTEST_HEADER_PEER_DIVERGENCE$",
        ):
            self.audit.audit(window_size=3)

    def test_mutating_header_between_passes_is_denied(self):
        self.servers[0].mutate_after_header = 2
        with self.assertRaises(TwoNodeHeaderLinkError):
            self.audit.audit(window_size=3)

    def test_wrong_genesis_or_network_or_pruned_denied(self):
        for property_, replacement in (
            ("history", {**HISTORY, 0: FORK}),
            ("chain", "main"),
            ("pruned", True),
        ):
            with self.subTest(field=property_):
                old = getattr(self.servers[0], property_)
                setattr(self.servers[0], property_, replacement)
                with self.assertRaises(TwoNodeHeaderLinkError):
                    self.audit.audit(window_size=3)
                setattr(self.servers[0], property_, old)

    def test_wrong_auth_failure_redacts_secrets(self):
        wrong = TwoNodeHeaderLinkAuditor(
            self.a, self.auth_a, self.b,
            ExplicitRpcAuth("regtest", "DO_NOT_EXPOSE_AUTH"),
        )
        with self.assertRaises(TwoNodeHeaderLinkError) as caught:
            wrong.audit()
        self.assertNotIn("DO_NOT_EXPOSE_AUTH", str(caught.exception))

    def test_invalid_window_denied_before_network(self):
        for value in (0, -1, 17, True, False, None, 1.0, "2"):
            with self.subTest(value=value), self.assertRaisesRegex(
                TwoNodeHeaderLinkError, "^REGTEST_HEADER_WINDOW_DENIED$",
            ):
                self.audit.audit(window_size=value)
        self.assertFalse(self.servers[0].methods)
        self.assertFalse(self.servers[1].methods)

    def test_duplicate_or_non_native_endpoint_denied_before_network(self):
        for arguments in (
            (self.a, self.auth_a, self.a, self.auth_a),
            ("127.0.0.1", self.auth_a, self.b, self.auth_b),
            (self.a, "secret", self.b, self.auth_b),
        ):
            with self.assertRaises(TwoNodeHeaderLinkError):
                TwoNodeHeaderLinkAuditor(*arguments)
        self.assertFalse(self.servers[0].methods)

    def test_output_redacted_non_authorizing_and_no_executable(self):
        with patch.object(subprocess, "Popen",
                          side_effect=AssertionError("NO_CORE_EXEC")):
            report = self.audit.audit(window_size=3)
        for value in (*HISTORY.values(), PASSWORD_A, PASSWORD_B, "127.0.0.1"):
            self.assertNotIn(value, json.dumps(report))
        for key in ("genuine_core_processes_verified",
                    "cryptographic_headers_verified", "block_parent_links_verified",
                    "real_two_node_regtest_qualified", "scanner_enabled",
                    "wallet_ready", "signing_allowed", "broadcast_allowed",
                    "mainnet_allowed"):
            self.assertIs(report[key], False)


if __name__ == "__main__":
    unittest.main()
