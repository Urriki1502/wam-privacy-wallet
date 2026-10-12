"""Real-loopback TCP fixture regressions; never WAM Core process execution."""
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
from wam_privacy_wallet.node.two_node_bounded_ancestry import (
    TwoNodeAncestryError, TwoNodeBoundedAncestry,
)

HISTORY = {
    0: WAM_REGTEST_GENESIS,
    1: "a" * 64,
    2: "b" * 64,
    3: "c" * 64,
}
FORK = "d" * 64
SECRET_A = "REGTEST_SYNTHETIC_AUTH_A"
SECRET_B = "REGTEST_SYNTHETIC_AUTH_B"


class _Server(BaseHTTPRequestHandler):
    def do_POST(self):
        server = self.server
        try:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            request = json.loads(body)
        except (ValueError, KeyError):
            self.send_error(400)
            return
        method = request.get("method")
        server.calls.append(method)
        if self.headers.get("Authorization") != server.authorization:
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        height = server.height
        if method == "getblockhash":
            block_height = request["params"][0]
            server.at_height[block_height] = server.at_height.get(block_height, 0) + 1
            if (server.flip_height == block_height
                    and server.at_height[block_height] >= server.flip_count):
                server.history[block_height] = FORK
            result = server.history.get(block_height)
        elif method == "getblockcount":
            result = height
        elif method == "getbestblockhash":
            result = server.history.get(height)
        elif method == "getblockchaininfo":
            result = {
                "chain": server.chain, "blocks": height,
                "headers": height, "bestblockhash": server.history.get(height),
                "pruned": server.pruned,
            }
        else:
            result = None
        response = json.dumps({"result": result, "error": None, "id": 1}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args):
        pass


class TwoNodeBoundedAncestryWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = []
        cls.workers = []
        for secret in (SECRET_A, SECRET_B):
            server = ThreadingHTTPServer(("127.0.0.1", 0), _Server)
            server.authorization = "Basic " + base64.b64encode(
                ("regtest:" + secret).encode(),
            ).decode()
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            cls.servers.append(server)
            cls.workers.append(worker)

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        for worker in cls.workers:
            worker.join(timeout=5)

    def setUp(self):
        for server in self.servers:
            server.calls = []
            server.height = 3
            server.history = dict(HISTORY)
            server.at_height = {}
            server.flip_height = None
            server.flip_count = 999
            server.chain = "regtest"
            server.pruned = False
        self.a = LocalRegtestEndpoint("127.0.0.1", self.servers[0].server_port)
        self.b = LocalRegtestEndpoint("127.0.0.1", self.servers[1].server_port)
        self.auth_a = ExplicitRpcAuth("regtest", SECRET_A)
        self.auth_b = ExplicitRpcAuth("regtest", SECRET_B)
        self.audit = TwoNodeBoundedAncestry(self.a, self.auth_a, self.b, self.auth_b)

    def test_actual_two_distinct_tcp_hosts_audit_three_heights_twice(self):
        result = self.audit.audit(window_size=3)
        self.assertEqual(result["window_start"], 1)
        self.assertEqual(result["window_count"], 3)
        self.assertEqual(result["height_hash_read_passes"], 2)
        for server in self.servers:
            self.assertGreaterEqual(server.at_height.get(1, 0), 2)
            self.assertGreaterEqual(server.at_height.get(2, 0), 2)
            self.assertIn("getblockchaininfo", server.calls)

    def test_default_window_is_bounded_to_eight(self):
        self.assertEqual(self.audit.audit()["window_count"], 4)

    def test_full_window_includes_genesis_and_matches_pinned_hash(self):
        result = self.audit.audit(window_size=16)
        self.assertEqual((result["window_start"], result["window_count"]), (0, 4))

    def test_genesis_only_height_zero_is_supported(self):
        for server in self.servers:
            server.height = 0
        result = self.audit.audit()
        self.assertEqual((result["height"], result["window_count"]), (0, 1))

    def test_invalid_window_values_refused_before_any_wire_calls(self):
        for value in (0, -1, 17, True, False, 3.0, "3", None, (), 10**6):
            with self.subTest(value=value), self.assertRaisesRegex(
                TwoNodeAncestryError, "^REGTEST_ANCESTRY_WINDOW_DENIED$",
            ):
                self.audit.audit(window_size=value)
        for server in self.servers:
            self.assertEqual(server.calls, [])

    def test_duplicate_endpoint_or_wrong_types_refused_before_requests(self):
        for args in (
            (self.a, self.auth_a, self.a, self.auth_a),
            ("127.0.0.1", self.auth_a, self.b, self.auth_b),
            (self.a, "secret", self.b, self.auth_b),
        ):
            with self.subTest(args=tuple(type(x).__name__ for x in args)), \
                 self.assertRaises(TwoNodeAncestryError):
                TwoNodeBoundedAncestry(*args)
        self.assertEqual(self.servers[0].calls, [])

    def test_same_reported_tip_but_different_interior_height_denied(self):
        self.servers[1].history[2] = FORK
        with self.assertRaisesRegex(
            TwoNodeAncestryError, "^REGTEST_ANCESTRY_PEER_DIVERGENCE$",
        ):
            self.audit.audit(window_size=3)

    def test_silent_interior_mutation_between_two_passes_is_denied(self):
        # Identical tip/height/genesis: a hidden interior block changes
        # only after the first historical read, without modifying tip.
        self.servers[0].flip_height = 1
        self.servers[0].flip_count = 2
        with self.assertRaisesRegex(
            TwoNodeAncestryError, "^REGTEST_ANCESTRY_PEER_DIVERGENCE$",
        ):
            self.audit.audit(window_size=3)

    def test_different_tip_height_between_nodes_denied(self):
        self.servers[1].height = 2
        with self.assertRaisesRegex(
            TwoNodeAncestryError, "^REGTEST_ANCESTRY_CHAIN_DIVERGENCE$",
        ):
            self.audit.audit()

    def test_wrong_genesis_denied_even_with_matching_height_and_tip(self):
        self.servers[0].history[0] = FORK
        with self.assertRaisesRegex(
            TwoNodeAncestryError, "^REGTEST_ANCESTRY_RPC_DENIED$",
        ):
            self.audit.audit(window_size=4)

    def test_mainnet_or_pruned_node_denied(self):
        for key, value in (("chain", "main"), ("pruned", True)):
            with self.subTest(key=key):
                setattr(self.servers[1], key, value)
                with self.assertRaisesRegex(
                    TwoNodeAncestryError, "^REGTEST_ANCESTRY_RPC_DENIED$",
                ):
                    self.audit.audit()
                setattr(self.servers[1], key, "regtest" if key == "chain" else False)

    def test_invalid_non_lowercase_hash_denied(self):
        self.servers[1].history[1] = "G" * 64
        with self.assertRaisesRegex(
            TwoNodeAncestryError, "^REGTEST_ANCESTRY_HASH_DENIED$",
        ):
            self.audit.audit(window_size=3)

    def test_bad_auth_redacts_password(self):
        wrong = TwoNodeBoundedAncestry(
            self.a, self.auth_a, self.b,
            ExplicitRpcAuth("regtest", "DO_NOT_LEAK_THIS_TOKEN"),
        )
        with self.assertRaises(TwoNodeAncestryError) as context:
            wrong.audit()
        self.assertNotIn("DO_NOT_LEAK_THIS_TOKEN", str(context.exception))

    def test_report_contains_no_hash_addresses_or_credentials(self):
        report = self.audit.audit()
        rendered = json.dumps(report)
        for text in (HISTORY[0], HISTORY[1], HISTORY[2], HISTORY[3],
                     SECRET_A, SECRET_B, "Authorization", "127.0.0.1"):
            self.assertNotIn(text, rendered)
        for name in ("genuine_core_processes_verified", "block_parent_links_verified",
                     "real_two_node_regtest_qualified", "scanner_enabled",
                     "wallet_ready", "signing_allowed",
                     "broadcast_allowed", "mainnet_allowed"):
            self.assertIs(report[name], False)

    def test_never_calls_wam_core_subprocess_on_real_localhost_http(self):
        with patch.object(subprocess, "Popen",
                          side_effect=AssertionError("WAM_CORE_EXEC_DENIED")):
            result = self.audit.audit(window_size=3)
        self.assertIs(result["real_two_node_regtest_qualified"], False)


if __name__ == "__main__":
    unittest.main()
