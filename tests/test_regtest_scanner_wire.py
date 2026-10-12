"""Actual loopback HTTP contract tests for regtest scanner-shaped reads.

The HTTP peer is a disposable protocol fixture, NOT a WAM Core binary. Only
the actual transport path is exercised. No wallet, funds, keys or network peers.
"""
import json
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from wam_privacy_wallet.integrations.regtest_scanner_wire import (
    RegtestScannerReadBridge, RegtestScannerWireError,
)
from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth

TIP = "a" * 64
OTHER = "d" * 64
TX = "c" * 64


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        request = json.loads(raw)
        self.server.requests.append((self.path, dict(self.headers), request))
        method = request["method"]
        if method == "getblockhash":
            response = (self.server.genesis if request["params"] == [0] else
                        self.server.parent_hash if self.server.height == 2 and request["params"] == [1]
                        else self.server.tip)
            if self.server.height == 2 and request["params"] == [1] and self.server.bad_parent:
                response = "bad-parent"
        elif method == "getblockcount":
            response = self.server.height
        elif method == "getbestblockhash":
            response = self.server.tip
        elif method == "getblockchaininfo":
            response = {
                "chain": self.server.chain, "blocks": self.server.height, "headers": self.server.height,
                "bestblockhash": self.server.tip, "pruned": self.server.pruned,
            }
        elif method == "getblock":
            response = {"hash": TIP, "previousblockhash": (
                self.server.parent_hash if self.server.height == 2 else WAM_REGTEST_GENESIS),
                        "height": self.server.height, "tx": [{"txid": TX}]}
        elif method == "getrawmempool":
            response = [TX]
        else:
            response = None
        if method in self.server.results:
            response = self.server.results[method]
        if method in self.server.flip_on:
            self.server.tip = OTHER
        if method in self.server.flip_parent_on:
            self.server.parent_hash = OTHER
        wire = json.dumps({"result": response, "error": None, "id": 1}).encode()
        if self.server.reply_override is not None and method == self.server.reply_method:
            wire = self.server.reply_override
        self.send_response(self.server.status if method == self.server.reply_method else 200)
        self.send_header("Content-Type", "application/json")
        declared = (self.server.length_override if method == self.server.reply_method
                    and self.server.length_override is not None else len(wire))
        self.send_header("Content-Length", str(declared))
        self.end_headers()
        try:
            self.wfile.write(wire)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_args):
        pass


class RegtestScannerReadBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.endpoint = LocalRegtestEndpoint("127.0.0.1", cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        self.server.requests = []
        self.server.tip = TIP
        self.server.genesis = WAM_REGTEST_GENESIS
        self.server.chain = "regtest"
        self.server.pruned = False
        self.server.height = 1
        self.server.parent_hash = "b" * 64
        self.server.bad_parent = False
        self.server.flip_parent_on = set()
        self.server.results = {}
        self.server.flip_on = set()
        self.server.status = 200
        self.server.reply_override = None
        self.server.reply_method = "getblock"
        self.server.length_override = None
        self.bridge = RegtestScannerReadBridge(
            self.endpoint, ExplicitRpcAuth("fixture", "test-only"),
        )

    def test_real_loopback_http_fetches_block_without_mock_callback(self):
        summary = self.bridge.read_confirmed(1, expected_previous_hash=WAM_REGTEST_GENESIS)
        self.assertEqual((summary.phase, summary.height, summary.item_count),
                         ("confirmed", 1, 1))
        requests = [r[2] for r in self.server.requests]
        self.assertEqual([r["method"] for r in requests].count("getblock"), 1)
        getblock = next(r for r in requests if r["method"] == "getblock")
        self.assertEqual(getblock["params"], [TIP, 3])
        self.assertEqual(getblock["jsonrpc"], "1.0")
        self.assertGreaterEqual([r["method"] for r in requests].count("getblockchaininfo"), 2)
        self.assertTrue(all(path == "/" for path, _, _ in self.server.requests))
        self.assertTrue(all("Authorization" in headers for _, headers, _ in self.server.requests))

    def test_mempool_reads_live_wire_with_zero_operational_authority(self):
        summary = self.bridge.read_mempool()
        self.assertEqual((summary.phase, summary.item_count), ("mempool", 1))
        self.assertEqual([r[2]["method"] for r in self.server.requests].count("getrawmempool"), 1)
        for field in ("scanner_enabled", "wallet_ready", "chain_identity_verified"):
            self.assertIs(getattr(summary, field), False)

    def test_denies_write_methods_and_scanner_rpc_params_before_socket(self):
        for method, params in (("sendrawtransaction", []), ("stop", []),
                               ("getwalletinfo", []), ("getblock", [TIP, 2]),
                               ("getblock", ["bad", 3]), ("getrawmempool", [True])):
            with self.subTest(method=method, params=params):
                with self.assertRaises(RegtestScannerWireError):
                    self.bridge._scanner.call(method, params)
        self.assertFalse(self.server.requests)

    def test_existing_diagnostic_wire_never_gains_transaction_lookup(self):
        # Expanding the separately scoped WSP-1 adapter must not broaden
        # the original scanner diagnostics or the identity-only RPC.
        with self.assertRaisesRegex(RegtestScannerWireError,
                                    "^SCAN_RPC_METHOD_DENIED$"):
            self.bridge._scanner.call("getrawtransaction", [TX, 2])
        self.assertFalse(self.server.requests)

    def test_reject_remote_hosts_and_bad_transport_timeout(self):
        for host in ("localhost", "example.org", "8.8.8.8", "0.0.0.0"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                LocalRegtestEndpoint(host, 12345)
        for timeout in (0, 11, True, "1", float("nan"), float("inf")):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                RegtestScannerReadBridge(
                    self.endpoint, ExplicitRpcAuth("fixture", "test-only"),
                    timeout=timeout,
                )
        self.assertFalse(self.server.requests)

    def test_invalid_confirmed_expectations_cause_zero_network_calls(self):
        for height, previous in ((True, WAM_REGTEST_GENESIS), (0, WAM_REGTEST_GENESIS),
                                 (100000001, WAM_REGTEST_GENESIS), (1, "wrong"),
                                 (1, TIP.upper())):
            with self.subTest(height=height, previous=previous):
                with self.assertRaisesRegex(RegtestScannerWireError, "SCAN_RPC_EXPECTATION_DENIED"):
                    self.bridge.read_confirmed(height, expected_previous_hash=previous)
        self.assertFalse(self.server.requests)

    def test_wrong_genesis_and_chain_fail_before_scanner_request(self):
        self.server.genesis = OTHER
        with self.assertRaisesRegex(RegtestScannerWireError, "^SCAN_RPC_PROFILE_DENIED$"):
            self.bridge.read_confirmed(1, expected_previous_hash=WAM_REGTEST_GENESIS)
        self.assertNotIn("getblock", [r[2]["method"] for r in self.server.requests])
        self.server.requests = []
        self.server.genesis = WAM_REGTEST_GENESIS
        self.server.chain = "main"
        with self.assertRaisesRegex(RegtestScannerWireError, "^SCAN_RPC_PROFILE_DENIED$"):
            self.bridge.read_mempool()
        self.assertNotIn("getrawmempool", [r[2]["method"] for r in self.server.requests])

    def test_pruned_regtest_profile_denied_before_block(self):
        self.server.pruned = True
        with self.assertRaisesRegex(RegtestScannerWireError, "^SCAN_RPC_PROFILE_DENIED$"):
            self.bridge.read_confirmed(1, expected_previous_hash=WAM_REGTEST_GENESIS)
        self.assertNotIn("getblock", [r[2]["method"] for r in self.server.requests])

    def test_reorg_during_block_rpc_denied_after_read(self):
        self.server.flip_on.add("getblock")
        with self.assertRaisesRegex(RegtestScannerWireError, "^SCAN_RPC_TIP_CHANGED$"):
            self.bridge.read_confirmed(1, expected_previous_hash=WAM_REGTEST_GENESIS)

    def test_wrong_block_identity_and_previous_hash_fail_closed(self):
        for changed in ({"hash": OTHER}, {"previousblockhash": OTHER},
                        {"height": 2}, {"tx": [{"txid": "BAD"}]}):
            block = {"hash": TIP, "previousblockhash": WAM_REGTEST_GENESIS,
                     "height": 1, "tx": [{"txid": TX}]}
            block.update(changed)
            self.server.results["getblock"] = block
            with self.subTest(changed=changed), self.assertRaisesRegex(
                RegtestScannerWireError, "^SCAN_RPC_BLOCK_DENIED$"
            ):
                self.bridge.read_confirmed(1, expected_previous_hash=WAM_REGTEST_GENESIS)

    def test_duplicate_block_and_mempool_transactions_denied(self):
        self.server.results["getblock"] = {
            "hash": TIP, "previousblockhash": WAM_REGTEST_GENESIS,
            "height": 1, "tx": [{"txid": TX}, {"txid": TX}],
        }
        with self.assertRaisesRegex(RegtestScannerWireError, "^SCAN_RPC_BLOCK_DENIED$"):
            self.bridge.read_confirmed(1, expected_previous_hash=WAM_REGTEST_GENESIS)
        self.server.results["getrawmempool"] = [TX, TX]
        with self.assertRaisesRegex(RegtestScannerWireError, "^SCAN_RPC_MEMPOOL_DENIED$"):
            self.bridge.read_mempool()

    def test_http_auth_failure_does_not_expose_credentials(self):
        self.server.reply_method = "getblockcount"
        self.server.status = 401
        self.server.reply_override = b'wallet-private-key-in-error'
        with self.assertRaises(RegtestScannerWireError) as result:
            self.bridge.read_mempool()
        self.assertEqual(str(result.exception), "SCAN_RPC_PROFILE_DENIED")
        self.assertNotIn("test-only", repr(result.exception))
        self.assertNotIn("private-key", repr(result.exception))

    def test_invalid_wire_reply_denied_without_payload_leaks(self):
        for data in (b'not json', b'{"id":2,"result":[],"error":null}',
                     b'{"id":true,"result":[],"error":null}',
                     b'{"id":1,"result":[]}', b'{"id":1,"result":null,"error":"secret"}'):
            self.server.reply_method = "getrawmempool"
            self.server.reply_override = data
            with self.subTest(data=data), self.assertRaises(RegtestScannerWireError) as caught:
                self.bridge.read_mempool()
            self.assertNotIn("secret", str(caught.exception))

    def test_read_response_size_cap_rejects_claimed_oversize(self):
        self.server.reply_method = "getrawmempool"
        self.server.length_override = 8 * 1024 * 1024 + 1
        with self.assertRaisesRegex(RegtestScannerWireError, "^SCAN_RPC_RESPONSE_LIMIT$"):
            self.bridge.read_mempool()

    def test_height_ahead_rejected_after_regtest_probe(self):
        with self.assertRaisesRegex(RegtestScannerWireError, "^SCAN_RPC_HEIGHT_AHEAD$"):
            self.bridge.read_confirmed(2, expected_previous_hash=WAM_REGTEST_GENESIS)
        self.assertNotIn("getblock", [r[2]["method"] for r in self.server.requests])

    def test_live_node_supplies_parent_without_external_expected_hash(self):
        summary = self.bridge.read_confirmed(1)
        self.assertEqual((summary.height, summary.item_count), (1, 1))
        gethash = [r[2]["params"] for r in self.server.requests
                   if r[2]["method"] == "getblockhash"]
        self.assertGreaterEqual(gethash.count([0]), 3)
        self.assertGreaterEqual(gethash.count([1]), 2)

    def test_mismatched_external_parent_denied_before_block_read(self):
        with self.assertRaisesRegex(RegtestScannerWireError,
                                    "^SCAN_RPC_PREVIOUS_MISMATCH$"):
            self.bridge.read_confirmed(1, expected_previous_hash=TX)
        self.assertNotIn("getblock", [r[2]["method"] for r in self.server.requests])

    def test_parent_hash_change_with_stable_tip_is_denied(self):
        self.server.height = 2
        self.server.flip_parent_on.add("getblock")
        with self.assertRaisesRegex(RegtestScannerWireError,
                                    "^SCAN_RPC_TIP_CHANGED$"):
            self.bridge.read_confirmed(2)
        self.assertEqual(self.server.tip, TIP)

    def test_parent_invalid_rpc_payload_denied_before_getblock(self):
        self.server.height = 2
        self.server.bad_parent = True
        with self.assertRaisesRegex(RegtestScannerWireError,
                                    "^SCAN_RPC_PARENT_DENIED$"):
            self.bridge.read_confirmed(2)
        self.assertNotIn("getblock", [r[2]["method"] for r in self.server.requests])

    def test_live_transport_does_not_launch_core_or_load_wsp(self):
        with patch.object(subprocess, "Popen", side_effect=AssertionError("NO_CORE_LAUNCH")):
            self.assertEqual(self.bridge.read_mempool().item_count, 1)
        import sys
        self.assertFalse(any(k.startswith("wam_sp") for k in sys.modules))


if __name__ == "__main__":
    unittest.main()
