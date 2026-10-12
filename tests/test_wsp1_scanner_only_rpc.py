"""Native localhost HTTP tests of the new WSP-1 scan-only RPC adapter.

The peer is a disposable fake JSON-RPC server, never WAM Core. No keys,
scanner database, signer, mempool broadcast or live wallet are involved.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import (
    Wsp1ScannerOnlyRpc, WspScannerRpcError,
)
from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth

TIP = "a" * 64
OTHER = "b" * 64
TX = "c" * 64
PREV = "d" * 64


class Fixture(BaseHTTPRequestHandler):
    def do_POST(self):
        wire = self.rfile.read(int(self.headers["Content-Length"]))
        try:
            request = json.loads(wire)
        except ValueError:
            self.send_error(400)
            return
        state = self.server
        state.requests.append((self.path, dict(self.headers), request))
        method = request["method"]
        params = request["params"]
        if method == "getblockhash":
            result = state.genesis if params == [0] else state.tip
        elif method == "getblockcount":
            result = 1
        elif method == "getbestblockhash":
            result = state.tip
        elif method == "getblockchaininfo":
            result = {"chain": state.chain, "blocks": 1, "headers": 1,
                      "bestblockhash": state.tip, "pruned": state.pruned}
        elif method == "getblock":
            result = {"hash": state.tip, "height": 1,
                      "previousblockhash": state.genesis, "tx": [{"txid": TX}]}
        elif method == "getrawmempool":
            result = [TX]
        elif method == "getrawtransaction":
            result = {"txid": params[0], "vin": [{"txid": PREV}],
                      "vout": [{"value": 0.1}]}
        else:
            result = None
        if method in state.overrides:
            result = state.overrides[method]
        payload = json.dumps({"result": result, "error": None, "id": 1}).encode()
        if method == state.change_on:
            state.tip = OTHER
        if method == state.fail_method:
            payload = state.fail_payload
        code = state.code if method == state.fail_method else 200
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length",
                         str(state.declared_size if method == state.fail_method
                             and state.declared_size is not None else len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_args):
        pass


class WspScannerOnlyRpcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.endpoint = LocalRegtestEndpoint("127.0.0.1", cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        state = self.server
        state.requests = []
        state.genesis = WAM_REGTEST_GENESIS
        state.tip = TIP
        state.chain = "regtest"
        state.pruned = False
        state.overrides = {}
        state.change_on = None
        state.fail_method = None
        state.fail_payload = b"untrusted wallet-secret"
        state.declared_size = None
        state.code = 200
        self.auth = ExplicitRpcAuth("synthetic", "fixture-password")
        self.rpc = Wsp1ScannerOnlyRpc(self.endpoint, self.auth)
        self.mempool = Wsp1ScannerOnlyRpc(
            self.endpoint, self.auth, include_mempool=True,
        )

    def _calls(self):
        return [r[2]["method"] for r in self.server.requests]

    def test_every_scan_call_requires_fresh_explicit_attest(self):
        for method, params in (("getblockcount", []), ("getblock", [TIP, 3])):
            with self.subTest(method=method), self.assertRaisesRegex(
                WspScannerRpcError, "^WSP_SCAN_ATTEST_REQUIRED$",
            ):
                self.rpc.call(method, params)
        self.assertFalse(self.server.requests)

    def test_wsp_scanner_sync_identity_methods_on_real_loopback_http(self):
        self.rpc.attest()
        self.assertEqual(self.rpc.call("getbestblockhash"), TIP)
        self.assertEqual(self.rpc.call("getblockcount"), 1)
        self.assertEqual(self.rpc.call("getblockhash", [1]), TIP)
        self.assertEqual(self.rpc.call("getblockhash", [0]), WAM_REGTEST_GENESIS)
        self.assertTrue(all(path == "/" for path, _, _ in self.server.requests))
        self.assertTrue(all("Authorization" in headers for _, headers, _
                            in self.server.requests))
        self.assertTrue(all(r["jsonrpc"] == "1.0" for _, _, r in self.server.requests))

    def test_full_verbose_three_block_is_strict_scanner_only_read(self):
        self.rpc.attest()
        block = self.rpc.call("getblock", [TIP, 3])
        self.assertEqual(block["tx"][0]["txid"], TX)
        self.assertIn("getblock", self._calls())
        self.assertEqual([r[2]["params"] for r in self.server.requests
                          if r[2]["method"] == "getblock"], [[TIP, 3]])

    def test_mempool_must_be_explicitly_selected_before_any_wire(self):
        self.rpc.attest()
        self.server.requests.clear()
        for method, params in (("getrawmempool", []),
                               ("getrawtransaction", [TX, 2])):
            with self.subTest(method=method), self.assertRaisesRegex(
                WspScannerRpcError, "^WSP_SCAN_MEMPOOL_DENIED$",
            ):
                self.rpc.call(method, params)
        self.assertEqual(self.server.requests, [])

    def test_opted_in_mempool_and_verbose_transaction_read_no_broadcast(self):
        self.mempool.attest()
        self.assertEqual(self.mempool.call("getrawmempool"), [TX])
        self.assertEqual(self.mempool.call("getrawtransaction", [TX, 2])["txid"], TX)
        self.assertEqual(self.mempool.call("getrawtransaction", [PREV, 1])["txid"], PREV)
        self.assertFalse(any(m in self._calls() for m in
                             ("sendrawtransaction", "getwalletinfo", "stop")))

    def test_disallow_all_write_methods_and_foreign_rpc_before_network(self):
        for method in ("sendrawtransaction", "submitblock", "stop",
                       "getwalletinfo", "importprivkey", "gettxout",
                       "testmempoolaccept", "getblockchaininfo", "getblockheader",
                       None, 1, ""):
            with self.subTest(method=method), self.assertRaisesRegex(
                WspScannerRpcError, "^WSP_SCAN_METHOD_DENIED$",
            ):
                self.mempool.call(method, [])
        self.assertEqual(self.server.requests, [])

    def test_malformed_params_fail_before_network_even_after_attest(self):
        self.mempool.attest()
        self.server.requests.clear()
        cases = (("getblock", [TIP, 2]), ("getblock", [TIP, True]),
                 ("getblock", [TIP.upper(), 3]), ("getblockhash", [True]),
                 ("getblockcount", [1]), ("getbestblockhash", [] + [1]),
                 ("getrawmempool", [True]), ("getrawtransaction", [TX, 0]),
                 ("getrawtransaction", [TX, True]),
                 ("getrawtransaction", ["bad", 2]),
                 ("getrawtransaction", [TX, 2, PREV]))
        for method, params in cases:
            with self.subTest(method=method, params=params), self.assertRaisesRegex(
                WspScannerRpcError, "^WSP_SCAN_PARAMS_DENIED$",
            ):
                self.mempool.call(method, params)
        self.assertFalse(self.server.requests)

    def test_wrong_genesis_chain_or_pruned_denies_before_scan(self):
        for name, val in (("genesis", OTHER), ("chain", "main"),
                          ("pruned", True)):
            setattr(self.server, name, val)
            with self.subTest(name=name), self.assertRaisesRegex(
                WspScannerRpcError, "^WSP_SCAN_PROFILE_DENIED$",
            ):
                self.rpc.attest()
            self.assertNotIn("getblock", self._calls())
            setattr(self.server, name, {
                "genesis": WAM_REGTEST_GENESIS, "chain": "regtest",
                "pruned": False,
            }[name])

    def test_tip_changes_during_block_read_poison_session(self):
        self.rpc.attest()
        self.server.change_on = "getblock"
        with self.assertRaisesRegex(WspScannerRpcError, "^WSP_SCAN_CHAIN_DRIFT$"):
            self.rpc.call("getblock", [TIP, 3])
        self.server.requests.clear()
        with self.assertRaisesRegex(WspScannerRpcError, "^WSP_SCAN_ATTEST_REQUIRED$"):
            self.rpc.call("getblockcount")
        self.assertEqual(self.server.requests, [])

    def test_attest_detects_profile_drift_and_revokes_previous_baseline(self):
        self.rpc.attest()
        self.server.tip = OTHER
        with self.assertRaisesRegex(WspScannerRpcError, "^WSP_SCAN_CHAIN_DRIFT$"):
            self.rpc.attest()
        self.server.requests.clear()
        with self.assertRaisesRegex(WspScannerRpcError, "^WSP_SCAN_ATTEST_REQUIRED$"):
            self.rpc.call("getblockcount")
        self.assertEqual(self.server.requests, [])

    def test_malformed_or_replayed_transaction_response_fails_closed(self):
        self.mempool.attest()
        for tx in (None, [], "deadbeef",
                   {"txid": OTHER, "vin": [{}], "vout": [{}]},
                   {"txid": TX, "vin": [], "vout": [{}]},
                   {"txid": TX, "vin": [{}], "vout": None}):
            self.server.overrides["getrawtransaction"] = tx
            self.mempool.attest()
            with self.subTest(tx=type(tx).__name__), self.assertRaisesRegex(
                WspScannerRpcError, "^WSP_SCAN_REPLY_DENIED$",
            ):
                self.mempool.call("getrawtransaction", [TX, 2])

    def test_duplicate_or_bad_mempool_ids_cannot_enter_scanner(self):
        for ids in ([TX, TX], ["invalid"], None, {"txids": [TX]}):
            self.server.overrides["getrawmempool"] = ids
            self.mempool.attest()
            with self.subTest(ids=str(ids)[:15]), self.assertRaisesRegex(
                WspScannerRpcError, "^WSP_SCAN_REPLY_DENIED$",
            ):
                self.mempool.call("getrawmempool")

    def test_malformed_block_or_duplicate_tx_rejected(self):
        self.rpc.attest()
        for data in (None, {"hash": OTHER, "tx": [{"txid": TX}]},
                     {"hash": TIP, "tx": [{"txid": TX}, {"txid": TX}]},
                     {"hash": TIP, "tx": [{"txid": "bad"}]},
                     {"hash": TIP, "tx": []}):
            self.server.overrides["getblock"] = data
            self.rpc.attest()
            with self.subTest(case=str(data)[:12]), self.assertRaisesRegex(
                WspScannerRpcError, "^WSP_SCAN_REPLY_DENIED$",
            ):
                self.rpc.call("getblock", [TIP, 3])

    def test_bounded_http_response_denied_without_credential_leak(self):
        self.mempool.attest()
        self.server.fail_method = "getrawmempool"
        self.server.declared_size = 8 * 1024 * 1024 + 1
        with self.assertRaisesRegex(WspScannerRpcError, "^WSP_SCAN_TRANSPORT_DENIED$") as err:
            self.mempool.call("getrawmempool")
        self.assertNotIn("fixture-password", str(err.exception))

    def test_http_auth_failure_redacts_node_response_and_revokes_session(self):
        self.rpc.attest()
        self.server.fail_method = "getblock"
        self.server.code = 401
        with self.assertRaisesRegex(WspScannerRpcError, "^WSP_SCAN_TRANSPORT_DENIED$") as err:
            self.rpc.call("getblock", [TIP, 3])
        self.assertNotIn("wallet-secret", repr(err.exception))
        self.server.requests.clear()
        with self.assertRaisesRegex(WspScannerRpcError, "^WSP_SCAN_ATTEST_REQUIRED$"):
            self.rpc.call("getblock", [TIP, 3])
        self.assertFalse(self.server.requests)

    def test_nonlocal_endpoint_and_invalid_mempool_scope_denied(self):
        for host in ("example.org", "8.8.8.8", "0.0.0.0", "localhost"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                LocalRegtestEndpoint(host, 18443)
        for flag in (1, None, "yes"):
            with self.subTest(flag=flag), self.assertRaisesRegex(
                ValueError, "^WSP_SCAN_MEMPOOL_SCOPE_DENIED$",
            ):
                Wsp1ScannerOnlyRpc(self.endpoint, self.auth, include_mempool=flag)

    def test_no_wam_core_launch_or_upstream_import_on_read_only_path(self):
        with patch.object(subprocess, "Popen",
                          side_effect=AssertionError("NO_WAM_CORE_PROCESS")):
            self.mempool.attest()
            self.assertEqual(self.mempool.call("getrawmempool"), [TX])
        self.assertFalse(any(name.startswith("wam_sp") for name in sys.modules))


if __name__ == "__main__":
    unittest.main()
