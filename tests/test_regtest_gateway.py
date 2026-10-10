"""Integrated loopback RPC + chain-identity tests, using a synthetic WAM node.

The server has no access to private keys, funds, external networks or WAM Core.
Windows x86 is tested using an actual 32-bit CPython interpreter.
"""

from __future__ import annotations

import base64
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS, RegtestIdentityError
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
from wam_privacy_wallet.node.regtest_gateway import LocalRegtestIdentityGateway

TIP = "a" * 64
NEW_TIP = "b" * 64
EXPECTED_AUTH = "Basic " + base64.b64encode(b"mock-user:mock-pass").decode("ascii")
EXPECTED_METHODS = (
    ("getblockhash", (0,)),
    ("getblockcount", ()),
    ("getbestblockhash", ()),
    ("getblockhash", (19,)),
    ("getbestblockhash", ()),
    ("getblockcount", ()),
)


class _FakeWamNodeHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/" or self.headers.get("Authorization") != EXPECTED_AUTH:
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        try:
            amount = int(self.headers.get("Content-Length", "-1"))
            if not 0 <= amount <= 4096:
                raise ValueError("size")
            request = json.loads(self.rfile.read(amount))
            if type(request) is not dict:
                raise ValueError("shape")
            method = request.get("method")
            params = request.get("params")
            if type(method) is not str or type(params) is not list:
                raise ValueError("request")
        except (ValueError, UnicodeDecodeError):
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        node = self.server
        with node.lock:
            node.calls.append((method, tuple(params)))
            count = sum(1 for name, _ in node.calls if name == method)
            state = node.state.copy()

        if state.get("raw_response") is not None:
            body = state["raw_response"]
        else:
            if method == "getblockhash" and params == [0]:
                result = state["genesis"]
            elif method == "getblockhash" and params == [state["height"]]:
                result = state.get("hash_at_height", state["tip"])
            elif method == "getblockcount" and params == []:
                result = state.get("height_after", state["height"]) if count == 2 else state["height"]
            elif method == "getbestblockhash" and params == []:
                result = state.get("tip_after", state["tip"]) if count == 2 else state["tip"]
            else:
                # No unsupported method should ever be reached through the
                # gateway's read-only allowlist.
                result = None
            body = json.dumps(
                {"result": result, "error": None, "id": request["id"]},
                separators=(",", ":"),
            ).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        # Avoid logging HTTP headers or credentials.
        return


class LocalRegtestGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.node = ThreadingHTTPServer(("127.0.0.1", 0), _FakeWamNodeHandler)
        cls.node.lock = threading.Lock()
        cls.worker = threading.Thread(target=cls.node.serve_forever, daemon=True)
        cls.worker.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.node.shutdown()
        cls.node.server_close()
        cls.worker.join(timeout=5)

    def setUp(self) -> None:
        self.node.calls = []
        self.node.state = {"genesis": WAM_REGTEST_GENESIS, "height": 19, "tip": TIP}
        self.endpoint = LocalRegtestEndpoint("127.0.0.1", self.node.server_port)
        self.auth = ExplicitRpcAuth("mock-user", "mock-pass")

    def gateway(self, auth=None) -> LocalRegtestIdentityGateway:
        return LocalRegtestIdentityGateway(
            self.endpoint, self.auth if auth is None else auth, timeout=2.0
        )

    def test_integrated_happy_path_only_six_read_only_calls(self) -> None:
        identity = self.gateway().probe_identity()
        self.assertEqual(identity.endpoint, self.endpoint)
        self.assertEqual(identity.genesis, WAM_REGTEST_GENESIS)
        self.assertEqual(identity.height, 19)
        self.assertEqual(identity.best_block_hash, TIP)
        self.assertEqual(tuple(self.node.calls), EXPECTED_METHODS)
        self.assertTrue(all(name in {
            "getblockhash", "getblockcount", "getbestblockhash"
        } for name, _ in self.node.calls))

    def test_wrong_genesis_fails_before_tip_queries(self) -> None:
        self.node.state["genesis"] = "f" * 64
        with self.assertRaisesRegex(RegtestIdentityError, "^WAM_NODE_WRONG_GENESIS$"):
            self.gateway().probe_identity()
        self.assertEqual(self.node.calls, [("getblockhash", (0,))])

    def test_mid_probe_tip_reorg_is_not_approved(self) -> None:
        self.node.state["tip_after"] = NEW_TIP
        with self.assertRaisesRegex(RegtestIdentityError, "^WAM_NODE_TIP_CHANGED$"):
            self.gateway().probe_identity()

    def test_mid_probe_height_change_is_not_approved(self) -> None:
        self.node.state["height_after"] = 20
        with self.assertRaisesRegex(RegtestIdentityError, "^WAM_NODE_TIP_CHANGED$"):
            self.gateway().probe_identity()

    def test_tip_does_not_match_hash_at_height(self) -> None:
        self.node.state["hash_at_height"] = NEW_TIP
        with self.assertRaisesRegex(RegtestIdentityError, "^WAM_NODE_INCONSISTENT_TIP$"):
            self.gateway().probe_identity()

    def test_authentication_failure_is_redacted(self) -> None:
        wrong = ExplicitRpcAuth("mock-user", "not-the-password")
        with self.assertRaises(RegtestIdentityError) as caught:
            self.gateway(wrong).probe_identity()
        self.assertEqual(str(caught.exception), "WAM_NODE_PROBE_TRANSPORT_ERROR")
        self.assertNotIn("not-the-password", repr(caught.exception))
        self.assertEqual(self.node.calls, [])

    def test_malformed_rpc_response_fails_closed(self) -> None:
        self.node.state["raw_response"] = b'{"id":true,"result":0,"error":null}'
        with self.assertRaisesRegex(RegtestIdentityError, "^WAM_NODE_PROBE_TRANSPORT_ERROR$"):
            self.gateway().probe_identity()

    def test_unavailable_rpc_fails_closed(self) -> None:
        # A reserved-port assumption is unsafe; binding a temporary socket
        # and closing it is still subject to races. Instead inject an HTTP
        # status failure in the synthetic server's credential path.
        with self.assertRaisesRegex(RegtestIdentityError, "^WAM_NODE_PROBE_TRANSPORT_ERROR$"):
            self.gateway(ExplicitRpcAuth("bad-user", "mock-pass")).probe_identity()

    def test_every_probe_is_fresh_and_never_grants_persistent_approval(self) -> None:
        gate = self.gateway()
        first = gate.probe_identity()
        self.node.calls.clear()
        self.node.state["tip"] = NEW_TIP
        second = gate.probe_identity()
        self.assertEqual(first.best_block_hash, TIP)
        self.assertEqual(second.best_block_hash, NEW_TIP)
        self.assertEqual(tuple(self.node.calls), EXPECTED_METHODS)
        self.assertFalse(hasattr(gate, "is_approved"))
        self.assertFalse(hasattr(gate, "scanner"))

    def test_rejects_nonlocal_endpoint_and_nonexplicit_auth_before_io(self) -> None:
        with self.assertRaisesRegex(ValueError, "WAM_RPC_NONLOCAL_HOST"):
            LocalRegtestEndpoint("10.1.2.3", self.node.server_port)
        with self.assertRaisesRegex(ValueError, "^WAM_RPC_LOCAL_ENDPOINT_REQUIRED$"):
            LocalRegtestIdentityGateway("127.0.0.1", self.auth)
        with self.assertRaisesRegex(ValueError, "^WAM_RPC_AUTH_REQUIRED$"):
            LocalRegtestIdentityGateway(self.endpoint, ("mock-user", "mock-pass"))
        self.assertEqual(self.node.calls, [])


if __name__ == "__main__":
    unittest.main()
