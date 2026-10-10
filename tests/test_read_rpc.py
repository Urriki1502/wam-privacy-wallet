"""Synthetic loopback-only RPC tests. Never connect to a real WAM node."""

import base64
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth, LocalReadOnlyRpc, LocalRpcError


class MockRpcHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers['Content-Length']))
        self.server.observed.append((self.path, dict(self.headers), raw))
        reply = self.server.reply
        self.send_response(self.server.code)
        self.send_header('Content-Type', 'application/json')
        if not self.server.omit_content_length:
            self.send_header('Content-Length', str(self.server.content_length if self.server.content_length is not None else len(reply)))
        self.end_headers()
        try:
            self.wfile.write(reply)
        except (BrokenPipeError, ConnectionResetError):
            # Expected when the bounded client stops reading an oversized body.
            pass

    def log_message(self, *_args):
        return  # Never log credentials, even synthetic credentials.


class LocalReadOnlyRpcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), MockRpcHandler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.endpoint = LocalRegtestEndpoint('127.0.0.1', cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=5)

    def setUp(self):
        self.server.code = 200
        self.server.reply = b'{"result":"' + b'a' * 64 + b'","error":null,"id":1}'
        self.server.content_length = None
        self.server.omit_content_length = False
        self.server.observed = []
        self.rpc = LocalReadOnlyRpc(self.endpoint, ExplicitRpcAuth('synthetic', 'test-only'))

    def test_allowed_methods_and_explicit_auth(self):
        result = self.rpc.call('getblockhash', [0])
        self.assertEqual(result, 'a' * 64)
        self.assertEqual(len(self.server.observed), 1)
        path, headers, raw = self.server.observed[0]
        self.assertEqual(path, '/')
        self.assertEqual(json.loads(raw), {'jsonrpc': '1.0', 'id': 1, 'method': 'getblockhash', 'params': [0]})
        self.assertEqual(headers['Authorization'], 'Basic ' + base64.b64encode(b'synthetic:test-only').decode())
        self.assertEqual(self.rpc.call('getblockcount'), 'a' * 64)
        self.assertEqual(self.rpc.call('getbestblockhash', []), 'a' * 64)

    def test_write_methods_rejected_before_socket(self):
        for method in ('sendrawtransaction', 'getwalletinfo', 'stop', 'getblock', 'getrawtransaction', '', None, True):
            with self.subTest(method=method):
                with self.assertRaisesRegex(LocalRpcError, '^WAM_RPC_METHOD_DENIED$'):
                    self.rpc.call(method)
        self.assertFalse(self.server.observed)

    def test_reject_invalid_method_parameters(self):
        for method, params in [('getblockhash', []), ('getblockhash', [True]), ('getblockhash', [-1]), ('getblockhash', [1.5]), ('getblockhash', [100_000_001]), ('getblockhash', [0, 0]), ('getblockcount', [0]), ('getbestblockhash', [0]), ('getblockcount', '[]')]:
            with self.subTest(method=method, params=params):
                with self.assertRaisesRegex(LocalRpcError, '^WAM_RPC_INVALID_PARAMS$'):
                    self.rpc.call(method, params)
        self.assertFalse(self.server.observed)

    def test_reject_nonlocal_endpoint_and_insecure_auth(self):
        with self.assertRaises(ValueError):
            LocalReadOnlyRpc('localhost', ExplicitRpcAuth('user', 'secret'))
        with self.assertRaises(ValueError):
            LocalRegtestEndpoint('192.168.1.1', 8999)
        for u, p in [('', 'p'), ('u\\nInjected', 'p'), ('u:bad', 'p'), ('u', ''), ('u', 'bad\\r')]:
            with self.subTest(u=u):
                with self.assertRaisesRegex(ValueError, 'WAM_RPC_INVALID_AUTH'):
                    ExplicitRpcAuth(u, p)
        self.assertNotIn('test-only', repr(ExplicitRpcAuth('synthetic', 'test-only')))

    def test_redirect_does_not_follow(self):
        self.server.code = 302
        with self.assertRaisesRegex(LocalRpcError, 'WAM_RPC_HTTP_REJECTED'):
            self.rpc.call('getblockcount')
        self.assertEqual(len(self.server.observed), 1)

    def test_http_error_does_not_expose_server_body(self):
        self.server.code = 401
        self.server.reply = b'SECRET IN ERROR'
        with self.assertRaises(LocalRpcError) as cm:
            self.rpc.call('getblockcount')
        self.assertEqual(str(cm.exception), 'WAM_RPC_HTTP_REJECTED')

    def test_size_bounded_by_header_and_actual_length(self):
        self.server.content_length = 1_048_577
        with self.assertRaisesRegex(LocalRpcError, 'WAM_RPC_RESPONSE_LIMIT'):
            self.rpc.call('getblockcount')
        self.server.content_length = None
        self.server.reply = b' ' * 1_048_577
        with self.assertRaisesRegex(LocalRpcError, 'WAM_RPC_RESPONSE_LIMIT'):
            self.rpc.call('getblockcount')

    def test_missing_or_malformed_fields_rejected(self):
        for response in (b'no json', b'{"id":1,"result":0}', b'{"id":true,"result":0,"error":null}', b'{"id":2,"result":0,"error":null}', b'[]'):
            with self.subTest(response=response[:20]):
                self.server.reply = response
                with self.assertRaisesRegex(LocalRpcError, 'WAM_RPC_INVALID_RESPONSE'):
                    self.rpc.call('getblockcount')

    def test_rpc_error_returns_only_stable_code(self):
        self.server.reply = b'{"result":null,"error":{"message":"sensitive info"},"id":1}'
        with self.assertRaisesRegex(LocalRpcError, '^WAM_RPC_REMOTE_ERROR$'):
            self.rpc.call('getblockcount')

    def test_reject_bad_timeout_values(self):
        for timeout in (True, None, '2', 0, -1, 11, float('inf'), float('nan')):
            with self.subTest(timeout=timeout):
                with self.assertRaisesRegex(ValueError, 'WAM_RPC_TIMEOUT_INVALID'):
                    LocalReadOnlyRpc(self.endpoint, ExplicitRpcAuth('u', 'p'), timeout=timeout)


if __name__ == '__main__':
    unittest.main()
