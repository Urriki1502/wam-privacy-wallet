"""Disposable loopback JSON-RPC peer, never Core. No wallet or private keys."""
import hashlib
import json
import subprocess
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.core_readiness_rpc import CoreRegtestReadinessRpc, CoreReadinessError
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth

TIP, OTHER = 'a' * 64, 'b' * 64
INDEXES = ('txindex', 'basic block filter index', 'coinstatsindex')


def header_for_empty(parent):
    h = lambda raw: hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    return h(h(b'\x00') + bytes.fromhex(parent)[::-1])[::-1].hex()


class Peer(BaseHTTPRequestHandler):
    def do_POST(self):
        state = self.server
        req = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        method, params = req['method'], req['params']
        state.requests.append((self.path, dict(self.headers), method, params))
        if method == 'getblockhash':
            result = state.genesis if params == [0] else state.tip
        elif method == 'getblockcount':
            result = state.height
        elif method == 'getbestblockhash':
            result = state.tip
        elif method == 'getblockchaininfo':
            result = {'chain': state.chain, 'blocks': state.height,
                      'headers': state.headers, 'bestblockhash': state.tip, 'pruned': False}
        elif method == 'getindexinfo':
            state.index_reads += 1
            result = state.indexes
            if state.stale_second and state.index_reads == 2:
                result = {n: {'synced': True, 'best_block_height': 0} for n in INDEXES}
        elif method == 'getblockfilter':
            previous = header_for_empty('0' * 64)
            result = {'filter': '00', 'header': previous if params[0] == state.genesis
                      else header_for_empty(previous)}
            if state.height == 0:
                result['header'] = previous
        elif method == 'scanblocks':
            result = {'from_height': params[2], 'to_height': params[3],
                      'relevant_blocks': [state.tip], 'completed': True}
        elif method == 'getblockheader':
            result = {'hash': params[0], 'height': state.height}
        else:
            self.send_error(403)
            return
        result = state.overrides.get(method, result)
        if method == state.change_on:
            state.tip = OTHER
        payload = json.dumps({'id': 1, 'error': None, 'result': result}).encode()
        if method == state.fail_on:
            payload = state.failure
        if method == state.delay_on:
            time.sleep(0.1)
        self.send_response(401 if method == state.auth_fail else 200)
        self.send_header('Content-Length', str(state.size if method == state.fail_on
                                              and state.size is not None else len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_):
        pass


class CoreReadinessRpcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Peer)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.endpoint = LocalRegtestEndpoint('127.0.0.1', cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        s = self.server
        s.requests, s.overrides = [], {}
        s.genesis, s.tip, s.height, s.headers, s.chain = WAM_REGTEST_GENESIS, TIP, 1, 1, 'regtest'
        s.indexes = {n: {'synced': True, 'best_block_height': 1} for n in INDEXES}
        s.index_reads, s.stale_second = 0, False
        s.change_on, s.fail_on, s.auth_fail, s.size = None, None, None, None
        s.delay_on = None
        s.failure = b'untrusted-private-reply'
        self.rpc = CoreRegtestReadinessRpc(self.endpoint, ExplicitRpcAuth('fixture', 'test-only'))

    def scan(self, **changed):
        args = dict(scripts=('51',), start=1, stop=1, user_consented=True)
        args.update(changed)
        return self.rpc.scan_public_scripts(**args)

    def test_reported_index_filter_consistency_no_authority(self):
        receipt = self.rpc.observe().receipt()
        self.assertEqual(receipt['height'], 1)
        self.assertEqual(receipt['indexes'], list(INDEXES))
        for key in ('core_binary_authenticated', 'real_regtest_accepted',
                    'filter_can_skip_wsp_blocks', 'signing_allowed', 'broadcast_allowed',
                    'mainnet_allowed'):
            self.assertIs(receipt[key], False)

    def test_genesis_filter_header_uses_zero_parent(self):
        s = self.server
        s.height = s.headers = 0
        s.tip = s.genesis
        s.indexes = {n: {'synced': True, 'best_block_height': 0} for n in INDEXES}
        self.assertEqual(self.rpc.observe().height, 0)

    def test_missing_stale_or_unsynchronized_index_refused(self):
        for name in INDEXES:
            for item in (None, {'synced': False, 'best_block_height': 1},
                         {'synced': True, 'best_block_height': 0},
                         {'synced': 1, 'best_block_height': 1},
                         {'synced': True, 'best_block_height': True}):
                self.server.indexes[name] = item
                with self.assertRaisesRegex(CoreReadinessError, '^CORE_READINESS_INDEX_DENIED$'):
                    self.rpc.observe()
            self.server.indexes[name] = {'synced': True, 'best_block_height': 1}

    def test_indexes_rechecked_after_observation(self):
        self.server.stale_second = True
        with self.assertRaisesRegex(CoreReadinessError, '^CORE_READINESS_INDEX_DENIED$'):
            self.rpc.observe()

    def test_wrong_network_or_genesis_refused_before_index_rpc(self):
        for name, value in (('chain', 'main'), ('genesis', OTHER)):
            old = getattr(self.server, name)
            setattr(self.server, name, value)
            with self.assertRaises(CoreReadinessError):
                self.rpc.observe()
            self.assertFalse(any(r[2] == 'getindexinfo' for r in self.server.requests))
            setattr(self.server, name, old)

    def test_unsynced_headers_refused_before_index_rpc(self):
        self.server.headers = 2
        with self.assertRaisesRegex(CoreReadinessError, '^CORE_READINESS_HEADERS_PENDING$'):
            self.rpc.observe()

    def test_malformed_filter_and_wrong_header_refused(self):
        for result in (None, {}, {'filter': '0000', 'header': '0' * 64},
                       {'filter': '00', 'header': '0' * 64},
                       {'filter': '00', 'header': 'A' * 64}):
            self.server.overrides['getblockfilter'] = result
            with self.assertRaisesRegex(CoreReadinessError, '^CORE_READINESS_FILTER_DENIED$'):
                self.rpc.observe()

    def test_reorg_during_filter_read_denied(self):
        self.server.change_on = 'getblockfilter'
        with self.assertRaises(CoreReadinessError):
            self.rpc.observe()

    def test_auth_failure_redacted_and_not_retried(self):
        self.server.auth_fail = 'getindexinfo'
        with self.assertRaisesRegex(CoreReadinessError, '^CORE_READINESS_RPC_DENIED$') as err:
            self.rpc.observe()
        self.assertNotIn('private', repr(err.exception))
        self.assertEqual(sum(r[2] == 'getindexinfo' for r in self.server.requests), 1)

    def test_duplicate_or_nonfinite_json_refused(self):
        for raw in (b'{"id":1,"error":null,"result":{},"result":{}}',
                    b'{"id":1,"error":null,"result":NaN}'):
            self.server.fail_on = 'getindexinfo'
            self.server.failure = raw
            with self.assertRaisesRegex(CoreReadinessError, '^CORE_READINESS_RPC_DENIED$'):
                self.rpc.observe()

    def test_response_limit_is_fail_closed(self):
        self.server.fail_on, self.server.size = 'getblockfilter', 2_200_001
        with self.assertRaisesRegex(CoreReadinessError, '^CORE_READINESS_RPC_DENIED$'):
            self.rpc.observe()

    def test_timeout_is_bounded_and_never_retries_scan_or_index(self):
        self.server.delay_on = 'getindexinfo'
        rpc = CoreRegtestReadinessRpc(self.endpoint, ExplicitRpcAuth('fixture', 'test-only'),
                                     timeout=0.02)
        with self.assertRaisesRegex(CoreReadinessError, '^CORE_READINESS_RPC_DENIED$'):
            rpc.observe()
        self.assertEqual(sum(r[2] == 'getindexinfo' for r in self.server.requests), 1)

    def test_live_application_index_denial_precedes_source_or_store_access(self):
        from pathlib import Path
        from wam_privacy_wallet.application import live_regtest_scanner as app
        self.server.indexes = {}
        with patch.object(app, 'SourceQualifiedScanRuntime') as runtime:
            with self.assertRaisesRegex(app.LiveRegtestScanError, '^LIVE_SCAN_DENIED$'):
                app.scan_existing_regtest(Path.cwd(), Path.cwd(), b'test-only-passphrase',
                    endpoint=self.endpoint, rpc_auth=ExplicitRpcAuth('fixture', 'test-only'),
                    user_consented=True, acknowledge_unverified_binary=True,
                    require_synchronized_indexes=True)
            runtime.assert_not_called()

    def test_explicit_public_raw_script_scanblocks_and_chain_check(self):
        self.assertEqual(self.scan(), (TIP,))
        requests = [r for r in self.server.requests if r[2] == 'scanblocks']
        self.assertEqual(requests[0][3], ['start', ['raw(51)'], 1, 1, 'basic'])
        self.assertTrue(any(r[2] == 'getblockheader' for r in self.server.requests))

    def test_scan_requires_consent_and_typed_bounded_scope_before_network(self):
        for args in ({'user_consented': False}, {'user_consented': 1},
                     {'scripts': []}, {'scripts': ()}, {'scripts': ('51', '51')},
                     {'scripts': ('addr(bcrt1private)',)}, {'scripts': ('xprvsecret',)},
                     {'scripts': ('AA',)}, {'scripts': ('00' * 521,)},
                     {'start': True}, {'stop': 65}, {'start': -1}, {'start': 2, 'stop': 1}):
            with self.assertRaisesRegex(CoreReadinessError, '^CORE_READINESS_SCAN_SCOPE_DENIED$'):
                self.scan(**args)
        self.assertEqual(self.server.requests, [])

    def test_scan_height_ahead_refused_before_scanblocks(self):
        with self.assertRaises(CoreReadinessError):
            self.scan(stop=2)
        self.assertFalse(any(r[2] == 'scanblocks' for r in self.server.requests))

    def test_aborted_wrong_range_or_duplicate_matches_refused(self):
        base = {'from_height': 1, 'to_height': 1, 'relevant_blocks': [TIP], 'completed': True}
        for changes in ({'completed': False}, {'completed': 1}, {'from_height': True},
                        {'to_height': 2}, {'relevant_blocks': [TIP, TIP]},
                        {'relevant_blocks': ['bad']}):
            self.server.overrides['scanblocks'] = dict(base, **changes)
            with self.assertRaisesRegex(CoreReadinessError, '^CORE_READINESS_SCAN_REPLY_DENIED$'):
                self.scan()

    def test_forked_matching_block_refused(self):
        self.server.overrides['getblockheader'] = {'hash': TIP, 'height': 0}
        with self.assertRaises(CoreReadinessError):
            self.scan()

    def test_scanblocks_drift_or_stale_index_refuses_result(self):
        self.server.change_on = 'scanblocks'
        with self.assertRaises(CoreReadinessError):
            self.scan()
        self.server.change_on, self.server.tip = None, TIP
        self.server.index_reads, self.server.stale_second = 0, True
        with self.assertRaisesRegex(CoreReadinessError, '^CORE_READINESS_INDEX_DENIED$'):
            self.scan()

    def test_empty_match_set_is_diagnostic_not_scanner_exclusion(self):
        self.server.overrides['scanblocks'] = {'from_height': 1, 'to_height': 1,
                                              'relevant_blocks': [], 'completed': True}
        self.assertEqual(self.scan(), ())
        self.assertIs(self.rpc.observe().receipt()['filter_can_skip_wsp_blocks'], False)

    def test_transport_has_explicit_auth_and_no_launch_write_or_broad_call(self):
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('NO_CORE')):
            self.rpc.observe()
        self.assertFalse(hasattr(self.rpc, 'call'))
        for path, headers, method, _ in self.server.requests:
            self.assertEqual(path, '/')
            self.assertIn('Authorization', headers)
            self.assertIn(method, ('getblockhash', 'getblockcount', 'getbestblockhash',
                                  'getblockchaininfo', 'getindexinfo', 'getblockfilter'))


if __name__ == '__main__':
    unittest.main()
