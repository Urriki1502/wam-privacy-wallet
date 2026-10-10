"""Safe synthetic RPC contract tests: no network or wallet access."""

import unittest

from wam_privacy_wallet.node.attestation import (
    WAM_REGTEST_GENESIS,
    RegtestIdentityError,
    RegtestIdentityProbe,
)
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint

TIP = "a" * 64


class SyntheticRegtestRpc:
    def __init__(self, *, genesis=WAM_REGTEST_GENESIS, height=42, tip=TIP):
        self.genesis = genesis
        self.height = height
        self.tip = tip
        self.methods = []
        self.responses = {}

    def __call__(self, method, params):
        self.methods.append((method, params[:]))
        if method == "getblockhash":
            return self.genesis if params == [0] else self.responses.get("at_tip", self.tip)
        if method == "getblockcount":
            return self.responses.get("height_after", self.height) if self.methods.count(("getblockcount", [])) == 2 else self.height
        if method == "getbestblockhash":
            return self.responses.get("tip_after", self.tip) if self.methods.count(("getbestblockhash", [])) == 2 else self.tip
        raise AssertionError("unexpected RPC method: " + method)


class RegtestAttestationTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = LocalRegtestEndpoint("127.0.0.1", 32190)

    def probe(self, rpc):
        return RegtestIdentityProbe(self.endpoint, rpc).probe()

    def test_valid_identity_uses_only_read_only_queries(self):
        rpc = SyntheticRegtestRpc()
        result = self.probe(rpc)
        self.assertEqual((result.height, result.best_block_hash), (42, TIP))
        self.assertEqual(result.genesis, WAM_REGTEST_GENESIS)
        self.assertEqual(result.endpoint, self.endpoint)
        self.assertEqual(rpc.methods, [
            ("getblockhash", [0]),
            ("getblockcount", []),
            ("getbestblockhash", []),
            ("getblockhash", [42]),
            ("getbestblockhash", []),
            ("getblockcount", []),
        ])

    def test_height_zero_regtest(self):
        rpc = SyntheticRegtestRpc(height=0, tip=WAM_REGTEST_GENESIS)
        self.assertEqual(self.probe(rpc).height, 0)

    def test_wrong_genesis_and_bad_format_fail_closed(self):
        for genesis in ("1" * 64, "B" * 64, True, None, "0" * 65):
            with self.subTest(genesis=genesis):
                with self.assertRaisesRegex(RegtestIdentityError, "^WAM_NODE_WRONG_GENESIS$"):
                    self.probe(SyntheticRegtestRpc(genesis=genesis))

    def test_reject_invalid_heights(self):
        for height in (-1, True, 1.0, None, "2", 100_000_001):
            with self.subTest(height=height):
                with self.assertRaisesRegex(RegtestIdentityError, "^WAM_NODE_INVALID_HEIGHT$"):
                    self.probe(SyntheticRegtestRpc(height=height))

    def test_reject_invalid_tip_values(self):
        for tip in (None, 3, "f" * 63, "F" * 64, "g" * 64):
            with self.subTest(tip=tip):
                with self.assertRaisesRegex(RegtestIdentityError, "^WAM_NODE_INVALID_TIP$"):
                    self.probe(SyntheticRegtestRpc(tip=tip))

    def test_detect_inconsistent_height_hash(self):
        rpc = SyntheticRegtestRpc()
        rpc.responses["at_tip"] = "b" * 64
        with self.assertRaisesRegex(RegtestIdentityError, "^WAM_NODE_INCONSISTENT_TIP$"):
            self.probe(rpc)

    def test_detect_tip_reorg(self):
        rpc = SyntheticRegtestRpc()
        rpc.responses["tip_after"] = "c" * 64
        with self.assertRaisesRegex(RegtestIdentityError, "^WAM_NODE_TIP_CHANGED$"):
            self.probe(rpc)

    def test_detect_height_change_without_tip_change(self):
        rpc = SyntheticRegtestRpc()
        rpc.responses["height_after"] = 43
        with self.assertRaisesRegex(RegtestIdentityError, "^WAM_NODE_TIP_CHANGED$"):
            self.probe(rpc)

    def test_callback_exception_redacts_sensitive_message(self):
        def throw(_method, _params):
            raise RuntimeError("TOKEN=top-secret")
        with self.assertRaises(RegtestIdentityError) as cm:
            self.probe(throw)
        self.assertEqual(str(cm.exception), "WAM_NODE_PROBE_TRANSPORT_ERROR")
        self.assertIsNone(cm.exception.__cause__)

    def test_constructor_blocks_nonlocal_and_invalid_calls(self):
        for endpoint in (None, "127.0.0.1", object()):
            with self.subTest(endpoint=endpoint):
                with self.assertRaisesRegex(ValueError, "^WAM_NODE_LOCAL_ENDPOINT_REQUIRED$"):
                    RegtestIdentityProbe(endpoint, SyntheticRegtestRpc())
        with self.assertRaisesRegex(ValueError, "^WAM_NODE_CALL_REQUIRED$"):
            RegtestIdentityProbe(self.endpoint, None)
        with self.assertRaisesRegex(ValueError, "WAM_RPC_NONLOCAL_HOST"):
            LocalRegtestEndpoint("8.8.8.8", 32190)


if __name__ == "__main__":
    unittest.main()
