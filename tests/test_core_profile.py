"""WAM regtest profile gates, synthetic RPC only; no WAM Core binary."""

import unittest
from unittest.mock import patch

from wam_privacy_wallet.node.attestation import ChainIdentity, WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.core_profile import CoreProfileError, validate_core_profile
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth, LocalReadOnlyRpc, LocalRpcError
from wam_privacy_wallet.node.regtest_gateway import LocalRegtestIdentityGateway

TIP = "a" * 64


class CoreProfileGateTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = LocalRegtestEndpoint("127.0.0.1", 29554)
        self.identity = ChainIdentity(self.endpoint, WAM_REGTEST_GENESIS, 12, TIP)
        self.payload = {
            "chain": "regtest", "blocks": 12, "headers": 12,
            "bestblockhash": TIP, "pruned": False,
        }

    def test_valid_unpruned_regtest_matches_identity(self):
        result = validate_core_profile(self.payload.copy(), self.identity)
        self.assertEqual(result.identity, self.identity)
        self.assertEqual(result.headers, 12)
        self.assertFalse(result.pruned)

    def test_nonregtest_networks_blocked(self):
        for chain in ("main", "test", "signet", "REGTEST", "", None, True):
            with self.subTest(chain=chain):
                with self.assertRaisesRegex(CoreProfileError, "^WAM_CORE_WRONG_CHAIN$"):
                    validate_core_profile({**self.payload, "chain": chain}, self.identity)

    def test_pruned_or_missing_pruned_field_blocked(self):
        for value in (True, None, 0, "false"):
            with self.subTest(pruned=value):
                with self.assertRaisesRegex(CoreProfileError, "^WAM_CORE_PRUNED_OR_UNKNOWN$"):
                    validate_core_profile({**self.payload, "pruned": value}, self.identity)
        copy = self.payload.copy()
        del copy["pruned"]
        with self.assertRaisesRegex(CoreProfileError, "^WAM_CORE_PRUNED_OR_UNKNOWN$"):
            validate_core_profile(copy, self.identity)

    def test_height_and_headers_consistency(self):
        invalid = (
            {"blocks": True}, {"blocks": 11}, {"blocks": "12"},
            {"headers": True}, {"headers": 11}, {"headers": "12"},
            {"headers": 100_000_001},
        )
        for change in invalid:
            with self.subTest(change=change):
                with self.assertRaisesRegex(CoreProfileError, "^WAM_CORE_HEIGHT_MISMATCH$"):
                    validate_core_profile({**self.payload, **change}, self.identity)

    def test_bestblockhash_must_match_checked_tip(self):
        for tip in ("b" * 64, "A" * 64, None, 12, True):
            with self.subTest(tip=tip):
                with self.assertRaisesRegex(CoreProfileError, "^WAM_CORE_TIP_MISMATCH$"):
                    validate_core_profile({**self.payload, "bestblockhash": tip}, self.identity)

    def test_missing_or_wrong_structures(self):
        for item in ([], None, "string", True):
            with self.subTest(item=item):
                with self.assertRaisesRegex(CoreProfileError, "^WAM_CORE_PROFILE_INVALID$"):
                    validate_core_profile(item, self.identity)
        with self.assertRaisesRegex(CoreProfileError, "^WAM_CORE_IDENTITY_REQUIRED$"):
            validate_core_profile(self.payload, "not-an-identity")

    def test_gateway_checks_genesis_before_core_profile(self):
        calls = []
        replies = [WAM_REGTEST_GENESIS, 12, TIP, TIP, TIP, 12, self.payload]
        def fake_call(_self, method, params=None):
            calls.append((method, params))
            return replies.pop(0)
        gateway = LocalRegtestIdentityGateway(self.endpoint, ExplicitRpcAuth("x", "y"))
        with patch.object(LocalReadOnlyRpc, "call", fake_call):
            result = gateway.probe_core_profile()
        self.assertEqual(result.identity.genesis, WAM_REGTEST_GENESIS)
        self.assertEqual([name for name, _ in calls], [
            "getblockhash", "getblockcount", "getbestblockhash", "getblockhash",
            "getbestblockhash", "getblockcount", "getblockchaininfo",
        ])
        self.assertEqual(calls[-1], ("getblockchaininfo", []))

    def test_gateway_rejects_wrong_genesis_without_profile_rpc(self):
        calls = []
        def wrong_genesis(_self, method, params=None):
            calls.append(method)
            return "b" * 64
        gateway = LocalRegtestIdentityGateway(self.endpoint, ExplicitRpcAuth("x", "y"))
        with patch.object(LocalReadOnlyRpc, "call", wrong_genesis):
            with self.assertRaisesRegex(RuntimeError, "WAM_NODE_WRONG_GENESIS"):
                gateway.probe_core_profile()
        self.assertEqual(calls, ["getblockhash"])

    def test_gateway_redacts_rpc_failure(self):
        calls = []
        replies = [WAM_REGTEST_GENESIS, 12, TIP, TIP, TIP, 12]
        def last_rpc_fails(_self, method, params=None):
            calls.append(method)
            if method == "getblockchaininfo":
                raise LocalRpcError("secret=synthetic")
            return replies.pop(0)
        gateway = LocalRegtestIdentityGateway(self.endpoint, ExplicitRpcAuth("x", "y"))
        with patch.object(LocalReadOnlyRpc, "call", last_rpc_fails):
            with self.assertRaises(CoreProfileError) as error:
                gateway.probe_core_profile()
        self.assertEqual(str(error.exception), "WAM_CORE_PROFILE_RPC_ERROR")
        self.assertEqual(calls[-1], "getblockchaininfo")


if __name__ == "__main__":
    unittest.main()
