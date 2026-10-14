"""Non-authorizing contract tests. Real Core requires separate operator run."""
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from wam_privacy_wallet.node import two_node_core_readiness as subject
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS


class TwoNodeCoreReadinessTests(unittest.TestCase):
    def setUp(self):
        self.a = LocalRegtestEndpoint("127.0.0.1", 29554)
        self.b = LocalRegtestEndpoint("127.0.0.1", 29556)
        self.args = dict(
            a=self.a, aa=ExplicitRpcAuth("testa", "PUBLIC_A_PASSWORD"),
            b=self.b, bb=ExplicitRpcAuth("testb", "PUBLIC_B_PASSWORD"),
            p2p_a=29555, p2p_b=29557,
            consent=True, acknowledge_unverified_processes=True,
        )

    def test_scope_denials_do_not_create_network_clients(self):
        variants = ({"consent": False}, {"acknowledge_unverified_processes": 1},
                    {"p2p_b": 29555}, {"p2p_a": True}, {"b": self.a},
                    {"bb": self.args["aa"]})
        with patch.object(subject, "LocalRegtestIdentityGateway") as gateway, \
             patch.object(subject, "TwoNodeP2PReadOnlyAudit") as topology, \
             patch.object(subject, "CoreRegtestReadinessRpc") as index:
            for values in variants:
                with self.subTest(values=values):
                    with self.assertRaisesRegex(subject.TwoNodeCoreReadinessError,
                                                "^TWO_CORE_READINESS_SCOPE_DENIED$"):
                        subject.inspect_existing_core_readiness(**dict(self.args, **values))
            gateway.assert_not_called()
            topology.assert_not_called()
            index.assert_not_called()

    def test_readiness_is_bracketed_and_no_authority_is_granted(self):
        a = SimpleNamespace(identity=SimpleNamespace(
            genesis=WAM_REGTEST_GENESIS, height=42, best_block_hash="a" * 64,
        ))
        b = SimpleNamespace(identity=SimpleNamespace(
            genesis=WAM_REGTEST_GENESIS, height=42, best_block_hash="a" * 64,
        ))
        audit = {
            "status": "UNTRUSTED_LOCAL_REGTEST_P2P_TOPOLOGY_ONLY",
            "localhost_only_observed": True,
            "expected_direction_observed": True,
            "reported_chain_agrees": True,
            "genuine_wam_process_verified": False,
            "independent_processes_verified": False,
            "external_network_exclusion_proven": False,
            "real_two_node_regtest_qualified": False,
            "scanner_enabled": False,
            "wallet_ready": False,
            "signing_allowed": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
        }
        with patch.object(subject, "LocalRegtestIdentityGateway") as gateway, \
             patch.object(subject, "TwoNodeP2PReadOnlyAudit") as topology, \
             patch.object(subject, "CoreRegtestReadinessRpc") as index:
            gateway.side_effect = lambda endpoint, *_args, **_kwargs: (
                SimpleNamespace(probe_core_profile=lambda: a if endpoint == self.a else b)
            )
            topology.return_value.audit.return_value = audit
            index.return_value.observe.return_value = SimpleNamespace(
                height=42, block_hash="a" * 64, filter_header="b" * 64,
            )
            receipt = subject.inspect_existing_core_readiness(**self.args)
            self.assertEqual(receipt["height"], 42)
            self.assertTrue(receipt["two_node_loopback_p2p_observed"])
            self.assertTrue(receipt["synchronized_index_and_basic_filter_reports"])
            for key in ("core_executable_authenticated", "independent_processes_verified",
                        "real_core_e2e_accepted", "wsp_scanning_enabled",
                        "wallet_operational", "signing_allowed", "broadcast_allowed",
                        "mainnet_allowed"):
                self.assertIs(receipt[key], False)
            self.assertEqual(topology.return_value.audit.call_count, 2)
            self.assertEqual(index.return_value.observe.call_count, 2)

    def test_moving_or_mismatched_tip_denied_without_success(self):
        a = SimpleNamespace(identity=SimpleNamespace(
            genesis=WAM_REGTEST_GENESIS, height=3, best_block_hash="a" * 64))
        b = SimpleNamespace(identity=SimpleNamespace(
            genesis=WAM_REGTEST_GENESIS, height=4, best_block_hash="b" * 64))
        with patch.object(subject, "LocalRegtestIdentityGateway") as gateway, \
             patch.object(subject, "TwoNodeP2PReadOnlyAudit") as topology, \
             patch.object(subject, "CoreRegtestReadinessRpc") as index:
            gateway.side_effect = lambda endpoint, *_args, **_kwargs: (
                SimpleNamespace(probe_core_profile=lambda: a if endpoint == self.a else b))
            topology.return_value.audit.return_value = {
                "status": "UNTRUSTED_LOCAL_REGTEST_P2P_TOPOLOGY_ONLY",
                **{k: True for k in ("localhost_only_observed",
                                     "expected_direction_observed","reported_chain_agrees")},
                **{k: False for k in ("genuine_wam_process_verified",
                                      "independent_processes_verified",
                                      "external_network_exclusion_proven",
                                      "real_two_node_regtest_qualified",
                                      "scanner_enabled", "wallet_ready", "signing_allowed",
                                      "broadcast_allowed", "mainnet_allowed")},
            }
            index.return_value.observe.return_value = SimpleNamespace(
                height=3, block_hash="a" * 64, filter_header="c" * 64)
            with self.assertRaisesRegex(subject.TwoNodeCoreReadinessError,
                                        "^TWO_CORE_READINESS_DRIFT_DENIED$"):
                subject.inspect_existing_core_readiness(**self.args)


if __name__ == "__main__":
    unittest.main()
