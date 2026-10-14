"""Fail-closed unit tests for real-only REGTEST Qt two-node diagnostics."""
import unittest
from threading import Event
from unittest.mock import patch

from wam_privacy_wallet.node import gui_two_node_readonly as subject
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth


class RealNodeGuiTests(unittest.TestCase):
    def setUp(self):
        self.kwargs = {
            "a": LocalRegtestEndpoint("127.0.0.1", 29554),
            "aa": ExplicitRpcAuth("a", "disposable_a"),
            "b": LocalRegtestEndpoint("127.0.0.1", 29556),
            "bb": ExplicitRpcAuth("b", "disposable_b"),
            "p2p_a": 29555, "p2p_b": 29557,
            "user_consented": True,
            "acknowledged_unverified_core": True,
            "cancelled": Event(),
        }

    def test_bad_scope_and_cancel_never_touch_network(self):
        with patch.object(subject, "LocalRegtestIdentityGateway") as gw:
            variants = (
                {"user_consented": False},
                {"acknowledged_unverified_core": False},
                {"b": self.kwargs["a"]},
                {"bb": self.kwargs["aa"]},
                {"p2p_b": 29555},
            )
            for variant in variants:
                inputs = dict(self.kwargs, **variant)
                with self.assertRaisesRegex(subject.LiveNodeGuiProbeError,
                                            "^LIVE_NODE_GUI_SCOPE_DENIED$"):
                    subject.inspect_existing_two_nodes(**inputs)
            stop = Event()
            stop.set()
            with self.assertRaisesRegex(subject.LiveNodeGuiProbeError,
                                        "^LIVE_NODE_GUI_CANCELLED$"):
                subject.inspect_existing_two_nodes(**dict(self.kwargs, cancelled=stop))
            gw.assert_not_called()

    def test_index_observation_uses_both_nodes_without_granting_authority(self):
        observed = {
            "status": "OBSERVED_LIVE_TWO_NODE_REGTEST_RPC_AND_INDEXES_UNTRUSTED",
            "height": 11,
            "synchronized_index_and_basic_filter_reports": True,
            "two_node_loopback_p2p_observed": True,
            **{k: False for k in (
                "core_executable_authenticated", "independent_processes_verified",
                "real_core_e2e_accepted", "wsp_scanning_enabled",
                "wallet_operational", "signing_allowed", "broadcast_allowed",
                "mainnet_allowed")},
        }
        with patch.object(subject, "inspect_existing_core_readiness",
                          return_value=observed) as read:
            evidence = subject.inspect_existing_two_nodes(
                **dict(self.kwargs, check_index_filters=True))
            self.assertEqual(evidence.tip_height, 11)
            self.assertTrue(evidence.synchronized_indexes_observed)
            self.assertFalse(evidence.core_authenticated)
            self.assertFalse(evidence.wallet_operational)
            self.assertIs(read.call_args.kwargs["consent"], True)
            observed["wallet_operational"] = True
            with self.assertRaisesRegex(subject.LiveNodeGuiProbeError,
                                        "^LIVE_NODE_GUI_INDEX_RECEIPT_DENIED$"):
                subject.inspect_existing_two_nodes(
                    **dict(self.kwargs, check_index_filters=True))

    def test_index_observation_denies_type_and_prior_cancel_without_network(self):
        with patch.object(subject, "inspect_existing_core_readiness") as read:
            with self.assertRaisesRegex(subject.LiveNodeGuiProbeError,
                                        "^LIVE_NODE_GUI_SCOPE_DENIED$"):
                subject.inspect_existing_two_nodes(
                    **dict(self.kwargs, check_index_filters=1))
            stop = Event()
            stop.set()
            with self.assertRaisesRegex(subject.LiveNodeGuiProbeError,
                                        "^LIVE_NODE_GUI_CANCELLED$"):
                subject.inspect_existing_two_nodes(
                    **dict(self.kwargs, check_index_filters=True, cancelled=stop))
            read.assert_not_called()

    def test_evidence_rejects_forged_index_observation(self):
        with self.assertRaisesRegex(subject.LiveNodeGuiProbeError,
                                    "^LIVE_NODE_GUI_EVIDENCE_DENIED$"):
            subject.LiveNodeGuiEvidence(1, synchronized_indexes_observed=1)

    def test_evidence_never_grants_authority(self):
        proof = subject.LiveNodeGuiEvidence(100)
        self.assertFalse(proof.wallet_operational)
        self.assertFalse(proof.core_authenticated)
        self.assertFalse(proof.signing_allowed)
        self.assertFalse(proof.mainnet_allowed)
        with self.assertRaises(subject.LiveNodeGuiProbeError):
            subject.LiveNodeGuiEvidence(True)
        mutated = subject.LiveNodeGuiEvidence(42)
        object.__setattr__(mutated, "wallet_operational", True)
        with self.assertRaises(subject.LiveNodeGuiProbeError):
            subject.LiveNodeGuiEvidence(mutated.tip_height, wallet_operational=True)
