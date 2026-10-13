"""Strict pre-network fail-closed tests; no synthetic positive backend."""
import unittest
from pathlib import Path
from unittest.mock import patch

from wam_privacy_wallet.application import two_node_wsp_session as subject
from wam_privacy_wallet.node.attestation import ChainIdentity, WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth


class TwoNodeWspScopeTests(unittest.TestCase):
    def setUp(self):
        self.a = LocalRegtestEndpoint("127.0.0.1", 29554)
        self.b = LocalRegtestEndpoint("127.0.0.1", 29556)
        self.autha = ExplicitRpcAuth("a_test", "test-only-a-password")
        self.authb = ExplicitRpcAuth("b_test", "test-only-b-password")
        self.args = dict(
            node_a=self.a, auth_a=self.autha,
            node_b=self.b, auth_b=self.authb,
            node_a_p2p_port=29555, node_b_p2p_port=29557,
            user_consented=True, acknowledge_unverified_binaries=True,
        )

    def test_compare_independent_endpoints_by_chain_not_endpoint(self):
        identity_a = ChainIdentity(self.a, WAM_REGTEST_GENESIS, 42, "a" * 64)
        identity_b = ChainIdentity(self.b, WAM_REGTEST_GENESIS, 42, "a" * 64)
        self.assertNotEqual(identity_a, identity_b)
        self.assertTrue(subject.same_reported_chain(identity_a, identity_b))
        self.assertFalse(subject.same_reported_chain(
            identity_a, ChainIdentity(self.b, WAM_REGTEST_GENESIS, 41, "a" * 64),
        ))
        self.assertFalse(subject.same_reported_chain(
            identity_a, ChainIdentity(self.b, WAM_REGTEST_GENESIS, 42, "b" * 64),
        ))
        self.assertFalse(subject.same_reported_chain(identity_a, identity_a))

    def test_all_scope_denials_before_network(self):
        variants = [
            dict(user_consented=False),
            dict(acknowledge_unverified_binaries=False),
            dict(node_b=self.a),
            dict(auth_b=self.autha),
            dict(node_b_p2p_port=29555),
            dict(node_a_p2p_port=True),
            dict(max_blocks=0),
            dict(history_limit=True),
            dict(history_limit=101),
            dict(save_checkpoint=True, restore_checkpoint=True),
        ]
        with patch.object(subject, "TwoNodeP2PReadOnlyAudit") as audit:
            for changed in variants:
                with self.subTest(changed=changed):
                    kwargs = dict(self.args)
                    kwargs.update(changed)
                    with self.assertRaisesRegex(
                        subject.TwoNodeWspSessionError, "^TWO_NODE_WSP_SCOPE_DENIED$"
                    ):
                        subject.scan_two_existing_regtest_nodes(
                            Path("/unused"), Path("/unused"), b"x" * 16,
                            **kwargs,
                        )
            audit.assert_not_called()

    def test_no_signer_core_launcher_or_fake_peer_in_operator_contract(self):
        import inspect
        params = inspect.signature(subject.scan_two_existing_regtest_nodes).parameters
        for prohibited in ("core_binary", "core_launcher", "signer",
                           "rpc_peer", "mock_backend", "allow_broadcast"):
            self.assertNotIn(prohibited, params)
        self.assertIn("history_limit", params)
        self.assertIn("restore_checkpoint", params)
