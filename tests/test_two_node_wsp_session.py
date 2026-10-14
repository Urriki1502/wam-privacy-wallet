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
        self.absolute_unused = Path.cwd().resolve() / "unopened-test-only"
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
        self.assertFalse(subject.same_reported_chain(
            identity_a, ChainIdentity(self.b, "c" * 64, 42, "a" * 64),
        ))

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
            dict(receive_account_index=True),
            dict(receive_account_index=16),
            dict(show_observed_balance=1),
            dict(require_synchronized_indexes=1),
            dict(save_checkpoint=True, restore_checkpoint=True),
        ]
        with patch.object(subject, "TwoNodeP2PReadOnlyAudit") as audit:
            for bad_root, bad_password in (
                (Path("."), b"x" * 16),
                (self.absolute_unused, b"short"),
                (self.absolute_unused, "not-bytes"),
            ):
                with self.assertRaisesRegex(
                    subject.TwoNodeWspSessionError, "^TWO_NODE_WSP_SCOPE_DENIED$"
                ):
                    subject.scan_two_existing_regtest_nodes(
                        bad_root, self.absolute_unused, bad_password, **self.args,
                    )
            for changed in variants:
                with self.subTest(changed=changed):
                    kwargs = dict(self.args)
                    kwargs.update(changed)
                    with self.assertRaisesRegex(
                        subject.TwoNodeWspSessionError, "^TWO_NODE_WSP_SCOPE_DENIED$"
                    ):
                        subject.scan_two_existing_regtest_nodes(
                            self.absolute_unused, self.absolute_unused, b"x" * 16,
                            **kwargs,
                        )
            audit.assert_not_called()

    def test_chain_mutates_during_scan_never_returns_success(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        identity_a = ChainIdentity(self.a, WAM_REGTEST_GENESIS, 42, "a" * 64)
        identity_b = ChainIdentity(self.b, WAM_REGTEST_GENESIS, 42, "a" * 64)
        advanced_a = ChainIdentity(self.a, WAM_REGTEST_GENESIS, 43, "b" * 64)
        gateway_a = Mock()
        gateway_b = Mock()
        gateway_a.probe_core_profile.side_effect = (
            [SimpleNamespace(identity=identity_a),
             SimpleNamespace(identity=advanced_a)])
        gateway_b.probe_core_profile.side_effect = (
            [SimpleNamespace(identity=identity_b),
             SimpleNamespace(identity=identity_b)])
        scan = {
            "status": "REAL_LOOPBACK_WSP_SCAN_UNQUALIFIED_CORE",
            "core_binary_authenticated": False,
            "wallet_operational": False,
            "signer_enabled": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
            "chain_current": True, "tip_height": 42,
            "real_two_node_regtest_qualified": False,
        }
        with patch.object(subject, "TwoNodeP2PReadOnlyAudit") as topology, \
             patch.object(subject, "LocalRegtestIdentityGateway") as gateways, \
             patch.object(subject, "scan_existing_regtest", return_value=scan) as scanner:
            gateways.side_effect = lambda endpoint, auth, timeout: (
                gateway_a if endpoint == self.a else gateway_b
            )
            with self.assertRaisesRegex(
                subject.TwoNodeWspSessionError, "^TWO_NODE_WSP_MOVED_DENIED$"
            ):
                subject.scan_two_existing_regtest_nodes(
                    self.absolute_unused, self.absolute_unused, b"x" * 16, **self.args,
                )
            self.assertEqual(topology.return_value.audit.call_count, 2)
            scanner.assert_called_once()

    def test_forged_scanner_authority_receipt_is_refused(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        profile_a = SimpleNamespace(identity=ChainIdentity(
            self.a, WAM_REGTEST_GENESIS, 42, "a" * 64,
        ))
        profile_b = SimpleNamespace(identity=ChainIdentity(
            self.b, WAM_REGTEST_GENESIS, 42, "a" * 64,
        ))
        gateway_a = Mock()
        gateway_b = Mock()
        gateway_a.probe_core_profile.return_value = profile_a
        gateway_b.probe_core_profile.return_value = profile_b
        forged = {
            "status": "REAL_LOOPBACK_WSP_SCAN_UNQUALIFIED_CORE",
            "core_binary_authenticated": False,
            "wallet_operational": True,
            "signer_enabled": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
            "chain_current": True, "tip_height": 42,
        }
        with patch.object(subject, "TwoNodeP2PReadOnlyAudit"), \
             patch.object(subject, "LocalRegtestIdentityGateway") as gateways, \
             patch.object(subject, "scan_existing_regtest", return_value=forged):
            gateways.side_effect = lambda endpoint, auth, timeout: (
                gateway_a if endpoint == self.a else gateway_b
            )
            with self.assertRaisesRegex(
                subject.TwoNodeWspSessionError, "^TWO_NODE_WSP_RECEIPT_DENIED$"
            ):
                subject.scan_two_existing_regtest_nodes(
                    self.absolute_unused, self.absolute_unused, b"x" * 16, **self.args,
                )

    def test_no_signer_core_launcher_or_fake_peer_in_operator_contract(self):
        import inspect
        params = inspect.signature(subject.scan_two_existing_regtest_nodes).parameters
        for prohibited in ("core_binary", "core_launcher", "signer",
                           "rpc_peer", "mock_backend", "allow_broadcast"):
            self.assertNotIn(prohibited, params)
        self.assertIn("history_limit", params)
        self.assertIn("restore_checkpoint", params)
        self.assertIn("receive_account_index", params)
        self.assertIn("show_observed_balance", params)

    def test_opt_in_indexes_gate_reaches_real_scanner_without_new_backend(self):
        """Pure contract test: readiness must reach the existing live scanner."""
        from types import SimpleNamespace
        from unittest.mock import Mock

        tip = "a" * 64
        profile_a = SimpleNamespace(identity=ChainIdentity(
            self.a, WAM_REGTEST_GENESIS, 42, tip,
        ))
        profile_b = SimpleNamespace(identity=ChainIdentity(
            self.b, WAM_REGTEST_GENESIS, 42, tip,
        ))
        for require_indexes in (False, True):
            with self.subTest(require_indexes=require_indexes):
                gateway_a = Mock()
                gateway_b = Mock()
                gateway_a.probe_core_profile.return_value = profile_a
                gateway_b.probe_core_profile.return_value = profile_b
                receipt = {
                    "status": "REAL_LOOPBACK_WSP_SCAN_UNQUALIFIED_CORE",
                    "core_binary_authenticated": False,
                    "wallet_operational": False,
                    "signer_enabled": False,
                    "broadcast_allowed": False,
                    "mainnet_allowed": False,
                    "chain_current": True,
                    "tip_height": 42,
                    "real_two_node_regtest_qualified": False,
                }
                with patch.object(subject, "TwoNodeP2PReadOnlyAudit") as audit, \
                     patch.object(subject, "LocalRegtestIdentityGateway") as gateways, \
                     patch.object(subject, "scan_existing_regtest", return_value=receipt) as scanner:
                    gateways.side_effect = lambda endpoint, auth, timeout: (
                        gateway_a if endpoint == self.a else gateway_b
                    )
                    observed = subject.scan_two_existing_regtest_nodes(
                        self.absolute_unused, self.absolute_unused,
                        b"x" * 16, require_synchronized_indexes=require_indexes,
                        **self.args,
                    )
                    self.assertEqual(
                        scanner.call_args.kwargs["require_synchronized_indexes"],
                        require_indexes,
                    )
                    self.assertTrue(observed["two_node_reported_chain_agrees"])
                    self.assertFalse(observed["real_two_node_regtest_qualified"])
                    self.assertEqual(audit.return_value.audit.call_count, 2)
