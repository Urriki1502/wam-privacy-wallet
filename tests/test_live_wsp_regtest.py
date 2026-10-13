"""No-Core/no-network negative-path tests for the real-only scan entrypoint."""
import unittest
from pathlib import Path
from unittest.mock import patch
from wam_privacy_wallet.application import live_regtest_scanner as m
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth

class LiveRegtestContractTests(unittest.TestCase):
    def test_invalid_consent_or_scope_denies_without_socket_or_core(self):
        end = LocalRegtestEndpoint("127.0.0.1", 29554)
        auth = ExplicitRpcAuth("temporary", "test_disposable_regtest")
        kwargs = dict(
            endpoint=end, rpc_auth=auth, user_consented=True,
            acknowledge_unverified_binary=True,
        )
        with patch.object(m, "LocalRegtestIdentityGateway") as gateway:
            for changed in ({"user_consented": False},
                            {"acknowledge_unverified_binary": False},
                            {"max_blocks": 17}, {"history_limit": True},
                            {"history_limit": 101},
                            {"receive_account_index": True},
                            {"receive_account_index": 16},
                            {"show_observed_balance": 1},
                            {"require_synchronized_indexes": 1},
                            {"save_checkpoint": True, "restore_checkpoint": True}):
                with self.subTest(changed=changed):
                    values = dict(kwargs)
                    values.update(changed)
                    with self.assertRaises(m.LiveRegtestScanError):
                        m.scan_existing_regtest(
                            Path("/source"), Path("/disposable"), b"a" * 16, **values
                        )
            gateway.assert_not_called()


    def test_opt_in_private_projection_only_after_current_scan(self):
        """Test double guards the I/O interface; no claimed Core or WSP E2E."""
        from types import SimpleNamespace
        from unittest.mock import Mock
        end = LocalRegtestEndpoint("127.0.0.1", 29554)
        auth = ExplicitRpcAuth("temporary", "test_disposable_regtest")
        kwargs = dict(endpoint=end, rpc_auth=auth, user_consented=True,
                      acknowledge_unverified_binary=True)
        snapshot = SimpleNamespace(
            source_commit="a" * 40, tip_height=42, blocks_processed=1,
            transactions_processed=2, rollback_blocks=0, chain_current=True,
            confirmed_utxo_count=3, unqualified_confirmed_atoms=12_345,
            core_authenticated=False, wallet_operational=False,
            balance_qualified=False, signer_enabled=False,
            broadcast_allowed=False, mainnet_allowed=False,
        )
        profile = SimpleNamespace(chain="regtest")
        with patch.object(m, "LocalRegtestIdentityGateway") as gateway, \
             patch.object(m, "SourceQualifiedScanRuntime") as runtime, \
             patch.object(m, "Wsp1ScannerOnlyRpc"):
            gateway.return_value.probe_core_profile.return_value = profile
            session = runtime.return_value.open.return_value
            session.scan.return_value = snapshot
            session.closed = False
            session.receive_code.return_value = SimpleNamespace(code="PRIVATE-OPERATOR-CODE")
            receipt = m.scan_existing_regtest(
                Path.cwd().resolve(), Path.cwd().resolve(), b"a" * 16, **kwargs
            )
            self.assertNotIn("unqualified_receive_code", receipt)
            self.assertNotIn("unqualified_confirmed_atoms", receipt)
            receipt = m.scan_existing_regtest(
                Path.cwd().resolve(), Path.cwd().resolve(), b"a" * 16,
                receive_account_index=0, show_observed_balance=True, **kwargs
            )
            self.assertEqual(receipt["unqualified_receive_code"], "PRIVATE-OPERATOR-CODE")
            self.assertEqual(receipt["unqualified_confirmed_atoms"], 12_345)
            self.assertFalse(receipt["core_binary_authenticated"])
            self.assertFalse(receipt["wallet_operational"])
            session.receive_code.assert_called_once()
            self.assertEqual(session.close.call_count, 2)
            snapshot.chain_current = False
            with self.assertRaisesRegex(m.LiveRegtestScanError,
                                        "^LIVE_SCAN_INCOMPLETE_DENIED$"):
                m.scan_existing_regtest(
                    Path.cwd().resolve(), Path.cwd().resolve(), b"a" * 16,
                    show_observed_balance=True, **kwargs
                )

    def test_late_node_drift_refuses_private_output(self):
        """A late fork after read-side snapshot must fail before publishing."""
        from types import SimpleNamespace
        end = LocalRegtestEndpoint("127.0.0.1", 29554)
        auth = ExplicitRpcAuth("temporary", "disposable-regtest-only")
        snapshot = SimpleNamespace(
            source_commit="a" * 40, tip_height=42, blocks_processed=0,
            transactions_processed=0, rollback_blocks=0,
            chain_current=True, confirmed_utxo_count=1,
            unqualified_confirmed_atoms=12_345, core_authenticated=False,
            wallet_operational=False, balance_qualified=False,
            signer_enabled=False, broadcast_allowed=False,
            mainnet_allowed=False,
        )
        with patch.object(m, "LocalRegtestIdentityGateway") as gateway, \
             patch.object(m, "SourceQualifiedScanRuntime") as runtime, \
             patch.object(m, "Wsp1ScannerOnlyRpc"):
            gateway.return_value.probe_core_profile.side_effect = [
                SimpleNamespace(tip="stable"),
                SimpleNamespace(tip="stable"),
                SimpleNamespace(tip="changed"),
            ]
            session = runtime.return_value.open.return_value
            session.closed = False
            session.scan.return_value = snapshot
            session.receive_code.return_value = SimpleNamespace(code="PRIVATE-CODE")
            with self.assertRaisesRegex(
                m.LiveRegtestScanError, "^LIVE_SCAN_PEER_MOVED_DENIED$"
            ):
                m.scan_existing_regtest(
                    Path.cwd().resolve(), Path.cwd().resolve(), b"a" * 16,
                    endpoint=end, rpc_auth=auth,
                    user_consented=True, acknowledge_unverified_binary=True,
                    receive_account_index=0, show_observed_balance=True,
                )
            session.close.assert_called_once()

    def test_no_callback_or_network_override_parameter(self):
        import inspect
        params = inspect.signature(m.scan_existing_regtest).parameters
        self.assertNotIn("backend", params)
        self.assertNotIn("mock_peer", params)
        self.assertNotIn("core_executable", params)
        self.assertNotIn("signer", params)
        self.assertIn("restore_checkpoint", params)
        self.assertIn("history_limit", params)
        self.assertIn("save_checkpoint", params)
        self.assertIn("receive_account_index", params)
        self.assertIn("show_observed_balance", params)
