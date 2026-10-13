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
                            {"save_checkpoint": True, "restore_checkpoint": True}):
                with self.subTest(changed=changed):
                    values = dict(kwargs)
                    values.update(changed)
                    with self.assertRaises(m.LiveRegtestScanError):
                        m.scan_existing_regtest(
                            Path("/source"), Path("/disposable"), b"a" * 16, **values
                        )
            gateway.assert_not_called()

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
