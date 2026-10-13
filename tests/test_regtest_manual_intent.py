"""No signing, Core, or mocked backend. Storage tests use inert bytes only."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import regtest_manual_intent as sut
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth


class ManualIntentTests(unittest.TestCase):
    def test_no_network_on_invalid_scope(self):
        end = LocalRegtestEndpoint("127.0.0.1", 29554)
        auth = ExplicitRpcAuth("disposable", "only-regtest-pass")
        params = dict(
            endpoint=end, rpc_auth=auth,
            recipient_code="bad", recipient_atoms=50000, fee_atoms=1000,
            user_consented=True, acknowledge_unverified_binary=True,
        )
        with patch.object(sut, "LocalRegtestIdentityGateway") as gw:
            with self.assertRaisesRegex(
                sut.ManualIntentError, "^INTENT_PREPARE_SCOPE_DENIED$"
            ):
                sut.create_manual_regtest_intent(
                    Path("/never"), Path("/never"), Path("/never"),
                    b"x" * 16, b"y" * 16, **params,
                )
            gw.assert_not_called()

    def test_private_create_once_with_inert_envelope(self):
        if sys.platform != "linux":
            return
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"WAMSP02\x00" + b"X" * 64
            digest = sut._store_encrypted_intent(root, data)
            dest = root / "wsp-intent-v1.enc"
            self.assertTrue(dest.is_file())
            self.assertEqual(dest.read_bytes(), data)
            self.assertEqual(dest.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(digest), 64)
            with self.assertRaisesRegex(
                sut.ManualIntentError, "^INTENT_STORE_DENIED$"
            ):
                sut._store_encrypted_intent(root, data)
            self.assertEqual(dest.read_bytes(), data)

    def test_symlink_parent_and_unsafe_modes_denied(self):
        if sys.platform != "linux":
            return
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            link = root.parent / (root.name + "-link")
            try:
                link.symlink_to(root, target_is_directory=True)
                with self.assertRaises(sut.ManualIntentError):
                    sut._store_encrypted_intent(
                        link, b"WAMSP02\x00" + b"A" * 60
                    )
                root.chmod(0o755)
                with self.assertRaises(sut.ManualIntentError):
                    sut._store_encrypted_intent(
                        root, b"WAMSP02\x00" + b"A" * 60
                    )
            finally:
                link.unlink(missing_ok=True)

    def test_no_operational_signer_or_broadcast_api(self):
        import inspect
        source = inspect.getsource(sut)
        for blocked in ("sendrawtransaction", "Keyring(", "Signer(",
                        "subprocess.", "synthetic_backend"):
            self.assertNotIn(blocked, source)
