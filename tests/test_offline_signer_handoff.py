"""Actual Linux file-descriptor input validation for a future offline signer CLI."""
from pathlib import Path
from unittest.mock import patch
from wam_privacy_wallet.application import offline_signer_handoff as handoff
from tempfile import TemporaryDirectory
import unittest
from wam_privacy_wallet.application.offline_signer_handoff import (
    inspect_external_signer_request, SignerHandoffError,
)

PIN = "ac55f13423620252bdbf848c7e8a280c3b84721e"

class OfflineSignerHandoffTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name)
        self.key = self.dir / "keys.enc"
        self.request = self.dir / "request.enc"
        self.out = self.dir / "signed.psbt"
        self.key.write_bytes(b"WAMSP02\x00" + b"K" * 64)
        self.request.write_bytes(b"WAMSP02\x00" + b"I" * 64)
        self.key.chmod(0o600)
        self.request.chmod(0o600)

    def inspect(self, **changes):
        kwargs = dict(source_root=self.dir, user_consented=True)
        kwargs.update(changes)
        # Unit tests isolate private-file safety. The native integration
        # workflow independently proves pinned Git source closure.
        with patch.object(handoff, "verify_wsp1_full_source_closure",
                          return_value={
                              "pinned_commit": PIN,
                              "status": "WSP1_FULL_SOURCE_CLOSURE_VERIFIED_NO_AUTHORITY",
                              "signer_enabled": False,
                          }):
            return inspect_external_signer_request(
                self.key, self.request, self.out, **kwargs,
            )

    def test_no_signer_execution_or_authority(self):
        import sys
        if sys.platform != "linux":
            with self.assertRaises(SignerHandoffError):
                self.inspect()
            return
        receipt = self.inspect()
        self.assertFalse(receipt.signer_executed)
        self.assertFalse(receipt.signing_allowed)
        self.assertFalse(receipt.broadcast_allowed)
        self.assertFalse(receipt.mainnet_allowed)
        self.assertEqual(receipt.signer_entrypoint, "wam_sp.offline_signer")
        self.assertEqual(len(receipt.keyring_digest), 64)
        self.assertNotIn("DISPOSABLE", repr(receipt))
        self.assertFalse(self.out.exists())

    def test_no_consent_rejected(self):
        with self.assertRaisesRegex(SignerHandoffError,
                                    "^SIGNER_SOURCE_OR_CONSENT_DENIED$"):
            self.inspect(user_consented=False)

    def test_unqualified_source_closure_rejected(self):
        with self.assertRaisesRegex(SignerHandoffError,
                                    "^SIGNER_SOURCE_UNVERIFIED$"):
            inspect_external_signer_request(
                self.key, self.request, self.out,
                source_root=self.dir, user_consented=True,
            )

    def test_malformed_envelope_magic_denied(self):
        import sys
        if sys.platform != "linux":
            return
        self.request.write_bytes(b"NOTWSP00" + b"X" * 64)
        with self.assertRaisesRegex(SignerHandoffError,
                                    "^SIGNER_PRIVATE_FILE_DENIED$"):
            self.inspect()

    def test_symlinks_permissive_keys_and_existing_output_denied(self):
        import sys
        if sys.platform != "linux":
            return
        self.key.chmod(0o644)
        with self.assertRaises(SignerHandoffError):
            self.inspect()
        self.key.chmod(0o600)
        self.out.write_bytes(b"existing")
        with self.assertRaisesRegex(SignerHandoffError,
                                     "^SIGNER_OUTPUT_EXISTS_DENIED$"):
            self.inspect()
        self.out.unlink()
        self.key.unlink()
        self.key.symlink_to(self.request)
        with self.assertRaises(SignerHandoffError):
            self.inspect()
