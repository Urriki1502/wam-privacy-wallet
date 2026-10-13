"""Fail-closed reviewer boundary without launching signer or WAM Core."""
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import offline_signed_psbt_review as review

class SignedPsbtReadOnlyTests(unittest.TestCase):
    def test_no_io_on_invalid_consent_and_digest(self):
        with patch.object(review, "verify_wsp1_full_source_closure") as verify:
            for changed in ({"user_consented": False},
                            {"expected_request_sha256": "Z" * 64},
                            {"intent_password": b"short"}):
                args = dict(user_consented=True,
                            expected_request_sha256="a" * 64,
                            intent_password=b"a" * 16)
                args.update(changed)
                with self.subTest(changed=changed):
                    with self.assertRaisesRegex(
                        review.SignedPsbtReviewError,
                        "^SIGNED_PSBT_SCOPE_DENIED$",
                    ):
                        review.review_signed_regtest_psbt(
                            Path.cwd().resolve(), Path.cwd().resolve() / "request",
                            Path.cwd().resolve() / "signed",
                            args["intent_password"],
                            expected_request_sha256=args["expected_request_sha256"],
                            user_consented=args["user_consented"],
                        )
            verify.assert_not_called()

    def test_private_file_restrictions(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = root / "private.b64"
            file.write_bytes(b"A" * 100)
            if sys.platform != "linux":
                with self.assertRaises(review.SignedPsbtReviewError):
                    review._read_private_file(file, lower=16, upper=1400000)
                return
            file.chmod(0o600)
            self.assertEqual(
                review._read_private_file(file, lower=16, upper=1400000),
                b"A" * 100)
            file.chmod(0o644)
            with self.assertRaisesRegex(
                review.SignedPsbtReviewError,
                "^SIGNED_PSBT_PRIVATE_FILE_DENIED$",
            ):
                review._read_private_file(file, lower=16, upper=1400000)

    def test_no_sign_or_core_io_in_reviewer(self):
        import inspect
        src = inspect.getsource(review)
        for prohibited in ("sendrawtransaction", "subprocess.Popen",
                           "Signer(", "Keyring(", "broadcast(", "rpc.call("):
            self.assertNotIn(prohibited, src)
