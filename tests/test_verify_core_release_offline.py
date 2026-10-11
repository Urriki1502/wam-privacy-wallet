"""Negative controls for the nonexecuting official-release review command.

The core cryptographic GnuPG integration is tested separately by
ci_native_gpg_e2e with actual ephemeral signatures. These tests do NOT claim
an official WAM release has been verified or execute a Core binary.
"""
import contextlib
import io
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import verify_core_release_offline as cli
from wam_privacy_wallet.node.core_archive_inventory import (
    CoreArchiveInventory, CoreArchiveInventoryError,
)
from wam_privacy_wallet.node.core_signed_release import (
    CoreReleaseSignatureError, SignedDistributionEvidence,
    WAM_RELEASE_SIGNING_FINGERPRINT,
)

ARCHIVE = "wam-coin-v0.1.11-arm64-apple-darwin.tar.gz"
ABS = str(Path.cwd() / "wam-review-fixtures") + "/"\nGPG = str(Path.cwd() / "review-only-gpg-executable")


def files(name=ARCHIVE):
    return {
        "archive": ABS + name,
        "key": ABS + "SIGNING-KEY.asc",
        "checksums": ABS + "SHA256SUMS",
        "signature": ABS + "SHA256SUMS.asc",
        "gpg": GPG,
    }


def signed():
    return SignedDistributionEvidence(ARCHIVE, "a" * 64)


def inventory():
    return CoreArchiveInventory(
        ARCHIVE, 2, 1, 12, "wam-coin-v0.1.11/bin/wamd", 12, "b" * 64,
    )


class OfficialReleaseReviewCliTests(unittest.TestCase):
    def test_review_only_receipt_is_scalar_and_never_a_launch_token(self):
        receipt = cli._review_only_receipt(signed(), inventory())
        self.assertEqual(receipt["status"], "SIGNED_ARCHIVE_REVIEW_ONLY")
        self.assertEqual(receipt["archive_sha256"], "a" * 64)
        self.assertEqual(receipt["node_sha256"], "b" * 64)
        self.assertEqual(receipt["signer_fingerprint"],
                         WAM_RELEASE_SIGNING_FINGERPRINT)
        for key in ("execution_identity_bound", "core_execution_allowed",
                    "real_wallet_allowed", "mainnet_allowed", "real_regtest_qualified"):
            self.assertIs(receipt[key], False)
        self.assertNotIn("binary_path", receipt)
        self.assertNotIn("password", str(receipt))

    def test_non_absolute_or_url_input_rejected_before_file_access(self):
        variants = ("file.tar.gz", "https://wamcoin.org/download", "",
                    "C:ambiguous-relative-file")
        for bad in variants:
            with self.subTest(bad=bad), patch.object(
                cli, "verify_wam_signed_distribution",
                side_effect=AssertionError("MUST_NOT_VALIDATE"),
            ):
                with self.assertRaisesRegex(
                    CoreReleaseSignatureError, "^CORE_RECEIPT_PATH_DENIED$"
                ):
                    cli.qualify_release(**dict(files(), key=bad))

    def test_wrong_release_asset_rejected_without_crypto(self):
        for name in ("fake.tar.gz", "../escape.tar.gz", "wallet.dat",
                     "wam-coin-v0.1.10-x86_64-linux-gnu.tar.gz"):
            with self.subTest(name=name), patch.object(
                cli, "verify_wam_signed_distribution",
                side_effect=AssertionError("MUST_NOT_VALIDATE"),
            ):
                with self.assertRaisesRegex(
                    CoreReleaseSignatureError, "^CORE_RELEASE_ASSET_DENIED$"
                ):
                    cli.qualify_release(**files(name))

    def test_real_file_paths_are_passed_exactly_without_callback_network(self):
        with patch.object(cli, "verify_wam_signed_distribution", return_value=signed()) as verify, \
             patch.object(cli, "inspect_wam_core_archive", return_value=inventory()) as inspect:
            out = cli.qualify_release(**files())
        self.assertIs(out["core_execution_allowed"], False)
        opts = verify.call_args.kwargs
        self.assertEqual(opts["archive_name"], ARCHIVE)
        self.assertEqual(opts["gpg_executable"], Path(GPG))
        self.assertEqual(inspect.call_args.kwargs["signed_receipt"], signed())
        self.assertEqual(inspect.call_args.kwargs["archive"], Path(ABS + ARCHIVE))

    def test_signature_failure_never_inspects_archive(self):
        with patch.object(
            cli, "verify_wam_signed_distribution",
            side_effect=CoreReleaseSignatureError("CORE_RELEASE_SIGNATURE_DENIED"),
        ), patch.object(
            cli, "inspect_wam_core_archive",
            side_effect=AssertionError("MUST_NOT_INSPECT"),
        ):
            with self.assertRaisesRegex(
                CoreReleaseSignatureError, "^CORE_RELEASE_SIGNATURE_DENIED$"
            ):
                cli.qualify_release(**files())

    def test_inspection_failure_never_produces_receipt(self):
        with patch.object(cli, "verify_wam_signed_distribution", return_value=signed()), \
             patch.object(
                 cli, "inspect_wam_core_archive",
                 side_effect=CoreArchiveInventoryError("CORE_ARCHIVE_COLLISION_DENIED"),
             ):
            with self.assertRaisesRegex(
                CoreArchiveInventoryError, "^CORE_ARCHIVE_COLLISION_DENIED$"
            ):
                cli.qualify_release(**files())

    def test_wrong_or_forged_provenance_is_not_reviewed(self):
        bad = signed()
        object.__setattr__(bad, "signing_fingerprint", "f" * 40)
        for candidate in (None, {}, bad, SignedDistributionEvidence("bad", "a" * 64)):
            with self.subTest(candidate=type(candidate).__name__), self.assertRaisesRegex(
                CoreReleaseSignatureError, "^CORE_RECEIPT_AUTHORITY_DENIED$"
            ):
                cli._review_only_receipt(candidate, inventory())

    def test_forced_execution_claim_is_always_rejected(self):
        candidate = signed()
        object.__setattr__(candidate, "core_execution_allowed", True)
        with self.assertRaisesRegex(
            CoreReleaseSignatureError, "^CORE_RECEIPT_AUTHORITY_DENIED$"
        ):
            cli._review_only_receipt(candidate, inventory())
        candidate = inventory()
        object.__setattr__(candidate, "execution_identity_bound", True)
        with self.assertRaisesRegex(
            CoreReleaseSignatureError, "^CORE_RECEIPT_AUTHORITY_DENIED$"
        ):
            cli._review_only_receipt(signed(), candidate)

    def test_mismatching_archive_identity_and_fake_node_digest_denied(self):
        changed = inventory()
        object.__setattr__(changed, "archive_name",
                           "wam-coin-v0.1.11-x86_64-linux-gnu.tar.gz")
        with self.assertRaisesRegex(
            CoreReleaseSignatureError, "^CORE_RECEIPT_AUTHORITY_DENIED$"
        ):
            cli._review_only_receipt(signed(), changed)
        changed = inventory()
        object.__setattr__(changed, "node_sha256", "SECRET")
        with self.assertRaisesRegex(
            CoreReleaseSignatureError, "^CORE_RECEIPT_AUTHORITY_DENIED$"
        ):
            cli._review_only_receipt(signed(), changed)

    def test_empty_binary_receipt_is_denied(self):
        changed = inventory()
        object.__setattr__(changed, "node_entry", "../wallet.dat")
        with self.assertRaisesRegex(CoreReleaseSignatureError, "^CORE_RECEIPT_AUTHORITY_DENIED$"):
            cli._review_only_receipt(signed(), changed)
        changed = inventory()
        object.__setattr__(changed, "node_byte_count", 0)
        with self.assertRaisesRegex(
            CoreReleaseSignatureError, "^CORE_RECEIPT_AUTHORITY_DENIED$"
        ):
            cli._review_only_receipt(signed(), changed)

    def test_cli_failure_reports_only_fixed_status_and_no_paths(self):
        with patch.object(
            cli, "verify_wam_signed_distribution",
            side_effect=CoreReleaseSignatureError("CORE_RELEASE_SIGNATURE_DENIED"),
        ):
            err, out = io.StringIO(), io.StringIO()
            args = [word for key, val in files().items()
                    for word in ("--" + key, val)]
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
                status = cli.main(args)
        self.assertEqual(status, 2)
        self.assertEqual(err.getvalue().strip(), "CORE_RELEASE_SIGNATURE_DENIED")
        self.assertEqual(out.getvalue(), "")
        self.assertNotIn(ABS, err.getvalue())

    def test_cli_success_is_non_authorizing_json_and_no_core_spawn(self):
        args = [word for key, val in files().items()
                for word in ("--" + key, val)]
        with patch.object(cli, "verify_wam_signed_distribution", return_value=signed()), \
             patch.object(cli, "inspect_wam_core_archive", return_value=inventory()), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("NO_CORE_EXEC")):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = cli.main(args)
        self.assertEqual(status, 0)
        proof = json.loads(output.getvalue())
        self.assertIs(proof["real_regtest_qualified"], False)
        self.assertIs(proof["core_execution_allowed"], False)
        self.assertEqual(proof["node_sha256"], "b" * 64)
        self.assertNotIn(ABS, output.getvalue())


if __name__ == "__main__":
    unittest.main()
