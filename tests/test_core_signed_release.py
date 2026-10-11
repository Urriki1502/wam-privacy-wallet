"""Signed distribution contract tests: NO Core, wallet, P2P, or real funds."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node import core_signed_release as mod
from wam_privacy_wallet.node.core_signed_release import (
    CoreReleaseSignatureError, SignedDistributionEvidence,
    RELEASE_ASSETS, WAM_RELEASE_SIGNING_FINGERPRINT,
    _gpg_primary_fingerprint, _signed_digest, _validate_gpg_status,
    verify_wam_signed_distribution,
)

LINUX = "wam-coin-v0.1.11-x86_64-linux-gnu.tar.gz"
MAC = "wam-coin-v0.1.11-arm64-apple-darwin.tar.gz"
WIN = "wam-coin-v0.1.11-x86_64-w64-mingw32.zip"
FP = WAM_RELEASE_SIGNING_FINGERPRINT
WRONG = "0" * 40


class CoreSignedReleaseTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="synthetic-signed-release-")
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.file = self.root / LINUX
        self.file.write_bytes(b"UNEXECUTABLE_SYNTHETIC_DISTRIBUTION_BYTES" * 3)
        self.sha = hashlib.sha256(self.file.read_bytes()).hexdigest()
        self.key = self.root / "SIGNING-KEY.asc"
        self.key.write_text("SYNTHETIC-TEST-KEY-NOT-REAL-PGP", encoding="ascii")
        self.sum = self.root / "SHA256SUMS"
        self.sum.write_text(
            self.sha + "  " + LINUX + "\n"
            + "1" * 64 + "  " + WIN + "\n"
            + "2" * 64 + "  " + MAC + "\n",
            encoding="ascii",
        )
        self.sig = self.root / "SHA256SUMS.asc"
        self.sig.write_bytes(b"SYNTHETIC_TEST_SIGNATURE_NOT_REAL")
        self.gpg = self.root / "SYNTHETIC_GPG_NOT_EXECUTED"

    def valid_results(self):
        listing = (
            "pub:-:4096:1:ABC:1234:::::::scSC:\n"
            + "fpr:::::::::" + FP + ":\n"
        )
        status = (
            "[GNUPG:] GOODSIG ABC WAM Coin release signing\n"
            + "[GNUPG:] VALIDSIG " + FP
            + " 2026-09-27 1790530000 0 4 0 1 10 00 " + FP + "\n"
        )
        return [(0, listing), (0, ""), (0, status)]

    def verify_fixture(self, **updates):
        args = {
            "signing_key": self.key,
            "sha256sums": self.sum,
            "detached_signature": self.sig,
            "archive": self.file,
            "archive_name": LINUX,
            "gpg_executable": self.gpg,
        }
        args.update(updates)
        return verify_wam_signed_distribution(**args)

    def test_correct_pinned_fingerprint_is_from_primary_wam_security_page(self):
        self.assertEqual(FP, "4BD4A8D3AFD43F5CBCB500E23798462FE00ADBA4")
        self.assertEqual(len(FP), 40)
        self.assertEqual(RELEASE_ASSETS, frozenset({LINUX, MAC, WIN}))

    def test_valid_signature_contract_is_still_archive_only_and_no_core_launch(self):
        with patch.object(mod, "_run_gpg", side_effect=self.valid_results()) as gpg, \
             patch.object(subprocess, "Popen",
                          side_effect=AssertionError("LIVE_CORE_FORBIDDEN")) as core:
            r = self.verify_fixture()
        self.assertEqual(gpg.call_count, 3)
        core.assert_not_called()
        self.assertEqual(r.status, "SIGNED_DISTRIBUTION_ONLY")
        self.assertEqual(r.archive_name, LINUX)
        self.assertEqual(r.distribution_sha256, self.sha)
        self.assertEqual(r.signing_fingerprint, FP)
        self.assertFalse(any((
            r.extracted_binary_verified, r.execution_identity_bound,
            r.core_execution_allowed, r.mainnet_allowed, r.real_wallet_allowed,
        )))

    def test_signature_check_is_required_before_archive_digest(self):
        with patch.object(mod, "_run_gpg", side_effect=self.valid_results()[:2] + [(1, "")]):
            with self.assertRaisesRegex(
                CoreReleaseSignatureError, "^CORE_RELEASE_SIGNATURE_DENIED$"
            ):
                self.verify_fixture(archive=self.root / "missing")

    def test_gpg_listed_primary_key_must_match_fixed_fingerprint(self):
        for listing in (
            "", "fpr:::::::::" + FP + ":\n",  # no pub
            "pub:...\nfpr:::::::::" + WRONG + ":\n",
            "pub:...\nfpr:::::::::" + FP + ":\n"
            + "pub:...\nfpr:::::::::" + WRONG + ":\n",
        ):
            with self.subTest(listing=listing), self.assertRaisesRegex(
                CoreReleaseSignatureError, "^CORE_RELEASE_SIGNER_DENIED$"
            ):
                _gpg_primary_fingerprint(listing)

    def test_correct_primary_key_allows_legitimate_subkey_fingerprint(self):
        listing = (
            "pub:...\nfpr:::::::::" + FP + ":\n"
            + "sub:...\nfpr:::::::::" + WRONG + ":\n"
        )
        self.assertEqual(_gpg_primary_fingerprint(listing), FP)

    def test_invalid_signature_states_are_rejected_even_with_validsig(self):
        good = self.valid_results()[-1][1]
        for bad in (
            "[GNUPG:] BADSIG ABC BAD",
            "[GNUPG:] REVOKEDKEY ABC",
            "[GNUPG:] EXPKEYSIG ABC BAD",
            "[GNUPG:] NO_PUBKEY ABC",
            "[GNUPG:] VALIDSIG " + WRONG,
            good.replace("GOODSIG", "NO_GOOD_SIG"),
            good + "[GNUPG:] VALIDSIG " + WRONG,
            good + "[GNUPG:] GOODSIG OTHER SECOND",
        ):
            with self.subTest(line=bad[:28]), self.assertRaisesRegex(
                CoreReleaseSignatureError, "^CORE_RELEASE_SIGNATURE_DENIED$"
            ):
                _validate_gpg_status(good + "\n" + bad if bad.startswith(
                    "[GNUPG:] BADSIG") or bad.startswith("[GNUPG:] EXPKEYSIG")
                    or bad.startswith("[GNUPG:] NO_PUBKEY") else bad)

    def test_unsigned_checksums_are_never_acceptance_evidence(self):
        with patch.object(mod, "_run_gpg",
                          side_effect=self.valid_results()[:2] + [(1, "")]):
            with self.assertRaises(CoreReleaseSignatureError):
                self.verify_fixture()

    def test_forged_signature_key_primary_is_denied(self):
        fake = "pub:...\nfpr:::::::::" + WRONG + ":\n"
        with patch.object(mod, "_run_gpg", side_effect=[(0, fake)]):
            with self.assertRaisesRegex(
                CoreReleaseSignatureError, "^CORE_RELEASE_SIGNER_DENIED$"
            ):
                self.verify_fixture()

    def test_gpg_command_failure_or_missing_binary_fails_closed(self):
        for executable in (None, "gpg", "./gpg", 1, True):
            with self.subTest(executable=executable), self.assertRaisesRegex(
                CoreReleaseSignatureError, "^CORE_RELEASE_GPG_UNAVAILABLE$"
            ):
                self.verify_fixture(gpg_executable=executable)
        with patch.object(mod, "_run_gpg",
                          side_effect=CoreReleaseSignatureError(
                              "CORE_RELEASE_GPG_UNAVAILABLE"
                          )):
            with self.assertRaises(CoreReleaseSignatureError):
                self.verify_fixture()

    def test_only_exact_pinned_core_archive_names_are_accepted(self):
        for name in (
            "../" + LINUX, "wam-miner-v0.1.11-x86_64-linux-gnu.tar.gz",
            "wam-qt-v0.1.11-x86_64-linux-gnu.tar.gz", LINUX + ".exe",
            LINUX.upper(), "wam-coin-v0.1.12-x86_64-linux-gnu.tar.gz",
            "wam-coin-v0.1.11-i686-w64-mingw32.zip",
            None, True, 123,
        ):
            with self.subTest(name=name), self.assertRaisesRegex(
                CoreReleaseSignatureError, "^CORE_RELEASE_ASSET_DENIED$"
            ):
                self.verify_fixture(archive_name=name)

    def test_missing_or_duplicated_checksum_entry_denied(self):
        original = self.sum.read_bytes()
        for data in (
            ("f" * 64 + "  " + WIN + "\n").encode("ascii"),
            original + original,
            original + self.sha.encode("ascii") + b"  " + LINUX.encode() + b"\n",
        ):
            with self.subTest(length=len(data)), self.assertRaises(
                CoreReleaseSignatureError
            ):
                _signed_digest(data, LINUX)

    def test_checksum_parser_rejects_traversal_case_nonascii_and_malformed(self):
        for bad in (
            b"not a SHA256SUMS file\n",
            b"\xff\xfe",
            (self.sha + "  ../" + LINUX + "\n").encode("ascii"),
            (self.sha.upper() + "  " + LINUX + "\n").encode("ascii"),
            (self.sha + " " + LINUX + "\n").encode("ascii"),
            (self.sha + "  " + LINUX + "\n") .encode("ascii") * 129,
        ):
            with self.subTest(length=len(bad)), self.assertRaisesRegex(
                CoreReleaseSignatureError, "^CORE_RELEASE_SUMS_DENIED$"
            ):
                _signed_digest(bad, LINUX)

    def test_checksum_uses_only_exact_selected_file(self):
        self.assertEqual(_signed_digest(self.sum.read_bytes(), LINUX), self.sha)
        self.assertEqual(_signed_digest(self.sum.read_bytes(), WIN), "1" * 64)

    def test_post_signature_archive_digest_mismatch_denied(self):
        self.file.write_bytes(b"INCORRECT_ARCHIVE")
        with patch.object(mod, "_run_gpg", side_effect=self.valid_results()):
            with self.assertRaisesRegex(
                CoreReleaseSignatureError, "^CORE_RELEASE_ARCHIVE_DENIED$"
            ):
                self.verify_fixture()

    def test_no_signed_release_key_or_checksum_file_is_denied(self):
        for field in ("signing_key", "sha256sums", "detached_signature"):
            with self.subTest(field=field), self.assertRaises(
                CoreReleaseSignatureError
            ):
                self.verify_fixture(**{field: self.root / "missing"})

    def test_oversized_signature_key_and_checksum_files_are_denied(self):
        for field, target, size in (
            ("signing_key", self.key, 32769),
            ("sha256sums", self.sum, 131073),
            ("detached_signature", self.sig, 16385),
        ):
            with self.subTest(field=field):
                target.write_bytes(b"A" * size)
                with self.assertRaisesRegex(
                    CoreReleaseSignatureError, "^CORE_RELEASE_FILE_DENIED$"
                ):
                    self.verify_fixture()
                # Restore other fixtures to make each subtest isolated.
                target.write_bytes(b"SYNTHETIC_FILE")

    def test_symlink_key_and_signature_rejected(self):
        for field, target in (("signing_key", self.key),
                              ("detached_signature", self.sig)):
            link = self.root / (field + ".link")
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                continue
            with self.subTest(field=field), self.assertRaisesRegex(
                CoreReleaseSignatureError, "^CORE_RELEASE_FILE_DENIED$"
            ):
                self.verify_fixture(**{field: link})

    def test_no_wallet_keys_addresses_or_raw_key_material_in_result(self):
        with patch.object(mod, "_run_gpg", side_effect=self.valid_results()):
            r = self.verify_fixture()
        display = repr(r)
        self.assertNotIn(self.sha, display)
        self.assertNotIn("SYNTHETIC", display)
        with self.assertRaises(FrozenInstanceError):
            r.mainnet_allowed = True
        for name in ("core_execution_allowed", "mainnet_allowed",
                     "real_wallet_allowed", "extracted_binary_verified",
                     "execution_identity_bound", "signing_fingerprint", "status"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                replace(r, **{name: True})
        for name in ("seed", "private_key", "wallet", "rpc", "binary_path"):
            self.assertFalse(hasattr(r, name))

    def test_gpg_invocation_never_uses_shell_or_user_gnupghome(self):
        home = self.root / "empty-gnupg"
        home.mkdir()
        class Process:
            returncode = 0
            stdout = b"[GNUPG:] VALIDSIG TEST"
        with patch.object(mod.subprocess, "run", return_value=Process()) as proc, \
             patch.dict(os.environ, {
                 "GNUPGHOME": "PRIVATE_HOME",
                 "LD_PRELOAD": "MALICIOUS_PRELOAD",
                 "WAM_RPC_PASSWORD": "SECRET",
             }):
            mod._run_gpg(self.gpg, home, ("--version",))
            call = proc.call_args
            self.assertFalse(call.kwargs["shell"])
            self.assertEqual(call.kwargs["env"]["GNUPGHOME"], str(home))
            self.assertNotIn("LD_PRELOAD", call.kwargs["env"])
            self.assertNotIn("WAM_RPC_PASSWORD", call.kwargs["env"])
            self.assertEqual(call.kwargs["cwd"], home)

    def test_missing_gpg_executable_os_error_is_redacted(self):
        with patch.object(mod.subprocess, "run",
                          side_effect=OSError("SECRET_PATH_AND_USER")):
            with self.assertRaisesRegex(
                CoreReleaseSignatureError, "^CORE_RELEASE_GPG_UNAVAILABLE$"
            ):
                mod._run_gpg(self.gpg, self.root, ("--version",))


if __name__ == "__main__":
    unittest.main()
