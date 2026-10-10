"""G1-02 provenance intake: offline adversarial tests (no binary/network)."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node.core_source_pin import load_core_manifest
from wam_privacy_wallet.node.provenance_intake import (
    ProvenanceIntakeError, REVIEWED_SOURCE_COMMIT, SOURCE_REPOSITORY,
    intake_core_artifact,
)


def candidate():
    return {
        "schema": "wam-core-candidate-intake/v1",
        "repository": SOURCE_REPOSITORY,
        "reviewed_source_commit": REVIEWED_SOURCE_COMMIT,
        "claimed_release": "v0.1.11",
        "platform": "linux-x64",
        "binary_sha256": "a" * 64,
        "publisher_proof": "NOT_VERIFIED",
        "real_regtest_qualified": False,
        "release_allowed": False,
    }


class CoreProvenanceIntakeTests(unittest.TestCase):
    def test_valid_shape_is_review_only_not_binary_attestation(self):
        output = intake_core_artifact(candidate())
        self.assertEqual(output.status, "UNTRUSTED_CANDIDATE_REVIEW_ONLY")
        self.assertEqual(output.binary_sha256, "a" * 64)
        for attr in ("publisher_identity_verified", "binary_source_equivalence_verified",
                     "real_regtest_qualified", "execution_allowed", "release_allowed"):
            self.assertIs(getattr(output, attr), False)

    def test_pinned_commit_must_match_readonly_core_source_manifest(self):
        pin = Path(__file__).resolve().parents[1] / "compat/wam_core_source_pin.json"
        manifest = load_core_manifest(pin)
        self.assertEqual(manifest["repository"], SOURCE_REPOSITORY)
        self.assertEqual(manifest["inspected_commit"], REVIEWED_SOURCE_COMMIT)

    def test_missing_or_extra_fields_fail_closed(self):
        for altered in (None, [], {}, "candidate", True, {"schema": 1}):
            with self.subTest(data=repr(altered)):
                with self.assertRaises(ProvenanceIntakeError):
                    intake_core_artifact(altered)
        for field in tuple(candidate()):
            changed = candidate()
            del changed[field]
            with self.subTest(missing=field), self.assertRaises(ProvenanceIntakeError):
                intake_core_artifact(changed)
        changed = candidate()
        changed["approved"] = True
        with self.assertRaises(ProvenanceIntakeError):
            intake_core_artifact(changed)

    def test_wrong_or_renamed_core_source_rejected(self):
        for repo, commit in (("other/core", REVIEWED_SOURCE_COMMIT),
                             (SOURCE_REPOSITORY, "b" * 40),
                             (SOURCE_REPOSITORY, "main"),
                             (SOURCE_REPOSITORY, REVIEWED_SOURCE_COMMIT.upper())):
            p = candidate()
            p["repository"], p["reviewed_source_commit"] = repo, commit
            with self.subTest(repo=repo), self.assertRaisesRegex(
                ProvenanceIntakeError, "^G1_PROVENANCE_SOURCE_REJECTED$"
            ):
                intake_core_artifact(p)

    def test_bad_digests_never_valid_even_if_other_fields_match(self):
        for sha in (None, 42, True, "", "A" * 64, "a" * 63, "a" * 65, "g" * 64):
            p = candidate()
            p["binary_sha256"] = sha
            with self.subTest(sha=repr(sha)), self.assertRaisesRegex(
                ProvenanceIntakeError, "^G1_PROVENANCE_SHA256_REJECTED$"
            ):
                intake_core_artifact(p)

    def test_claimed_release_format_is_bounded(self):
        for tag in (None, True, "", "main", "v1.2", "v1.2.3-rc1", "v1.2.3\n", "v"*200):
            p = candidate()
            p["claimed_release"] = tag
            with self.subTest(tag=repr(tag)), self.assertRaisesRegex(
                ProvenanceIntakeError, "^G1_PROVENANCE_RELEASE_REJECTED$"
            ):
                intake_core_artifact(p)

    def test_platform_allowlist_is_explicit_and_non_authorizing(self):
        for platform in ("linux-x64", "windows-x86", "windows-x64", "macos-arm64"):
            p = candidate()
            p["platform"] = platform
            self.assertFalse(intake_core_artifact(p).execution_allowed)
        for platform in ("mainnet", "browser", "unknown", 1, False):
            p = candidate()
            p["platform"] = platform
            with self.assertRaises(ProvenanceIntakeError):
                intake_core_artifact(p)

    def test_cannot_approve_signature_real_regtest_or_release(self):
        for field, value in (("publisher_proof", "VERIFIED"),
                             ("publisher_proof", True),
                             ("real_regtest_qualified", True),
                             ("release_allowed", True),
                             ("release_allowed", 0)):
            p = candidate()
            p[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                ProvenanceIntakeError, "^G1_PROVENANCE_AUTHORITY_REJECTED$"
            ):
                intake_core_artifact(p)

    def test_snapshot_is_frozen_and_holds_no_path_or_secret(self):
        record = intake_core_artifact(candidate())
        with self.assertRaises(FrozenInstanceError):
            record.release_allowed = True
        for name in ("credential", "path", "private_key", "rpc", "sign", "wallet"):
            self.assertFalse(hasattr(record, name))

    def test_intake_is_pure_no_file_socket_subprocess_or_requests(self):
        with patch("builtins.open", side_effect=AssertionError("NO_FILE")), \
             patch.object(socket, "socket", side_effect=AssertionError("NO_SOCKET")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("NO_SPAWN")):
            record = intake_core_artifact(candidate())
        self.assertEqual(record.status, "UNTRUSTED_CANDIDATE_REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
