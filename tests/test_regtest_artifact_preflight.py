"""G1-00 preflight: synthetic files, no external nodes or production keys."""
from __future__ import annotations

import contextlib
from dataclasses import FrozenInstanceError, replace
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.check_regtest_artifact_preflight import (
    ArtifactPreflightError, LocalHashEvidence, evaluate_local_binary, main,
)


class RegtestBinaryArtifactPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="g1-preflight-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.binary = Path(self.temp.name) / "synthetic_not_core.bin"
        self.binary.write_bytes(b"synthetic-test-fixture-not-a-real-core-daemon\n")
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()

    def test_matching_synthetic_file_never_counts_as_real_node(self):
        with patch("subprocess.Popen", side_effect=AssertionError("MUST NOT EXECUTE")):
            result = evaluate_local_binary(str(self.binary), self.digest)
        self.assertEqual(result.sha256, self.digest)
        self.assertEqual(result.profile_network, "regtest")
        self.assertEqual(result.status, "LOCAL_SHA256_MATCH_ONLY")
        self.assertFalse(result.real_regtest_qualified)
        self.assertFalse(result.publisher_identity_verified)
        self.assertFalse(result.binary_source_equivalence_verified)
        self.assertFalse(result.execution_allowed)
        self.assertFalse(result.release_allowed)
        self.assertNotIn(str(self.binary), repr(result))
        with self.assertRaises(FrozenInstanceError):
            result.release_allowed = True

    def test_preflight_constructor_cannot_forge_qualification(self):
        # The offline evidence object cannot be initialized with elevated
        # status or authority fields, even if the SHA matches.
        claims = {
            "profile_network": "main",
            "status": "PUBLISHER_VERIFIED",
            "real_regtest_qualified": True,
            "publisher_identity_verified": True,
            "binary_source_equivalence_verified": True,
            "execution_allowed": True,
            "release_allowed": True,
        }
        for field_name, forged_value in claims.items():
            with self.subTest(field=field_name):
                with self.assertRaises(TypeError):
                    LocalHashEvidence(self.digest, **{field_name: forged_value})
        evidence = LocalHashEvidence(self.digest)
        self.assertIs(evidence.execution_allowed, False)
        self.assertIs(evidence.binary_source_equivalence_verified, False)

    def test_direct_evidence_digest_must_be_canonical_not_attestation(self):
        for invalid in (None, True, b"0" * 64, "", "f" * 63,
                        "F" * 64, "g" * 64, "f" * 64 + "\\n"):
            with self.subTest(value=repr(invalid)):
                with self.assertRaisesRegex(
                    ValueError, "^G1_LOCAL_EVIDENCE_DIGEST_INVALID$"
                ):
                    LocalHashEvidence(invalid)
        direct = LocalHashEvidence(self.digest)
        self.assertEqual(direct.sha256, self.digest)
        self.assertFalse(direct.execution_allowed)
        self.assertFalse(direct.publisher_identity_verified)
        with self.assertRaisesRegex(
            ValueError, "^G1_LOCAL_EVIDENCE_DIGEST_INVALID$"
        ):
            replace(direct, sha256="invalid")

    def test_preflight_replace_cannot_escalate_qualification(self):
        evidence = evaluate_local_binary(self.binary, self.digest)
        for field_name, forged_value in (
            ("profile_network", "main"),
            ("status", "RELEASE_READY"),
            ("real_regtest_qualified", True),
            ("publisher_identity_verified", True),
            ("binary_source_equivalence_verified", True),
            ("execution_allowed", True),
            ("release_allowed", True),
        ):
            with self.subTest(field=field_name):
                with self.assertRaises(ValueError):
                    replace(evidence, **{field_name: forged_value})
        for name in ("binary_path", "rpc_credentials", "wallet_key", "subprocess"):
            self.assertFalse(hasattr(evidence, name))

    def test_wrong_hash_and_malformed_hash_are_denied(self):
        cases = (
            ("0" * 64, "G1_CORE_SHA256_MISMATCH"),
            ("bad", "G1_CORE_SHA256_INVALID"),
            ("A" * 64, "G1_CORE_SHA256_INVALID"),
            ("", "G1_CORE_SHA256_INVALID"),
            (None, "G1_SHA256_REQUIRED"),
            (True, "G1_SHA256_REQUIRED"),
        )
        for digest, expected in cases:
            with self.subTest(digest=digest):
                with self.assertRaisesRegex(ArtifactPreflightError, "^" + expected + "$"):
                    evaluate_local_binary(self.binary, digest)

    def test_path_is_explicit_absolute_and_no_auto_discovery(self):
        cases = (
            ("./wamd", "G1_ABSOLUTE_PATH_REQUIRED"),
            ("wamd", "G1_ABSOLUTE_PATH_REQUIRED"),
            ("", "G1_BINARY_PATH_REQUIRED"),
            (None, "G1_BINARY_PATH_REQUIRED"),
            (17, "G1_BINARY_PATH_REQUIRED"),
            (True, "G1_BINARY_PATH_REQUIRED"),
            (b"/bin/wamd", "G1_BINARY_PATH_REQUIRED"),
        )
        for value, expected in cases:
            with self.subTest(path=repr(value)):
                with self.assertRaisesRegex(ArtifactPreflightError, "^" + expected + "$"):
                    evaluate_local_binary(value, self.digest)

    def test_directories_and_missing_files_are_rejected(self):
        for item in (Path(self.temp.name), Path(self.temp.name) / "missing-wamd"):
            with self.subTest(item=item.name):
                with self.assertRaises(ArtifactPreflightError):
                    evaluate_local_binary(item, self.digest)

    def test_symlinks_are_rejected_even_when_digest_matches(self):
        link = Path(self.temp.name) / "alias-wamd"
        try:
            link.symlink_to(self.binary)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation not supported by this OS/user")
        with self.assertRaises(ArtifactPreflightError):
            evaluate_local_binary(link, self.digest)

    def test_cli_reports_digest_only_and_cannot_claim_release(self):
        buffer = io.StringIO()
        with patch("subprocess.Popen", side_effect=AssertionError("MUST NOT EXECUTE")):
            with contextlib.redirect_stdout(buffer):
                code = main(["--binary", str(self.binary), "--sha256", self.digest])
        self.assertEqual(code, 0)
        data = json.loads(buffer.getvalue())
        self.assertEqual(data["status"], "LOCAL_SHA256_MATCH_ONLY")
        self.assertIs(data["real_regtest_qualified"], False)
        self.assertIs(data["publisher_identity_verified"], False)
        self.assertIs(data["binary_source_equivalence_verified"], False)
        self.assertIs(data["execution_allowed"], False)
        self.assertIs(data["release_allowed"], False)
        self.assertNotIn(str(self.binary), buffer.getvalue())

    def test_missing_provenance_manifest_denied(self):
        with patch("tools.check_regtest_artifact_preflight.load_core_manifest",
                   side_effect=OSError("should never leak filesystem details")):
            with self.assertRaisesRegex(ArtifactPreflightError, "^G1_PINNED_PROFILE_REJECTED$"):
                evaluate_local_binary(self.binary, self.digest)


if __name__ == "__main__":
    unittest.main()
