"""G1-00 preflight: synthetic files, no external nodes or production keys."""
from __future__ import annotations

import contextlib
from dataclasses import FrozenInstanceError
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.check_regtest_artifact_preflight import (
    ArtifactPreflightError, evaluate_local_binary, main,
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
        self.assertFalse(result.release_allowed)
        self.assertNotIn(str(self.binary), repr(result))
        with self.assertRaises(FrozenInstanceError):
            result.release_allowed = True

    def test_wrong_hash_and_malformed_hash_are_denied(self):
        for digest in ("0" * 64, "bad", "A" * 64, "", None, True):
            with self.subTest(digest=digest):
                with self.assertRaises(ArtifactPreflightError):
                    evaluate_local_binary(self.binary, digest)

    def test_path_is_explicit_absolute_and_no_auto_discovery(self):
        for value in ("./wamd", "wamd", "", None, 17, True, b"/bin/wamd"):
            with self.subTest(path=repr(value)):
                with self.assertRaises(ArtifactPreflightError):
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
        self.assertIs(data["release_allowed"], False)
        self.assertNotIn(str(self.binary), buffer.getvalue())

    def test_missing_provenance_manifest_denied(self):
        with patch("tools.check_regtest_artifact_preflight.load_core_manifest",
                   side_effect=OSError("should never leak filesystem details")):
            with self.assertRaisesRegex(ArtifactPreflightError, "^G1_PINNED_PROFILE_REJECTED$"):
                evaluate_local_binary(self.binary, self.digest)


if __name__ == "__main__":
    unittest.main()
