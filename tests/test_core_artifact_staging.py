"""Core staging threat-boundary tests: only synthetic files, never Core launch."""
from dataclasses import FrozenInstanceError, replace
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node.core_artifact_staging import (
    CoreArtifactStagingError, CoreArtifactStagingEvidence,
    stage_untrusted_core_artifact,
)


class CoreArtifactStagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-core-artifact-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.candidate = self.root / "NOT-WAM-CORE.bin"
        self.candidate.write_bytes(b"synthetic nonexecutable WAM fixture" * 8)
        self.digest = hashlib.sha256(self.candidate.read_bytes()).hexdigest()

    def test_verified_synthetic_snapshot_never_authorizes_core_execution(self):
        with patch.object(subprocess, "Popen",
                          side_effect=AssertionError("NO_CORE_EXEC")) as popen:
            with stage_untrusted_core_artifact(self.candidate, self.digest) as x:
                self.assertEqual(x.status, "OFFLINE_STAGED_UNTRUSTED")
                self.assertEqual(x.byte_count, self.candidate.stat().st_size)
                self.assertEqual(hashlib.sha256(x.snapshot_path.read_bytes()).hexdigest(),
                                 self.digest)
                self.assertFalse(any((x.core_execution_allowed, x.mainnet_allowed,
                                      x.execution_identity_bound, x.publisher_verified,
                                      x.wallet_enabled)))
                self.assertNotEqual(x.snapshot_path, self.candidate)
                self.assertEqual(x.snapshot_path.suffix, ".dat")
                stage_path = x.snapshot_path
            self.assertFalse(stage_path.exists())
            popen.assert_not_called()

    def test_mainnet_testnet_and_untyped_networks_rejected(self):
        for network in ("main", "mainnet", "testnet", "signet", "", None, True, 1):
            with self.subTest(network=network), self.assertRaisesRegex(
                CoreArtifactStagingError, "^CORE_STAGE_NETWORK_DENIED$"
            ):
                with stage_untrusted_core_artifact(
                    self.candidate, self.digest, network=network
                ):
                    self.fail("Unexpected stage")

    def test_malformed_digest_denied(self):
        for sha in (None, True, "", "f" * 63, "G" * 64, self.digest.upper(), 12):
            with self.subTest(value=sha), self.assertRaisesRegex(
                CoreArtifactStagingError, "^CORE_STAGE_DIGEST_DENIED$"
            ):
                with stage_untrusted_core_artifact(self.candidate, sha):
                    self.fail("Unexpected stage")

    def test_wrong_but_wellformed_sha_is_not_publisher_evidence(self):
        with self.assertRaisesRegex(
            CoreArtifactStagingError, "^CORE_STAGE_DIGEST_MISMATCH$"
        ):
            with stage_untrusted_core_artifact(self.candidate, "0" * 64):
                self.fail("Unexpected digest acceptance")

    def test_directory_and_missing_path_fail_closed(self):
        for x in (self.root, self.root / "missing"):
            with self.subTest(path=x), self.assertRaises(CoreArtifactStagingError):
                with stage_untrusted_core_artifact(x, self.digest):
                    self.fail("Unexpected stage")

    def test_symlink_rejected(self):
        link = self.root / "symlink"
        try:
            link.symlink_to(self.candidate)
        except (OSError, NotImplementedError):
            return
        with self.assertRaisesRegex(
            CoreArtifactStagingError, "^CORE_STAGE_SOURCE_DENIED$"
        ):
            with stage_untrusted_core_artifact(link, self.digest):
                self.fail("Unexpected symlink")

    def test_multiple_hardlinks_denied(self):
        other = self.root / "same-inode"
        try:
            os.link(self.candidate, other)
        except (OSError, NotImplementedError):
            return
        with self.assertRaisesRegex(
            CoreArtifactStagingError, "^CORE_STAGE_SOURCE_DENIED$"
        ):
            with stage_untrusted_core_artifact(self.candidate, self.digest):
                self.fail("Unexpected hardlink")

    def test_empty_candidate_denied(self):
        self.candidate.write_bytes(b"")
        with self.assertRaisesRegex(
            CoreArtifactStagingError, "^CORE_STAGE_SIZE_DENIED$"
        ):
            with stage_untrusted_core_artifact(self.candidate, hashlib.sha256(b"").hexdigest()):
                self.fail("Unexpected empty snapshot")

    def test_size_bound_before_read(self):
        from wam_privacy_wallet.node import core_artifact_staging as module
        with patch.object(module, "_MAX_BYTES", 7):
            with self.assertRaisesRegex(
                CoreArtifactStagingError, "^CORE_STAGE_SIZE_DENIED$"
            ):
                with stage_untrusted_core_artifact(self.candidate, self.digest):
                    self.fail("Unexpected overbound snapshot")

    def test_descriptor_path_identity_swap_rejected(self):
        from wam_privacy_wallet.node import core_artifact_staging as module
        with patch.object(module, "_same_stat", return_value=False):
            with self.assertRaisesRegex(
                CoreArtifactStagingError, "^CORE_STAGE_SOURCE_CHANGED$"
            ):
                with stage_untrusted_core_artifact(self.candidate, self.digest):
                    self.fail("Unexpected descriptor acceptance")

    def test_postcopy_metadata_race_rejected(self):
        from wam_privacy_wallet.node import core_artifact_staging as module
        with patch.object(module, "_same_stat", side_effect=[True, False]):
            with self.assertRaisesRegex(
                CoreArtifactStagingError, "^CORE_STAGE_SOURCE_CHANGED$"
            ):
                with stage_untrusted_core_artifact(self.candidate, self.digest):
                    self.fail("Unexpected post-copy acceptance")

    def test_staged_file_has_no_posix_execute_permissions(self):
        with stage_untrusted_core_artifact(self.candidate, self.digest) as x:
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(x.snapshot_path.stat().st_mode) & 0o111, 0)
            self.assertEqual(x.snapshot_path.name, "untrusted-core-bytes.dat")

    def test_secret_path_and_hash_not_logged_in_repr(self):
        with stage_untrusted_core_artifact(self.candidate, self.digest) as x:
            display = repr(x)
            self.assertNotIn(str(x.snapshot_path), display)
            self.assertNotIn(str(self.candidate), display)
            self.assertNotIn(self.digest, display)
            self.assertNotIn("synthetic nonexecutable", display)

    def test_approval_flags_are_nonconstructor_nonreplaceable(self):
        with stage_untrusted_core_artifact(self.candidate, self.digest) as x:
            with self.assertRaises(FrozenInstanceError):
                x.core_execution_allowed = True
            for key in ("publisher_verified", "core_execution_allowed",
                        "execution_identity_bound", "mainnet_allowed",
                        "wallet_enabled", "status"):
                with self.subTest(field=key), self.assertRaises(ValueError):
                    replace(x, **{key: True})
            with self.assertRaises(TypeError):
                CoreArtifactStagingEvidence(
                    x.snapshot_path, self.digest, x.byte_count,
                    core_execution_allowed=True,
                )

    def test_unsupported_object_types_are_redacted(self):
        for source in (None, False, True, {}, [], 42):
            with self.subTest(typ=type(source).__name__), self.assertRaisesRegex(
                CoreArtifactStagingError, "^CORE_STAGE_SOURCE_DENIED$"
            ):
                with stage_untrusted_core_artifact(source, self.digest):
                    self.fail("Unexpected source")

    def test_nothing_is_left_in_operator_workspace_after_stage(self):
        first = set(self.root.iterdir())
        with stage_untrusted_core_artifact(self.candidate, self.digest) as x:
            self.assertFalse(x.snapshot_path.is_relative_to(self.root))
        self.assertEqual(set(self.root.iterdir()), first)


if __name__ == "__main__":
    unittest.main()
