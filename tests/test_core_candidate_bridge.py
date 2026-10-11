"""Cross-boundary untrusted WAM Core candidate / staged binary regressions."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node import core_candidate_bridge as bridge
from wam_privacy_wallet.node.core_candidate_bridge import (
    CoreCandidateBridgeError, review_local_core_candidate,
)
from wam_privacy_wallet.node.provenance_intake import (
    SOURCE_REPOSITORY, REVIEWED_SOURCE_COMMIT,
)


class CoreCandidateBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="candidate-bridge-fixture-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.file = self.root / "NOT_WAM_CORE"
        self.file.write_bytes(b"synthetic bytes no executable, wallet or node")
        self.digest = hashlib.sha256(self.file.read_bytes()).hexdigest()

    def candidate(self, **overrides):
        data = {
            "schema": "wam-core-candidate-intake/v1",
            "repository": SOURCE_REPOSITORY,
            "reviewed_source_commit": REVIEWED_SOURCE_COMMIT,
            "claimed_release": "v0.1.11",
            "platform": bridge._native_runtime_platform(),
            "binary_sha256": self.digest,
            "publisher_proof": "NOT_VERIFIED",
            "real_regtest_qualified": False,
            "release_allowed": False,
        }
        data.update(overrides)
        return data

    def test_staged_candidate_requires_identical_host_and_bytes(self):
        metadata = self.candidate()
        self.assertIsNotNone(metadata["platform"])
        with review_local_core_candidate(metadata, self.file) as (candidate, stage):
            self.assertEqual(candidate.binary_sha256, self.digest)
            self.assertEqual(candidate.platform, metadata["platform"])
            self.assertEqual(stage.sha256, self.digest)
            self.assertEqual(stage.status, "OFFLINE_STAGED_UNTRUSTED")
            self.assertTrue(stage.snapshot_path.is_file())
            self.assertFalse(any((
                candidate.execution_allowed, candidate.release_allowed,
                candidate.publisher_identity_verified, candidate.real_regtest_qualified,
                stage.publisher_verified, stage.core_execution_allowed,
                stage.execution_identity_bound, stage.mainnet_allowed,
            )))
            snapshot_path = stage.snapshot_path
        self.assertFalse(snapshot_path.exists())

    def test_matching_claimed_sha_does_not_assert_publisher_provenance(self):
        with review_local_core_candidate(self.candidate(), self.file) as result:
            candidate, stage = result
            self.assertEqual(candidate.status, "UNTRUSTED_CANDIDATE_REVIEW_ONLY")
            self.assertFalse(candidate.binary_source_equivalence_verified)
            self.assertFalse(stage.publisher_verified)

    def test_bad_schema_and_extra_approval_fields_denied_before_disk(self):
        for bad in (None, True, {}, {"schema": "faked"},
                    self.candidate(execution_allowed=True),
                    self.candidate(schema="v2"),
                    self.candidate(repository="attacker/repo")):
            with self.subTest(typ=type(bad).__name__), patch.object(
                bridge, "stage_untrusted_core_artifact",
                side_effect=AssertionError("DISK_READ_BEFORE_INTAKE"),
            ):
                with self.assertRaisesRegex(
                    CoreCandidateBridgeError, "^CORE_CANDIDATE_INTAKE_DENIED$"
                ):
                    with review_local_core_candidate(bad, self.file):
                        self.fail("Unexpected intake")

    def test_asserted_publisher_approval_is_denied(self):
        for update in (
            {"publisher_proof": "VERIFIED"},
            {"real_regtest_qualified": True},
            {"release_allowed": True},
        ):
            with self.subTest(update=update), self.assertRaisesRegex(
                CoreCandidateBridgeError, "^CORE_CANDIDATE_INTAKE_DENIED$"
            ):
                with review_local_core_candidate(self.candidate(**update), self.file):
                    self.fail("Accepted forged approval")

    def test_wrong_native_platform_is_denied_before_disk_read(self):
        actual = bridge._native_runtime_platform()
        alternate = "macos-arm64" if actual != "macos-arm64" else "linux-x64"
        with patch.object(bridge, "stage_untrusted_core_artifact",
                          side_effect=AssertionError("DISK_ACCESS_DENIED")):
            with self.assertRaisesRegex(
                CoreCandidateBridgeError, "^CORE_CANDIDATE_PLATFORM_MISMATCH$"
            ):
                with review_local_core_candidate(
                    self.candidate(platform=alternate), self.file,
                ):
                    self.fail("Invalid host platform accepted")

    def test_unsupported_host_denied_without_io(self):
        with patch.object(bridge, "_native_runtime_platform", return_value=None), \
             patch.object(bridge, "stage_untrusted_core_artifact",
                          side_effect=AssertionError("DISK_ACCESS_DENIED")):
            with self.assertRaisesRegex(
                CoreCandidateBridgeError, "^CORE_CANDIDATE_HOST_UNSUPPORTED$"
            ):
                with review_local_core_candidate(
                    self.candidate(platform="linux-x64"), self.file,
                ):
                    self.fail("Unknown platform allowed")

    def test_wrong_but_wellformed_digest_denied_even_with_matching_metadata(self):
        with self.assertRaisesRegex(
            CoreCandidateBridgeError, "^CORE_CANDIDATE_STAGING_DENIED$"
        ):
            with review_local_core_candidate(
                self.candidate(binary_sha256="0" * 64), self.file,
            ):
                self.fail("Accepted digest mismatch")

    def test_missing_binary_or_symlink_denied(self):
        missing = self.root / "missing"
        link = self.root / "link"
        try:
            link.symlink_to(self.file)
        except (OSError, NotImplementedError):
            link = missing
        for source in (missing, link):
            with self.subTest(source=source), self.assertRaisesRegex(
                CoreCandidateBridgeError, "^CORE_CANDIDATE_STAGING_DENIED$"
            ):
                with review_local_core_candidate(self.candidate(), source):
                    self.fail("Unexpected binary source")

    def test_staged_mutation_on_context_exit_is_denied_with_redacted_code(self):
        with self.assertRaisesRegex(
            CoreCandidateBridgeError, "^CORE_CANDIDATE_STAGING_DENIED$"
        ):
            with review_local_core_candidate(self.candidate(), self.file) as (_, x):
                os.chmod(x.snapshot_path, 0o600)
                x.snapshot_path.write_bytes(b"x" * x.byte_count)

    def test_no_subprocess_socket_or_live_wam_core_usage(self):
        with patch.object(subprocess, "Popen",
                          side_effect=AssertionError("REAL_CORE_FORBIDDEN")), \
             patch.object(socket, "socket",
                          side_effect=AssertionError("SOCKET_FORBIDDEN")):
            with review_local_core_candidate(self.candidate(), self.file) as (p, x):
                self.assertFalse(p.execution_allowed)
                self.assertFalse(x.core_execution_allowed)

    def test_windows_process_width_native_classifier_is_explicit(self):
        with patch.object(bridge.sys, "platform", "win32"), \
             patch.object(bridge.struct, "calcsize", return_value=4), \
             patch.object(bridge.platform, "machine", return_value="AMD64"):
            self.assertEqual(bridge._native_runtime_platform(), "windows-x86")
        with patch.object(bridge.sys, "platform", "win32"), \
             patch.object(bridge.struct, "calcsize", return_value=8), \
             patch.object(bridge.platform, "machine", return_value="AMD64"):
            self.assertEqual(bridge._native_runtime_platform(), "windows-x64")

    def test_macos_and_linux_machine_mapping_is_explicit(self):
        for sysname, machine, width, expected in (
            ("darwin", "arm64", 8, "macos-arm64"),
            ("darwin", "x86_64", 8, "macos-x64"),
            ("linux", "aarch64", 8, "linux-arm64"),
            ("linux", "x86_64", 8, "linux-x64"),
            ("linux", "x86_64", 4, None),
            ("darwin", "x86_64", 4, None),
            ("plan9", "x86_64", 8, None),
        ):
            with self.subTest(sysname=sysname, machine=machine), \
                 patch.object(bridge.sys, "platform", sysname), \
                 patch.object(bridge.struct, "calcsize", return_value=width), \
                 patch.object(bridge.platform, "machine", return_value=machine):
                self.assertEqual(bridge._native_runtime_platform(), expected)

    def test_no_caller_override_of_native_platform(self):
        # Contextmanager generator validates its signature on __enter__.
        with self.assertRaises(TypeError):
            with review_local_core_candidate(
                self.candidate(), self.file, host_tag="linux-x64"
            ):
                self.fail("Host spoofing must never be accepted")

    def test_cleanup_on_exception_inside_review_context(self):
        with self.assertRaisesRegex(RuntimeError, "^SYNTHETIC_REVIEW_CANCEL$"):
            with review_local_core_candidate(self.candidate(), self.file) as (_, x):
                path = x.snapshot_path
                raise RuntimeError("SYNTHETIC_REVIEW_CANCEL")
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
