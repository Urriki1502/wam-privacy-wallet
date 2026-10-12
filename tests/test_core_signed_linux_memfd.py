"""Nonexecuting signed-archive -> real Linux sealed-memfd contract regressions.

Synthetic locally signed *claims* are mocked to exercise the byte pipeline;
only the separate official-release workflow provides actual GnuPG evidence.
"""
from __future__ import annotations

import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node import core_signed_linux_memfd as bridge
from tools import verify_core_release_sealed as cli
from wam_privacy_wallet.node.core_archive_inventory import CoreArchiveInventory
from wam_privacy_wallet.node.core_signed_release import (
    CoreReleaseSignatureError, SignedDistributionEvidence,
)

NAME = "wam-coin-v0.1.11-x86_64-linux-gnu.tar.gz"
ENTRY = "wam-coin-v0.1.11/bin/wamd"


class SignedLinuxCoreMemfdTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="wam-signed-member-")
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)
        self.node_bytes = b"synthetic-no-execution-test-binary-payload"
        self.node_hash = hashlib.sha256(self.node_bytes).hexdigest()
        self.archive = root / NAME
        with tarfile.open(self.archive, mode="w:gz") as tar:
            item = tarfile.TarInfo(ENTRY)
            item.size = len(self.node_bytes)
            tar.addfile(item, io.BytesIO(self.node_bytes))
        self.archive_hash = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.key = root / "key.asc"
        self.checksums = root / "sums"
        self.signature = root / "sums.asc"
        self.gpg = root / "gpg"
        self.inputs = dict(
            archive=self.archive, key=self.key, checksums=self.checksums,
            signature=self.signature, gpg=self.gpg,
        )
        self.signed = SignedDistributionEvidence(NAME, self.archive_hash)
        self.inventory = CoreArchiveInventory(
            NAME, 1, 1, len(self.node_bytes), ENTRY,
            len(self.node_bytes), self.node_hash,
        )

    def _patch_verified(self):
        return (
            patch.object(bridge, "_ARCHIVE_SHA", self.archive_hash),
            patch.object(bridge, "_MEMBER_SHA", self.node_hash),
            patch.object(bridge, "verify_wam_signed_distribution",
                         return_value=self.signed),
            patch.object(bridge, "inspect_wam_core_archive",
                         return_value=self.inventory),
        )

    def _supported(self):
        return (sys.platform == "linux" and bridge.fcntl is not None
                and hasattr(os, "memfd_create"))

    def _denies_platform(self):
        with self.assertRaisesRegex(
            bridge.SignedNodeSealError, "^CORE_SIGNED_SEAL_PLATFORM_DENIED$",
        ):
            with bridge.sealed_signed_linux_wamd(**self.inputs):
                self.fail("must deny unsupported platform")

    def test_real_kernel_memfd_has_no_execute_bits_and_signed_byte_hash(self):
        if not self._supported():
            self._denies_platform()
            return
        a, b, c, d = self._patch_verified()
        with a, b, c as verify, d as inspect:
            with bridge.sealed_signed_linux_wamd(**self.inputs) as review:
                self.assertTrue(review.audit())
                self.assertEqual(review.evidence.sha256, self.node_hash)
                self.assertFalse(os.fstat(review._descriptor).st_mode & 0o111)
                self.assertEqual(review.evidence.byte_count, len(self.node_bytes))
                self.assertFalse(review.evidence.core_execution_allowed)
        verify.assert_called_once()
        inspect.assert_called_once()

    def test_signed_memfd_kernel_exec_seal_blocks_x_bit_change(self):
        if not self._supported():
            self._denies_platform()
            return
        a, b, c, d = self._patch_verified()
        with a, b, c, d:
            with bridge.sealed_signed_linux_wamd(**self.inputs) as review:
                fd = review._descriptor
                self.assertEqual(
                    bridge.fcntl.fcntl(fd, bridge.fcntl.F_GET_SEALS)
                    & bridge._F_SEAL_EXEC,
                    bridge._F_SEAL_EXEC,
                )
                self.assertEqual(os.fstat(fd).st_mode & 0o111, 0)
                with self.assertRaises(OSError):
                    os.fchmod(fd, os.fstat(fd).st_mode | stat.S_IXUSR)
                self.assertTrue(review.audit())
                self.assertIs(review.evidence.core_execution_allowed, False)

    def test_absent_exec_seal_denies_before_signed_member_stream(self):
        if not self._supported():
            self._denies_platform()
            return
        a, b, c, d = self._patch_verified()
        # Model a kernel or API that has not applied the required EXEC seal.
        # Never trust only MFD_NOEXEC_SEAL flag supplied at creation.
        with a, b, c, d, patch.object(bridge, "_F_SEAL_EXEC", 0x40000000), \
             patch.object(bridge.tarfile, "open",
                          side_effect=AssertionError("MUST_NOT_STREAM")):
            with self.assertRaisesRegex(
                bridge.SignedNodeSealError, "^CORE_SIGNED_SEAL_NOEXEC_DENIED$",
            ):
                with bridge.sealed_signed_linux_wamd(**self.inputs):
                    self.fail("unsealed executable inode cannot be reviewed")

    def test_kernel_prohibits_post_seal_write_and_truncation(self):
        if not self._supported():
            self._denies_platform()
            return
        a, b, c, d = self._patch_verified()
        with a, b, c, d, bridge.sealed_signed_linux_wamd(**self.inputs) as review:
            with self.assertRaises(OSError):
                os.write(review._descriptor, b"mutate")
            with self.assertRaises(OSError):
                os.ftruncate(review._descriptor, 0)
            self.assertTrue(review.audit())

    def test_sealed_fd_closes_after_review_context(self):
        if not self._supported():
            self._denies_platform()
            return
        a, b, c, d = self._patch_verified()
        with a, b, c, d, bridge.sealed_signed_linux_wamd(**self.inputs) as review:
            self.assertTrue(review.audit())
        with self.assertRaises(bridge.LinuxCoreSealError):
            review.audit()

    def test_signed_review_closed_receipt_cannot_revive_after_fd_reuse(self):
        if not self._supported():
            self._denies_platform()
            return
        a, b, c, d = self._patch_verified()
        with a, b, c, d:
            with bridge.sealed_signed_linux_wamd(**self.inputs) as previous:
                old_number = previous._descriptor
                self.assertTrue(previous.audit())
            self.assertEqual(previous._descriptor, -1)
            with bridge.sealed_signed_linux_wamd(**self.inputs) as replacement:
                reused_directly = replacement._descriptor == old_number
                if not reused_directly:
                    os.dup2(replacement._descriptor, old_number)
                try:
                    self.assertTrue(replacement.audit())
                    with self.assertRaisesRegex(
                        bridge.LinuxCoreSealError, "^CORE_SEAL_CLOSED$",
                    ):
                        previous.audit()
                finally:
                    if not reused_directly:
                        os.close(old_number)

    def test_never_opens_real_core_subprocess_or_popen(self):
        if not self._supported():
            self._denies_platform()
            return
        a, b, c, d = self._patch_verified()
        with a, b, c, d, patch.object(
            subprocess, "Popen", side_effect=AssertionError("NO_WAMD_PROCESS"),
        ):
            with bridge.sealed_signed_linux_wamd(**self.inputs) as review:
                self.assertTrue(review.audit())
                self.assertIs(review.evidence.execution_identity_bound, False)

    def test_signature_error_fails_before_inventory_or_memfd(self):
        if not self._supported():
            self._denies_platform()
            return
        with patch.object(
            bridge, "verify_wam_signed_distribution",
            side_effect=CoreReleaseSignatureError("CORE_RELEASE_SIGNATURE_DENIED"),
        ), patch.object(
            bridge, "inspect_wam_core_archive",
            side_effect=AssertionError("MUST_NOT_INSPECT"),
        ), self.assertRaisesRegex(
            bridge.SignedNodeSealError, "^CORE_SIGNED_SEAL_DENIED$",
        ):
            with bridge.sealed_signed_linux_wamd(**self.inputs):
                self.fail("forged signature")

    def test_unsigned_archive_hash_incompatible_with_pinned_release(self):
        if not self._supported():
            self._denies_platform()
            return
        with patch.object(bridge, "verify_wam_signed_distribution",
                          return_value=self.signed), patch.object(
            bridge, "inspect_wam_core_archive",
            side_effect=AssertionError("MUST_NOT_INSPECT"),
        ), self.assertRaisesRegex(
            bridge.SignedNodeSealError, "^CORE_SIGNED_SEAL_RELEASE_DENIED$",
        ):
            with bridge.sealed_signed_linux_wamd(**self.inputs):
                self.fail("caller provided checksum is not release pin")

    def test_node_member_hash_mismatch_rejected_before_fd_write(self):
        if not self._supported():
            self._denies_platform()
            return
        a, b, c, d = self._patch_verified()
        altered = CoreArchiveInventory(
            NAME, 1, 1, len(self.node_bytes), ENTRY,
            len(self.node_bytes), "f" * 64,
        )
        with a, b, c, d, patch.object(
            bridge, "inspect_wam_core_archive", return_value=altered,
        ), self.assertRaisesRegex(
            bridge.SignedNodeSealError, "^CORE_SIGNED_SEAL_MEMBER_DENIED$",
        ):
            with bridge.sealed_signed_linux_wamd(**self.inputs):
                self.fail("forged node digest")

    def test_wrong_asset_and_relative_inputs_denied_before_signature(self):
        with patch.object(
            bridge, "verify_wam_signed_distribution",
            side_effect=AssertionError("NO_CRYPTO"),
        ):
            for candidate in (Path("/tmp/wallet.dat"), Path("relative.tar.gz")):
                with self.subTest(candidate=str(candidate)), self.assertRaises(
                    bridge.SignedNodeSealError,
                ):
                    with bridge.sealed_signed_linux_wamd(
                        **dict(self.inputs, archive=candidate),
                    ):
                        self.fail("untrusted path")

    def test_non_linux_rejects_without_attempted_stage_or_gpg(self):
        with patch.object(bridge.sys, "platform", "darwin"), patch.object(
            bridge, "verify_wam_signed_distribution",
            side_effect=AssertionError("MUST_NOT_GPG"),
        ):
            self._denies_platform()

    def test_report_authorities_remain_permanently_false(self):
        if not self._supported():
            self._denies_platform()
            return
        a, b, c, d = self._patch_verified()
        with a, b, c, d, bridge.sealed_signed_linux_wamd(**self.inputs) as review:
            proof = review.evidence
            for name in (
                "publisher_authenticated", "execution_identity_bound",
                "core_execution_allowed", "real_wallet_allowed",
                "mainnet_allowed", "genuine_two_node_qualified",
            ):
                self.assertIs(getattr(proof, name), False)
            self.assertNotIn(str(self.archive), repr(proof))



class SignedMemberCliTests(unittest.TestCase):
    def test_cli_denies_relative_archive_before_fetch(self):
        with patch.object(
            cli, "official_release_metadata", side_effect=AssertionError("NO_FETCH"),
        ):
            with self.assertRaises(CoreReleaseSignatureError):
                cli.verify_signed_linux_memfd(archive="not-absolute.tar.gz", gpg="/bin/gpg")

    def test_cli_reports_only_redacted_failure(self):
        with patch.object(
            cli, "official_release_metadata",
            side_effect=bridge.SignedNodeSealError("CORE_SIGNED_SEAL_DENIED"),
        ):
            stderr, stdout = io.StringIO(), io.StringIO()
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                status = cli.main(["--archive", str(Path.cwd() / "review-release.tar.gz"),
                                   "--gpg", str(Path.cwd() / "review-gpg")])
            self.assertEqual(status, 2)
            self.assertEqual(stderr.getvalue().strip(), "CORE_SIGNED_SEAL_DENIED")
            self.assertEqual(stdout.getvalue(), "")

    def test_cli_non_authority_json(self):
        receipt = {
            "status": "OFFICIAL_SIGNED_WAMD_LINUX_NOEXEC_MEMFD_REVIEW",
            "kernel_seals_verified": True,
            "kernel_noexec_enforced": True,
            "executed_core": False,
            "real_regtest_qualified": False,
            "core_execution_allowed": False,
            "execution_identity_bound": False,
            "mainnet_allowed": False,
        }
        stdout = io.StringIO()
        with patch.object(cli, "verify_signed_linux_memfd", return_value=receipt):
            with contextlib.redirect_stdout(stdout):
                status = cli.main(["--archive", "/tmp/release.tar.gz", "--gpg", "/bin/gpg"])
        self.assertEqual(status, 0)
        parsed = json.loads(stdout.getvalue())
        self.assertIs(parsed["executed_core"], False)
        self.assertIs(parsed["core_execution_allowed"], False)
        self.assertNotIn("/tmp/", stdout.getvalue())

if __name__ == "__main__":
    unittest.main()
