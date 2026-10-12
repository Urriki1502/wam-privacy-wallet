"""Kernel-backed Linux memfd sealing tests; no Core execution or user wallet.

Linux tests use actual kernel seals; macOS/Windows assert explicit deny
rather than pretending a mocked POSIX fd qualifies those platforms.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node import core_linux_sealed_snapshot as seal


class LinuxKernelSealedRegtestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="core-seal-tests-")
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "synthetic-artifact.dat"
        self.bytes = b"synthetic non-executable WAM review fixture 0123456789"
        self.source.write_bytes(self.bytes)
        self.digest = hashlib.sha256(self.bytes).hexdigest()

    def _supported(self):
        return sys.platform == "linux" and seal.fcntl is not None and hasattr(os, "memfd_create")

    def _open(self, **kwargs):
        return seal.sealed_linux_regtest_review(
            self.source, self.digest, **kwargs,
        )

    def _unsupported(self):
        with self.assertRaisesRegex(
            seal.LinuxCoreSealError, "^CORE_SEAL_PLATFORM_DENIED$",
        ):
            with self._open():
                self.fail("unsupported host must not hold memfd")

    def test_real_kernel_sealing_on_linux_other_hosts_fail_closed(self):
        if not self._supported():
            self._unsupported()
            return
        with self._open() as review:
            self.assertTrue(review.audit())
            self.assertEqual(review.evidence.byte_count, len(self.bytes))
            self.assertTrue(review.evidence.seal_flags_verified)
            flags = seal.fcntl.fcntl(review._descriptor, seal.fcntl.F_GET_SEALS)
            self.assertEqual(flags & review._seals, review._seals)

    def test_no_operational_or_publisher_authority_even_when_sealed(self):
        if not self._supported():
            self._unsupported()
            return
        with self._open() as review:
            proof = review.evidence
            for flag in ("publisher_authenticated", "execution_identity_bound",
                         "core_execution_allowed", "real_wallet_allowed",
                         "mainnet_allowed", "genuine_two_node_qualified"):
                self.assertIs(getattr(proof, flag), False)
            self.assertNotIn(str(self.source), repr(proof))
            self.assertNotIn("descriptor=", repr(proof))

    def test_kernel_denies_write_after_seals(self):
        if not self._supported():
            self._unsupported()
            return
        with self._open() as review:
            with self.assertRaises(OSError):
                os.write(review._descriptor, b"tamper")
            self.assertTrue(review.audit())

    def test_kernel_denies_truncate_and_growth_after_seals(self):
        if not self._supported():
            self._unsupported()
            return
        with self._open() as review:
            with self.assertRaises(OSError):
                os.ftruncate(review._descriptor, 0)
            with self.assertRaises(OSError):
                os.ftruncate(review._descriptor, len(self.bytes) + 1)
            self.assertTrue(review.audit())

    def test_audit_after_context_closes_descriptor(self):
        if not self._supported():
            self._unsupported()
            return
        with self._open() as review:
            self.assertTrue(review.audit())
        self.assertEqual(review._descriptor, -1)
        with self.assertRaisesRegex(
            seal.LinuxCoreSealError, "^CORE_SEAL_CLOSED$",
        ):
            review.audit()

    def test_seal_receipt_denies_forged_zero_seal_mask(self):
        if not self._supported():
            self._unsupported()
            return
        with self._open() as review:
            with self.assertRaisesRegex(
                seal.LinuxCoreSealError, "^CORE_SEAL_REVIEW_DENIED$",
            ):
                seal.KernelSealedReview(
                    review._descriptor, self.digest, len(self.bytes), 0,
                )
            self.assertTrue(review.audit())

    def test_unsealed_kernel_fd_cannot_claim_verified_seals(self):
        if not self._supported():
            self._unsupported()
            return
        fd = os.memfd_create("synthetic-not-sealed", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            os.write(fd, self.bytes)
            required = (seal.fcntl.F_SEAL_WRITE | seal.fcntl.F_SEAL_GROW
                        | seal.fcntl.F_SEAL_SHRINK | seal.fcntl.F_SEAL_SEAL)
            with self.assertRaisesRegex(
                seal.LinuxCoreSealError, "^CORE_SEAL_CHANGED$",
            ):
                seal.KernelSealedReview(fd, self.digest, len(self.bytes), required)
        finally:
            os.close(fd)

    def test_closed_review_cannot_attach_to_reused_valid_sealed_fd(self):
        if not self._supported():
            self._unsupported()
            return
        with self._open() as original:
            closed_number = original._descriptor
            self.assertTrue(original.audit())
        self.assertEqual(original._descriptor, -1)
        # New kernel memfd has the SAME seals, size, and content. A stale
        # numeric fd must never make the old receipt valid again.
        with self._open() as replacement:
            reused_directly = replacement._descriptor == closed_number
            if not reused_directly:
                os.dup2(replacement._descriptor, closed_number)
            try:
                self.assertTrue(replacement.audit())
                with self.assertRaisesRegex(
                    seal.LinuxCoreSealError, "^CORE_SEAL_CLOSED$",
                ):
                    original.audit()
            finally:
                if not reused_directly:
                    os.close(closed_number)

    def test_live_review_rejects_swapped_equivalent_sealed_fd(self):
        if not self._supported():
            self._unsupported()
            return
        with self._open() as original:
            held_fd = os.dup(original._descriptor)
            try:
                with self._open() as attacker:
                    first_id = os.fstat(original._descriptor)
                    second_id = os.fstat(attacker._descriptor)
                    self.assertNotEqual(
                        (first_id.st_dev, first_id.st_ino),
                        (second_id.st_dev, second_id.st_ino),
                    )
                    # Replace the live descriptor with a DIFFERENT sealed
                    # kernel object carrying identical bytes and seals.
                    os.dup2(attacker._descriptor, original._descriptor)
                    with self.assertRaisesRegex(
                        seal.LinuxCoreSealError, "^CORE_SEAL_CHANGED$",
                    ):
                        original.audit()
            finally:
                # Restore original file description before original context
                # exit so its independent cleanup audit remains valid.
                os.dup2(held_fd, original._descriptor)
                os.close(held_fd)
            self.assertTrue(original.audit())

    def test_wrong_digest_is_rejected_before_seal_claim(self):
        if not self._supported():
            self._unsupported()
            return
        with self.assertRaisesRegex(
            seal.LinuxCoreSealError, "^CORE_SEAL_INPUT_DENIED$",
        ):
            with seal.sealed_linux_regtest_review(self.source, "a" * 64):
                self.fail("forged hash")

    def test_zero_byte_source_cannot_be_sealed(self):
        self.source.write_bytes(b"")
        if not self._supported():
            self._unsupported()
            return
        with self.assertRaisesRegex(
            seal.LinuxCoreSealError, "^CORE_SEAL_INPUT_DENIED$",
        ):
            with self._open():
                self.fail("empty source")

    def test_symlink_source_is_rejected(self):
        if not self._supported():
            self._unsupported()
            return
        link = Path(self.temp.name) / "link"
        link.symlink_to(self.source)
        with self.assertRaisesRegex(
            seal.LinuxCoreSealError, "^CORE_SEAL_INPUT_DENIED$",
        ):
            with seal.sealed_linux_regtest_review(link, self.digest):
                self.fail("symlink")

    def test_arbitrary_pathlike_hooks_are_not_executed(self):
        class Trap:
            def __fspath__(self):
                raise AssertionError("untrusted path hook executed")
        if not self._supported():
            self._unsupported()
            return
        with self.assertRaisesRegex(
            seal.LinuxCoreSealError, "^CORE_SEAL_INPUT_DENIED$",
        ):
            with seal.sealed_linux_regtest_review(Trap(), self.digest):
                self.fail("custom path")

    def test_mainnet_network_label_denied_before_file_access(self):
        with patch.object(seal, "stage_untrusted_core_artifact",
                          side_effect=AssertionError("MUST_NOT_STAGE")):
            with self.assertRaisesRegex(
                seal.LinuxCoreSealError, "^CORE_SEAL_NETWORK_DENIED$",
            ):
                with self._open(network="main"):
                    self.fail("no mainnet candidate")

    def test_no_subprocess_or_exec_required_for_kernel_seal(self):
        if not self._supported():
            self._unsupported()
            return
        with patch.object(subprocess, "Popen",
                          side_effect=AssertionError("NO_CORE_LAUNCH")):
            with self._open() as review:
                self.assertTrue(review.audit())
                self.assertIs(review.evidence.core_execution_allowed, False)

    def test_invalid_sha_format_never_qualifies(self):
        if not self._supported():
            self._unsupported()
            return
        for bad in ("", "foo", "Z" * 64, True, None):
            with self.subTest(bad=bad), self.assertRaisesRegex(
                seal.LinuxCoreSealError, "^CORE_SEAL_INPUT_DENIED$",
            ):
                with seal.sealed_linux_regtest_review(self.source, bad):
                    self.fail("invalid digest")

    def test_kernel_audit_keeps_sealed_digest_and_size(self):
        if not self._supported():
            self._unsupported()
            return
        with self._open() as review:
            self.assertEqual(review.evidence.sha256, self.digest)
            self.assertTrue(review.audit())
            self.assertEqual(os.fstat(review._descriptor).st_size, len(self.bytes))


if __name__ == "__main__":
    unittest.main()
