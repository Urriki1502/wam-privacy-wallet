"""Crash/restart-only research: no disk, scanner, process or wallet IO."""
from dataclasses import FrozenInstanceError, replace
import socket
import subprocess
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS
from wam_privacy_wallet.application.offline_resume_review import (
    OfflineResumeReview, OfflineResumeReviewError, review_offline_resume,
)

A, B = "a" * 64, "b" * 64


def sample(*, version=3, checkpoint=3, tip_height=None, block=A, tip=None, **extra):
    d = {
        "schema": "wam-wallet-storage-review/v1",
        "profile": "WSP-1", "network": "regtest", "genesis": WAM_REGTEST_GENESIS,
        "store_schema_version": version,
        "checkpoint_height": checkpoint, "checkpoint_hash": block,
        "reported_height": checkpoint if tip_height is None else tip_height,
        "reported_tip": block if tip is None else tip,
        "writer_lock": "UNATTESTED", "db_integrity": "UNATTESTED",
        "wallet_identity": "UNATTESTED",
    }
    d.update(extra)
    return d


def check(*, before=None, after=None, old_revision=6, new_revision=7,
          interrupted_height=5, interruption="CRASH"):
    return review_offline_resume(
        before=sample() if before is None else before,
        after=sample() if after is None else after,
        old_revision=old_revision, new_revision=new_revision,
        interrupted_height=interrupted_height, interruption=interruption,
    )


class OfflineResumeReviewTests(unittest.TestCase):
    def test_matching_crash_never_auto_resumes(self):
        r = check()
        self.assertEqual(r.action, "REVALIDATE_BEFORE_RESCAN")
        self.assertEqual(r.reason, "UNVERIFIED_INTERRUPTION")
        self.assertEqual(r.status, "OFFLINE_RESUME_UNTRUSTED")
        self.assertEqual((r.revision, r.interrupted_height, r.claimed_checkpoint_height),
                         (7, 5, 3))
        self.assertFalse(any((r.resume_authorized, r.scanner_enabled,
                              r.wallet_enabled, r.checkpoint_durable,
                              r.chain_verified, r.release_allowed)))

    def test_orderly_restart_claim_still_unverified(self):
        r = check(interruption="RESTART")
        self.assertEqual(r.action, "REVALIDATE_BEFORE_RESCAN")
        self.assertFalse(r.resume_authorized)

    def test_unclean_shutdown_claim_still_unverified(self):
        self.assertEqual(check(interruption="UNCLEAN_SHUTDOWN").reason,
                         "UNVERIFIED_INTERRUPTION")

    def test_checkpoint_progress_is_not_persistence_proof(self):
        r = check(after=sample(checkpoint=4, block=B))
        self.assertEqual(r.claimed_checkpoint_height, 4)
        self.assertEqual(r.action, "REVALIDATE_BEFORE_RESCAN")
        self.assertFalse(r.checkpoint_durable)

    def test_height_rollback_requires_rewind_review(self):
        r = check(before=sample(checkpoint=4), after=sample(checkpoint=2))
        self.assertEqual((r.action, r.reason),
                         ("REWIND_RESCAN_REVIEW", "REORG_OR_ROLLBACK_SUSPECTED"))

    def test_reported_tip_rewind_requires_rewind_review(self):
        r = check(
            before=sample(tip_height=7, tip=B),
            after=sample(tip_height=6, tip=B),
        )
        self.assertEqual(r.action, "REWIND_RESCAN_REVIEW")

    def test_same_height_hash_fork_requires_rewind_review(self):
        r = check(after=sample(block=B))
        self.assertEqual(r.action, "REWIND_RESCAN_REVIEW")

    def test_stale_candidate_tip_requires_rewind_review(self):
        r = check(after=sample(tip_height=2, tip=B))
        self.assertEqual(r.action, "REWIND_RESCAN_REVIEW")

    def test_legacy_to_v3_never_proves_migration(self):
        r = check(before=sample(version=2))
        self.assertEqual((r.action, r.reason),
                         ("MIGRATION_RESCAN_REVIEW", "SCHEMA_MIGRATION_REQUIRED"))

    def test_downgrade_from_v3_to_legacy_requires_migration_review(self):
        r = check(after=sample(version=0))
        self.assertEqual(r.action, "MIGRATION_RESCAN_REVIEW")

    def test_invalid_interruption_tokens_are_redacted(self):
        for v in (None, True, 3, "MAINNET", "", "CRASH_SECRET"):
            with self.subTest(t=repr(v)), self.assertRaisesRegex(
                OfflineResumeReviewError, "^RECOVERY_RESUME_EVENT_DENIED$"
            ):
                check(interruption=v)

    def test_invalid_interrupted_height_is_denied(self):
        for v in (None, True, "5", -1, 100000001, 5.0):
            with self.subTest(t=repr(v)), self.assertRaisesRegex(
                OfflineResumeReviewError, "^RECOVERY_RESUME_HEIGHT_DENIED$"
            ):
                check(interrupted_height=v)

    def test_checkpoint_ahead_of_interruption_is_denied_on_either_side(self):
        for key in ("before", "after"):
            with self.subTest(side=key), self.assertRaisesRegex(
                OfflineResumeReviewError,
                "^RECOVERY_RESUME_CHECKPOINT_CONFLICT$",
            ):
                check(**{key: sample(checkpoint=6)})

    def test_stale_or_invalid_sequence_revision_denied(self):
        for old, new in ((6, 6), (6, 8), (True, 2), (None, 1), (-1, 0),
                         (2**63-1, 2**63)):
            with self.subTest(old=old, new=new), self.assertRaisesRegex(
                OfflineResumeReviewError, "^RECOVERY_RESUME_INPUT_DENIED$"
            ):
                check(old_revision=old, new_revision=new)

    def test_foreign_network_version_and_writer_claim_denied(self):
        for invalid in (
            sample(network="mainnet"), sample(profile="WSP-2"),
            sample(store_schema_version=99), sample(writer_lock="VERIFIED"),
            sample(genesis=B),
        ):
            with self.subTest(v=invalid.get("network")), self.assertRaisesRegex(
                OfflineResumeReviewError, "^RECOVERY_RESUME_INPUT_DENIED$"
            ):
                check(after=invalid)

    def test_non_dict_and_unrecognized_keys_denied(self):
        for invalid in ([], True, "SECRET", {"key": "DO_NOT_ECHO"},
                        sample(password="DO_NOT_ECHO")):
            with self.subTest(v=type(invalid).__name__), self.assertRaisesRegex(
                OfflineResumeReviewError, "^RECOVERY_RESUME_INPUT_DENIED$"
            ):
                check(before=invalid)

    def test_output_immutable_and_no_authority_constructor_override(self):
        r = check()
        with self.assertRaises(FrozenInstanceError):
            r.resume_authorized = True
        for name in ("resume_authorized", "scanner_enabled", "wallet_enabled",
                     "checkpoint_durable", "chain_verified", "release_allowed", "status"):
            with self.subTest(field=name), self.assertRaises(TypeError):
                OfflineResumeReview("REVALIDATE_BEFORE_RESCAN",
                    "UNVERIFIED_INTERRUPTION", 7, 5, 3, **{name: True})
            with self.assertRaises(ValueError):
                replace(r, **{name: True})

    def test_no_raw_hash_paths_secrets_or_previous_snapshot_retained(self):
        r = check(before=sample(block=A), after=sample(checkpoint=4, block=B))
        self.assertNotIn(A, repr(r))
        self.assertNotIn(B, repr(r))
        for x in ("old", "before", "after", "hash", "rpc", "credential",
                  "key", "seed", "path", "wallet_handle", "db", "scanner"):
            self.assertFalse(hasattr(r, x))

    def test_no_file_socket_process_or_wsp_imports(self):
        old, new = sample(), sample(checkpoint=4, block=B)
        with patch("builtins.open", side_effect=AssertionError("NO_FILE")), \
             patch.object(socket, "socket", side_effect=AssertionError("NO_SOCKET")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("NO_PROC")):
            result = check(before=old, after=new)
        self.assertFalse(result.resume_authorized)
        import sys
        self.assertFalse(any(k.startswith("wam_sp") for k in sys.modules))


if __name__ == "__main__":
    unittest.main()
