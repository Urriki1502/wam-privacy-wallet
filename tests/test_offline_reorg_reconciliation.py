"""Adversarial tests for no-authority offline rollback/rescan reconciliation."""
from dataclasses import FrozenInstanceError, replace
import socket
import subprocess
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application.recovery_transition import OfflineRecoveryTransition
from wam_privacy_wallet.application.offline_resume_review import OfflineResumeReview
from wam_privacy_wallet.application.offline_rescan_segments import (
    OfflineRescanSegments, inspect_offline_rescan_segments, OfflineRescanSegmentsError,
)
from wam_privacy_wallet.application.offline_reorg_reconciliation import (
    OfflineReorgReconciliation, OfflineReorgReconciliationError,
    reconcile_offline_reorg,
)

A, B, C = "a" * 64, "b" * 64, "c" * 64


def transition(reason="NO_TRUSTED_RECOVERY_EVIDENCE", checkpoint=5):
    decisions = {
        "NO_TRUSTED_RECOVERY_EVIDENCE": "REVIEW_ONLY_NOT_VERIFIED",
        "CHECKPOINT_ROLLBACK": "RESCAN_REQUIRED",
        "REPORTED_TIP_REWIND": "RESCAN_REQUIRED",
        "CHECKPOINT_FORK_OR_RESTORE": "RESCAN_REQUIRED",
        "MIGRATION_RESCAN_REQUIRED": "MIGRATION_RESCAN_REQUIRED",
        "VERSION_DOWNGRADE": "MIGRATION_RESCAN_REQUIRED",
        "RESCAN_REQUIRED": "RESCAN_REQUIRED",
    }
    return OfflineRecoveryTransition(
        reason, decisions[reason], 4, 5, checkpoint,
    )


def resume(action="REVALIDATE_BEFORE_RESCAN", *, checkpoint=5, interrupted=12):
    reasons = {
        "REVALIDATE_BEFORE_RESCAN": "UNVERIFIED_INTERRUPTION",
        "REWIND_RESCAN_REVIEW": "REORG_OR_ROLLBACK_SUSPECTED",
        "MIGRATION_RESCAN_REVIEW": "SCHEMA_MIGRATION_REQUIRED",
    }
    return OfflineResumeReview(action, reasons[action], 5, interrupted, checkpoint)


def segments(*, action="REVALIDATE_BEFORE_RESCAN", start=5, end=7,
             unique=1, replay=0, blocks=None, tx=1, disposition=None):
    if disposition is None:
        disposition = (
            "REPLAY_NOT_APPLIED" if replay
            else "CONTIGUOUS_UNVERIFIED" if unique else "NO_SEGMENTS"
        )
    return OfflineRescanSegments(
        disposition, action, 5, start, end, unique, replay,
        end - start if blocks is None else blocks, tx,
    )


_UNSET = object()


def check(*, before=_UNSET, after=_UNSET, batch=_UNSET, revision=5):
    return reconcile_offline_reorg(
        transition=transition() if before is _UNSET else before,
        resume=resume() if after is _UNSET else after,
        segments=segments() if batch is _UNSET else batch,
        expected_revision=revision,
    )


class OfflineReorgReconciliationTests(unittest.TestCase):
    def assert_code(self, code, **kwargs):
        with self.assertRaisesRegex(
            OfflineReorgReconciliationError, "^" + code + "$"
        ):
            check(**kwargs)

    def test_valid_contiguous_fixtures_do_not_claim_chain_or_cursor(self):
        r = check()
        self.assertEqual(r.verdict, "CONTIGUOUS_BUT_UNVERIFIED")
        self.assertEqual((r.revision, r.claimed_start_height, r.claimed_end_height),
                         (5, 5, 7))
        self.assertFalse(any((
            r.chain_verified, r.checkpoint_durable, r.restart_authorized,
            r.rescan_authorized, r.scanner_enabled, r.wallet_enabled,
            r.release_allowed,
        )))
        self.assertEqual(r.status, "REORG_RECONCILIATION_UNTRUSTED")

    def test_empty_segments_do_not_confer_progress(self):
        r = check(batch=segments(start=5, end=5, unique=0, tx=0))
        self.assertEqual(r.verdict, "NO_PROGRESS_EVIDENCE")
        self.assertEqual((r.unique_segments, r.replay_segments), (0, 0))

    def test_exact_replay_detected_without_duplicate_counts(self):
        r = check(batch=segments(start=5, end=7, unique=1, replay=1))
        self.assertEqual(r.verdict, "REPLAY_NOT_DOUBLE_COUNTED")
        self.assertEqual((r.unique_segments, r.replay_segments), (1, 1))
        self.assertFalse(r.checkpoint_durable)

    def test_rollback_requires_explicit_rewind_review(self):
        r = check(
            before=transition("CHECKPOINT_ROLLBACK"),
            after=resume("REWIND_RESCAN_REVIEW"),
            batch=segments(action="REWIND_RESCAN_REVIEW", start=4, end=7),
        )
        self.assertEqual(r.verdict, "ROLLBACK_RESCAN_REVIEW")
        self.assertFalse(r.rescan_authorized)

    def test_reported_tip_rewind_classified_as_rollback(self):
        r = check(
            before=transition("REPORTED_TIP_REWIND"),
            after=resume("REWIND_RESCAN_REVIEW"),
            batch=segments(action="REWIND_RESCAN_REVIEW", start=5, end=7),
        )
        self.assertEqual(r.verdict, "ROLLBACK_RESCAN_REVIEW")

    def test_same_height_fork_classified_as_rollback(self):
        r = check(
            before=transition("CHECKPOINT_FORK_OR_RESTORE"),
            after=resume("REWIND_RESCAN_REVIEW"),
            batch=segments(action="REWIND_RESCAN_REVIEW", start=3, end=6),
        )
        self.assertEqual(r.verdict, "ROLLBACK_RESCAN_REVIEW")

    def test_migration_cannot_claim_partial_genesis_scan(self):
        r = check(
            before=transition("MIGRATION_RESCAN_REQUIRED"),
            after=resume("MIGRATION_RESCAN_REVIEW"),
            batch=segments(action="MIGRATION_RESCAN_REVIEW", start=0, end=2),
        )
        self.assertEqual(r.verdict, "MIGRATION_RESCAN_REVIEW")
        self.assertFalse(r.wallet_enabled)

    def test_schema_downgrade_still_demands_migration_review(self):
        r = check(
            before=transition("VERSION_DOWNGRADE"),
            after=resume("MIGRATION_RESCAN_REVIEW"),
            batch=segments(action="MIGRATION_RESCAN_REVIEW", start=0, end=0,
                           unique=0, tx=0),
        )
        self.assertEqual(r.verdict, "MIGRATION_RESCAN_REVIEW")

    def test_rewind_start_above_checkpoint_denied(self):
        self.assert_code(
            "REORG_REWIND_ANCHOR_DENIED",
            before=transition("CHECKPOINT_ROLLBACK"),
            after=resume("REWIND_RESCAN_REVIEW"),
            batch=segments(action="REWIND_RESCAN_REVIEW", start=6, end=7),
        )

    def test_rewind_window_exceeding_bound_denied(self):
        self.assert_code(
            "REORG_REWIND_BUDGET_DENIED",
            before=transition("CHECKPOINT_ROLLBACK", checkpoint=200),
            after=resume("REWIND_RESCAN_REVIEW", checkpoint=200, interrupted=300),
            batch=segments(action="REWIND_RESCAN_REVIEW", start=71, end=73),
        )

    def test_migration_start_above_zero_denied(self):
        self.assert_code(
            "REORG_MIGRATION_ANCHOR_DENIED",
            before=transition("MIGRATION_RESCAN_REQUIRED"),
            after=resume("MIGRATION_RESCAN_REVIEW"),
            batch=segments(action="MIGRATION_RESCAN_REVIEW", start=1, end=3),
        )

    def test_ordinary_segment_start_must_match_claimed_checkpoint(self):
        for start, end in ((4, 6), (6, 8)):
            with self.subTest(start=start):
                self.assert_code(
                    "REORG_CHECKPOINT_ANCHOR_DENIED",
                    batch=segments(start=start, end=end),
                )

    def test_pre_interruption_window_cannot_end_after_interruption(self):
        self.assert_code(
            "REORG_INTERRUPTION_HORIZON_DENIED",
            batch=segments(start=5, end=13),
        )

    def test_checkpoint_mismatch_across_receipts_denied(self):
        self.assert_code(
            "REORG_CROSS_SOURCE_DENIED",
            before=transition(checkpoint=6),
        )

    def test_action_mismatch_between_transition_and_resume_denied(self):
        self.assert_code(
            "REORG_CROSS_SOURCE_DENIED",
            after=resume("REWIND_RESCAN_REVIEW"),
            batch=segments(action="REWIND_RESCAN_REVIEW"),
        )

    def test_action_mismatch_between_resume_and_segments_denied(self):
        self.assert_code(
            "REORG_CROSS_SOURCE_DENIED",
            batch=segments(action="REWIND_RESCAN_REVIEW"),
        )

    def test_stale_or_bool_revision_is_denied(self):
        for revision in (4, 6, None, True, "5", -1):
            with self.subTest(revision=revision):
                self.assert_code("REORG_REVISION_DENIED", revision=revision)

    def test_forged_transition_reason_status_or_authority_denied(self):
        legitimate = transition()
        forged = replace(legitimate)
        object.__setattr__(forged, "wallet_enabled", True)
        for bad in (
            replace(legitimate, reason="CUSTOM_REASON"),
            replace(legitimate, decision="RESCAN_REQUIRED"),
            replace(legitimate, checkpoint_height=True),
            forged, {}, None, "SEED_DATA",
        ):
            with self.subTest(kind=type(bad).__name__):
                self.assert_code("REORG_TRANSITION_DENIED", before=bad)

    def test_forged_resume_denied(self):
        legitimate = resume()
        forged = replace(legitimate)
        object.__setattr__(forged, "resume_authorized", True)
        for bad in (forged, replace(legitimate, reason="FAKE"), {}, True,
                    "DO_NOT_ECHO"):
            with self.subTest(kind=type(bad).__name__):
                self.assert_code("REORG_RESUME_DENIED", after=bad)

    def test_forged_segment_count_or_status_denied(self):
        legitimate = segments()
        bad_status = replace(legitimate)
        object.__setattr__(bad_status, "status", "TRUSTED")
        for bad in (
            replace(legitimate, observed_block_count=0),
            replace(legitimate, replay_count=1),
            replace(legitimate, unique_segment_count=True),
            replace(legitimate, observed_transaction_count=20001),
            bad_status, {}, True,
        ):
            with self.subTest(kind=type(bad).__name__):
                self.assert_code("REORG_SEGMENTS_DENIED", batch=bad)

    def test_output_never_retains_chain_hashes_or_wallet_handles(self):
        result = check()
        with self.assertRaises(FrozenInstanceError):
            result.release_allowed = True
        for name in ("release_allowed", "scanner_enabled",
                     "restart_authorized", "checkpoint_durable", "status"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                replace(result, **{name: True})
        for name in ("blocks", "hash", "wallet", "key", "rpc", "path",
                     "journal", "private_key", "scanner", "cursor"):
            self.assertFalse(hasattr(result, name))
        self.assertNotIn(A, repr(result))

    def test_no_file_socket_subprocess_or_operational_wsp_imports(self):
        with patch("builtins.open", side_effect=AssertionError("FILE")), \
             patch.object(socket, "socket", side_effect=AssertionError("SOCKET")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("PROCESS")):
            out = check()
        self.assertFalse(out.scanner_enabled)
        import sys
        self.assertFalse(any(x.startswith("wam_sp") for x in sys.modules))

    def test_metamorphic_immediate_replay_never_increases_unique_work(self):
        # For several independently shaped intervals, append one identical
        # last segment. The source segment model must report identical unique
        # blocks/transactions and the reconciler must not grant authority.
        for block_count in range(1, 7):
            with self.subTest(block_count=block_count):
                fixture = {
                    "start_height": 5, "end_height": 5 + block_count,
                    "parent_hash": A, "end_hash": B,
                    "transaction_count": 2 * block_count, "attempt": 1,
                }
                unmodified = inspect_offline_rescan_segments(
                    resume=resume(), expected_revision=5,
                    start_height=5, segments=(fixture,),
                )
                replayed = inspect_offline_rescan_segments(
                    resume=resume(), expected_revision=5,
                    start_height=5, segments=(fixture, dict(fixture)),
                )
                self.assertEqual(
                    (unmodified.observed_block_count, unmodified.observed_transaction_count),
                    (replayed.observed_block_count, replayed.observed_transaction_count),
                )
                one = check(batch=unmodified)
                two = check(batch=replayed)
                self.assertEqual(one.unique_segments, two.unique_segments)
                self.assertEqual(one.claimed_end_height, two.claimed_end_height)
                self.assertEqual(two.verdict, "REPLAY_NOT_DOUBLE_COUNTED")
                self.assertFalse(two.restart_authorized)

    def test_metamorphic_changed_replay_attempt_never_counts_as_valid(self):
        fixture = {
            "start_height": 5, "end_height": 7,
            "parent_hash": A, "end_hash": B,
            "transaction_count": 2, "attempt": 1,
        }
        for change in ("attempt", "end_hash", "transaction_count"):
            altered = dict(fixture)
            altered[change] = (
                2 if change == "attempt" else C if change == "end_hash" else 3
            )
            with self.subTest(change=change), self.assertRaises(OfflineRescanSegmentsError):
                inspect_offline_rescan_segments(
                    resume=resume(), expected_revision=5,
                    start_height=5, segments=(fixture, altered),
                )


if __name__ == "__main__":
    unittest.main()
