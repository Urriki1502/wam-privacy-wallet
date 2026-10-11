"""Bounded synthetic rescan accounting and idempotent replay regressions."""
from dataclasses import FrozenInstanceError, replace
import socket
import subprocess
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application.offline_resume_review import OfflineResumeReview
from wam_privacy_wallet.application.offline_rescan_segments import (
    OfflineRescanSegments, OfflineRescanSegmentsError,
    inspect_offline_rescan_segments,
)

A, B, C, D = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)


def resume(action="REVALIDATE_BEFORE_RESCAN"):
    reasons = {
        "REVALIDATE_BEFORE_RESCAN": "UNVERIFIED_INTERRUPTION",
        "REWIND_RESCAN_REVIEW": "REORG_OR_ROLLBACK_SUSPECTED",
        "MIGRATION_RESCAN_REVIEW": "SCHEMA_MIGRATION_REQUIRED",
    }
    return OfflineResumeReview(action, reasons[action], 5, 50, 8)


def seg(start=8, end=10, parent=A, digest=B, tx=2, attempt=1, **extra):
    d = {"start_height": start, "end_height": end,
         "parent_hash": parent, "end_hash": digest,
         "transaction_count": tx, "attempt": attempt}
    d.update(extra)
    return d


def review(*, preview=None, start_height=8, segments=None, revision=5):
    return inspect_offline_rescan_segments(
        resume=resume() if preview is None else preview,
        expected_revision=revision,
        start_height=start_height,
        segments=() if segments is None else segments,
    )


class OfflineRescanSegmentsTests(unittest.TestCase):
    def test_empty_batch_never_claims_scan_or_persistence(self):
        r = review()
        self.assertEqual((r.disposition, r.unique_segment_count, r.replay_count),
                         ("NO_SEGMENTS", 0, 0))
        self.assertEqual((r.start_height, r.observed_end_height), (8, 8))
        self.assertEqual((r.observed_block_count, r.observed_transaction_count), (0, 0))
        self.assertEqual(r.status, "OFFLINE_RESCAN_UNTRUSTED")
        self.assertFalse(any((r.resume_authorized, r.scanner_enabled, r.wallet_enabled,
                              r.checkpoint_durable, r.chain_verified, r.release_allowed)))

    def test_one_bounded_segment_counted_once(self):
        r = review(segments=(seg(),))
        self.assertEqual((r.disposition, r.observed_end_height), ("CONTIGUOUS_UNVERIFIED", 10))
        self.assertEqual((r.unique_segment_count, r.observed_block_count,
                          r.observed_transaction_count), (1, 2, 2))

    def test_two_contiguous_segments_count_unique_work(self):
        r = review(segments=(seg(), seg(10, 12, B, C, 3, 2)))
        self.assertEqual((r.unique_segment_count, r.observed_end_height), (2, 12))
        self.assertEqual((r.observed_block_count, r.observed_transaction_count), (4, 5))

    def test_exact_immediate_replay_does_not_double_count(self):
        s = seg()
        r = review(segments=(s, dict(s)))
        self.assertEqual((r.disposition, r.replay_count), ("REPLAY_NOT_APPLIED", 1))
        self.assertEqual((r.observed_block_count, r.observed_transaction_count), (2, 2))
        self.assertFalse(r.checkpoint_durable)

    def test_replay_after_previous_contiguous_segment_is_allowed(self):
        first, second = seg(), seg(10, 12, B, C, 1, 2)
        r = review(segments=(first, second, dict(second)))
        self.assertEqual((r.unique_segment_count, r.replay_count), (2, 1))
        self.assertEqual(r.observed_end_height, 12)

    def test_three_identical_attempts_are_denied(self):
        s = seg()
        with self.assertRaisesRegex(OfflineRescanSegmentsError,
                                    "^RESCAN_REPLAY_EXCESS_DENIED$"):
            review(segments=(s, dict(s), dict(s)))

    def test_new_segment_after_replay_is_denied(self):
        s = seg()
        with self.assertRaisesRegex(OfflineRescanSegmentsError,
                                    "^RESCAN_REPLAY_ORDER_DENIED$"):
            review(segments=(s, dict(s), seg(10, 12, B, C)))

    def test_nonadjacent_replay_denied_not_double_counted(self):
        s = seg()
        with self.assertRaisesRegex(OfflineRescanSegmentsError,
                                    "^RESCAN_GAP_OR_OVERLAP_DENIED$"):
            review(segments=(s, seg(10, 12, B, C), dict(s)))

    def test_gap_and_overlap_denied(self):
        for second in (seg(11, 13, B, C), seg(9, 11, B, C)):
            with self.subTest(second=second["start_height"]), self.assertRaisesRegex(
                OfflineRescanSegmentsError, "^RESCAN_GAP_OR_OVERLAP_DENIED$"
            ):
                review(segments=(seg(), second))

    def test_parent_hash_mismatch_denied(self):
        with self.assertRaisesRegex(OfflineRescanSegmentsError,
                                    "^RESCAN_LINK_CONFLICT_DENIED$"):
            review(segments=(seg(), seg(10, 12, C, D)))

    def test_same_parent_and_end_hash_cycle_denied(self):
        with self.assertRaisesRegex(OfflineRescanSegmentsError,
                                    "^RESCAN_SEGMENT_CYCLE_DENIED$"):
            review(segments=(seg(digest=A),))

    def test_hash_identity_cannot_cycle_back_to_earlier_anchor(self):
        # Links are syntactically coherent but a content-addressed chain
        # cannot revisit an earlier block identity at a new height.
        with self.assertRaisesRegex(
            OfflineRescanSegmentsError, "^RESCAN_SEGMENT_CYCLE_DENIED$"
        ):
            review(segments=(seg(), seg(10, 12, B, A)))

    def test_changed_attempt_is_not_an_idempotent_replay(self):
        with self.assertRaisesRegex(OfflineRescanSegmentsError,
                                    "^RESCAN_GAP_OR_OVERLAP_DENIED$"):
            review(segments=(seg(), seg(attempt=2)))

    def test_same_heights_changed_digest_rejected(self):
        with self.assertRaisesRegex(OfflineRescanSegmentsError,
                                    "^RESCAN_GAP_OR_OVERLAP_DENIED$"):
            review(segments=(seg(), seg(digest=C)))

    def test_too_many_segments_is_denied(self):
        with self.assertRaisesRegex(OfflineRescanSegmentsError,
                                    "^RESCAN_BATCH_DENIED$"):
            review(segments=tuple(seg() for _ in range(9)))

    def test_non_tuple_container_and_foreign_objects_denied(self):
        for value in ([], "SECRET", {}, True, (None,), ([],), ({"seed": "KEY"},)):
            with self.subTest(t=type(value).__name__), self.assertRaises(
                OfflineRescanSegmentsError
            ):
                review(segments=value)

    def test_invalid_segment_integer_types_heights_and_hashes_denied(self):
        invalid = (
            seg(start=True), seg(end="10"), seg(start=-1), seg(end=8),
            seg(end=25), seg(end=100000001), seg(tx=True), seg(tx=-1),
            seg(tx=20001), seg(attempt=True), seg(attempt=0), seg(attempt=5),
            seg(parent="A" * 64), seg(digest="bad"), seg(extra="PRIVATE"),
        )
        for piece in invalid:
            with self.subTest(piece=piece), self.assertRaisesRegex(
                OfflineRescanSegmentsError, "^RESCAN_SEGMENT_SHAPE_DENIED$"
            ):
                review(segments=(piece,))

    def test_more_than_total_transaction_cap_denied(self):
        first = seg(tx=15000)
        second = seg(10, 12, B, C, tx=6000)
        with self.assertRaisesRegex(OfflineRescanSegmentsError,
                                    "^RESCAN_WORK_DENIED$"):
            review(segments=(first, second))

    def test_invalid_anchor_types_denied(self):
        for x in (-1, True, None, "8", 100000001, 8.5):
            with self.subTest(start=x), self.assertRaisesRegex(
                OfflineRescanSegmentsError, "^RESCAN_ANCHOR_DENIED$"
            ):
                review(start_height=x)

    def test_stale_or_forged_revision_denied(self):
        for val in (4, 6, True, None, "5", -1):
            with self.subTest(revision=val), self.assertRaisesRegex(
                OfflineRescanSegmentsError, "^RESCAN_REVISION_DENIED$"
            ):
                review(revision=val)

    def test_resume_migration_and_rollback_stay_untrusted(self):
        for action in ("REWIND_RESCAN_REVIEW", "MIGRATION_RESCAN_REVIEW"):
            r = review(preview=resume(action), segments=(seg(),))
            self.assertEqual(r.resume_action, action)
            self.assertFalse(r.resume_authorized)

    def test_forged_resume_authority_and_subclass_denied(self):
        class FakeResume(OfflineResumeReview):
            pass
        base = resume()
        tampered = replace(base)
        object.__setattr__(tampered, "scanner_enabled", True)
        for bad in (FakeResume(base.action, base.reason, 5, 50, 8),
                    tampered, {}, None, True):
            with self.subTest(t=type(bad).__name__), self.assertRaisesRegex(
                OfflineRescanSegmentsError, "^RESCAN_RESUME_DENIED$"
            ):
                review(preview=bad)

    def test_output_immutable_no_sensitive_values_or_io(self):
        s = seg(parent=A, digest=B)
        with patch("builtins.open", side_effect=AssertionError("FILE")), \
             patch.object(socket, "socket", side_effect=AssertionError("SOCKET")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("PROC")):
            r = review(segments=(s,))
        self.assertNotIn(A, repr(r))
        self.assertNotIn(B, repr(r))
        with self.assertRaises(FrozenInstanceError):
            r.scanner_enabled = True
        for name in ("scanner_enabled", "wallet_enabled", "resume_authorized",
                     "checkpoint_durable", "chain_verified", "release_allowed", "status"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                replace(r, **{name: True})
        for name in ("parent_hash", "end_hash", "wallet", "secret", "path",
                     "block", "segments", "txid", "rpc"):
            self.assertFalse(hasattr(r, name))
        import sys
        self.assertFalse(any(n.startswith("wam_sp") for n in sys.modules))


if __name__ == "__main__":
    unittest.main()
