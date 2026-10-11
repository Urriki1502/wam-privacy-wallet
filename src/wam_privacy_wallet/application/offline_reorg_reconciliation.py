"""Fail-closed reconciliation of untrusted rollback/rescan research DTOs.

Consumes scalar-only offline *claims*. Never authenticates a WAM chain, WSP
scan, writer lock, persistence, or a safe restart cursor; zero file/network IO.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .recovery_transition import OfflineRecoveryTransition
from .offline_resume_review import OfflineResumeReview
from .offline_rescan_segments import OfflineRescanSegments, _valid_resume

_MAX_HEIGHT = 100_000_000
_MAX_REWIND_REVIEW = 128
_ALLOWED_REASONS = {
    "NO_TRUSTED_RECOVERY_EVIDENCE": "REVIEW_ONLY_NOT_VERIFIED",
    "VERSION_DOWNGRADE": "MIGRATION_RESCAN_REQUIRED",
    "CHECKPOINT_ROLLBACK": "RESCAN_REQUIRED",
    "REPORTED_TIP_REWIND": "RESCAN_REQUIRED",
    "CHECKPOINT_FORK_OR_RESTORE": "RESCAN_REQUIRED",
    "MIGRATION_RESCAN_REQUIRED": "MIGRATION_RESCAN_REQUIRED",
    "RESCAN_REQUIRED": "RESCAN_REQUIRED",
}
_ACTIONS = {
    "REVIEW_ONLY_NOT_VERIFIED": "REVALIDATE_BEFORE_RESCAN",
    "RESCAN_REQUIRED": "REWIND_RESCAN_REVIEW",
    "MIGRATION_RESCAN_REQUIRED": "MIGRATION_RESCAN_REVIEW",
}


class OfflineReorgReconciliationError(ValueError):
    """A fixed diagnostic code without source payloads or secret values."""


@dataclass(frozen=True, slots=True)
class OfflineReorgReconciliation:
    """A redacted, non-authorizing research summary; never a resume ticket."""

    verdict: Literal[
        "NO_PROGRESS_EVIDENCE", "CONTIGUOUS_BUT_UNVERIFIED",
        "REPLAY_NOT_DOUBLE_COUNTED", "ROLLBACK_RESCAN_REVIEW",
        "MIGRATION_RESCAN_REVIEW",
    ]
    revision: int
    claimed_start_height: int
    claimed_end_height: int
    unique_segments: int
    replay_segments: int
    status: Literal["REORG_RECONCILIATION_UNTRUSTED"] = field(
        default="REORG_RECONCILIATION_UNTRUSTED", init=False
    )
    chain_verified: bool = field(default=False, init=False)
    checkpoint_durable: bool = field(default=False, init=False)
    restart_authorized: bool = field(default=False, init=False)
    rescan_authorized: bool = field(default=False, init=False)
    scanner_enabled: bool = field(default=False, init=False)
    wallet_enabled: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)


def _valid_transition(t: object) -> bool:
    return (
        type(t) is OfflineRecoveryTransition
        and type(t.old_revision) is int
        and type(t.new_revision) is int
        and 0 <= t.old_revision < 2**63 - 1
        and t.new_revision == t.old_revision + 1
        and type(t.checkpoint_height) is int
        and 0 <= t.checkpoint_height <= _MAX_HEIGHT
        and type(t.reason) is str and type(t.decision) is str
        and _ALLOWED_REASONS.get(t.reason) == t.decision
        and type(t.status) is str
        and t.status == "SYNTHETIC_TRANSITION_UNTRUSTED"
        and t.writer_verified is False and t.chain_verified is False
        and t.recovery_completed is False and t.wallet_enabled is False
    )


def _valid_segments(s: object) -> bool:
    if (
        type(s) is not OfflineRescanSegments
        or type(s.revision) is not int or not 1 <= s.revision < 2**63
        or type(s.start_height) is not int
        or type(s.observed_end_height) is not int
        or not 0 <= s.start_height <= s.observed_end_height <= _MAX_HEIGHT
        or type(s.unique_segment_count) is not int
        or type(s.replay_count) is not int
        or not 0 <= s.unique_segment_count <= 8
        or not 0 <= s.replay_count <= 1
        or s.unique_segment_count + s.replay_count > 8
        or type(s.observed_block_count) is not int
        or s.observed_block_count != s.observed_end_height - s.start_height
        or not s.unique_segment_count <= s.observed_block_count <= 16 * s.unique_segment_count
        or type(s.observed_transaction_count) is not int
        or not 0 <= s.observed_transaction_count <= 20_000
        or type(s.status) is not str or s.status != "OFFLINE_RESCAN_UNTRUSTED"
        or type(s.resume_action) is not str
        or s.resume_action not in _ACTIONS.values()
        or s.scanner_enabled is not False or s.resume_authorized is not False
        or s.checkpoint_durable is not False or s.chain_verified is not False
        or s.wallet_enabled is not False or s.release_allowed is not False
        or type(s.disposition) is not str
    ):
        return False
    if s.replay_count:
        return s.unique_segment_count > 0 and s.disposition == "REPLAY_NOT_APPLIED"
    if not s.unique_segment_count:
        return s.disposition == "NO_SEGMENTS" and not s.observed_transaction_count
    return s.disposition == "CONTIGUOUS_UNVERIFIED"


def reconcile_offline_reorg(
    *, transition: object, resume: object, segments: object,
    expected_revision: object,
) -> OfflineReorgReconciliation:
    """Cross-check 3 independently untrusted receipts; NEVER permit rescan.

    Segments here are strictly a synthetic PRE-INTERRUPTION accounting claim.
    Claimed end cannot pass the interruption tip; migration begins from the
    synthetic genesis anchor (0), rollback claims must rewind at most 128
    blocks for *review*, and ordinary claims start at checkpoint. These are
    consistency rules, not safe rescan cursor derivation.
    """
    if not _valid_transition(transition):
        raise OfflineReorgReconciliationError("REORG_TRANSITION_DENIED")
    if not _valid_resume(resume):
        raise OfflineReorgReconciliationError("REORG_RESUME_DENIED")
    if not _valid_segments(segments):
        raise OfflineReorgReconciliationError("REORG_SEGMENTS_DENIED")
    if (type(expected_revision) is not int
            or expected_revision != transition.new_revision
            or expected_revision != resume.revision
            or expected_revision != segments.revision):
        raise OfflineReorgReconciliationError("REORG_REVISION_DENIED")
    if (transition.checkpoint_height != resume.claimed_checkpoint_height
            or resume.action != _ACTIONS[transition.decision]
            or segments.resume_action != resume.action):
        raise OfflineReorgReconciliationError("REORG_CROSS_SOURCE_DENIED")
    start, end = segments.start_height, segments.observed_end_height
    if end > resume.interrupted_height:
        raise OfflineReorgReconciliationError("REORG_INTERRUPTION_HORIZON_DENIED")
    if resume.action == "MIGRATION_RESCAN_REVIEW":
        if start != 0:
            raise OfflineReorgReconciliationError("REORG_MIGRATION_ANCHOR_DENIED")
        verdict = "MIGRATION_RESCAN_REVIEW"
    elif resume.action == "REWIND_RESCAN_REVIEW":
        if start > transition.checkpoint_height:
            raise OfflineReorgReconciliationError("REORG_REWIND_ANCHOR_DENIED")
        if transition.checkpoint_height - start > _MAX_REWIND_REVIEW:
            raise OfflineReorgReconciliationError("REORG_REWIND_BUDGET_DENIED")
        verdict = "ROLLBACK_RESCAN_REVIEW"
    else:
        if start != transition.checkpoint_height:
            raise OfflineReorgReconciliationError("REORG_CHECKPOINT_ANCHOR_DENIED")
        verdict = (
            "REPLAY_NOT_DOUBLE_COUNTED" if segments.replay_count
            else "CONTIGUOUS_BUT_UNVERIFIED" if segments.unique_segment_count
            else "NO_PROGRESS_EVIDENCE"
        )
    return OfflineReorgReconciliation(
        verdict, expected_revision, start, end,
        segments.unique_segment_count, segments.replay_count,
    )
