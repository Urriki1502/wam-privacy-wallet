"""Synthetic crash/restart resume review, with no resumable capability.

A caller-created metadata pair and reported interruption cannot prove a
durable checkpoint, full-node authenticity, lock ownership or scanner state.
This is a pure UI/research disposition: never automatically resume or scan.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .recovery_transition import (
    OfflineRecoveryTransitionError, evaluate_offline_recovery_transition,
)

_MAX_HEIGHT = 100_000_000


class OfflineResumeReviewError(ValueError):
    """Redacted fixed-code failure; no input, hash or path in messages."""


@dataclass(frozen=True, slots=True)
class OfflineResumeReview:
    """Scalar-only preview; not a restart token or checkpoint receipt."""

    action: Literal[
        "REVALIDATE_BEFORE_RESCAN", "REWIND_RESCAN_REVIEW",
        "MIGRATION_RESCAN_REVIEW",
    ]
    reason: Literal[
        "UNVERIFIED_INTERRUPTION", "REORG_OR_ROLLBACK_SUSPECTED",
        "SCHEMA_MIGRATION_REQUIRED",
    ]
    revision: int
    interrupted_height: int
    claimed_checkpoint_height: int
    # This is solely a *claim* about a synthetic interrupt, never authority.
    status: Literal["OFFLINE_RESUME_UNTRUSTED"] = field(
        default="OFFLINE_RESUME_UNTRUSTED", init=False
    )
    scanner_enabled: bool = field(default=False, init=False)
    wallet_enabled: bool = field(default=False, init=False)
    resume_authorized: bool = field(default=False, init=False)
    checkpoint_durable: bool = field(default=False, init=False)
    chain_verified: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)


def review_offline_resume(
    *, before: object, after: object, old_revision: object,
    new_revision: object, interrupted_height: object,
    interruption: object,
) -> OfflineResumeReview:
    """Review UNTRUSTED synthetic interruption metadata; deny real resume.

    Require two well-formed WSP-1 regtest snapshots, sequential revisions and
    a bounded interruption height. A claimed checkpoint *ahead* of the point
    at which execution was interrupted is contradictory and rejected.
    Contradictions do not reveal caller-supplied contents in errors.
    """
    if type(interruption) is not str or interruption not in (
        "CRASH", "RESTART", "UNCLEAN_SHUTDOWN",
    ):
        raise OfflineResumeReviewError("RECOVERY_RESUME_EVENT_DENIED")
    if type(interrupted_height) is not int or not 0 <= interrupted_height <= _MAX_HEIGHT:
        raise OfflineResumeReviewError("RECOVERY_RESUME_HEIGHT_DENIED")
    try:
        transition = evaluate_offline_recovery_transition(
            old=before, candidate=after,
            old_revision=old_revision, new_revision=new_revision,
        )
    except OfflineRecoveryTransitionError:
        raise OfflineResumeReviewError("RECOVERY_RESUME_INPUT_DENIED") from None
    # Evaluator already checked EXACT dict keys/strs and bounded integer
    # height/hash/profile fields; no reading from disk or retaining a dict.
    if (before["checkpoint_height"] > interrupted_height
            or after["checkpoint_height"] > interrupted_height):
        raise OfflineResumeReviewError("RECOVERY_RESUME_CHECKPOINT_CONFLICT")
    if transition.decision == "MIGRATION_RESCAN_REQUIRED":
        action = "MIGRATION_RESCAN_REVIEW"
        reason = "SCHEMA_MIGRATION_REQUIRED"
    elif transition.decision == "RESCAN_REQUIRED":
        action = "REWIND_RESCAN_REVIEW"
        reason = "REORG_OR_ROLLBACK_SUSPECTED"
    else:
        action = "REVALIDATE_BEFORE_RESCAN"
        reason = "UNVERIFIED_INTERRUPTION"
    return OfflineResumeReview(
        action=action, reason=reason, revision=transition.new_revision,
        interrupted_height=interrupted_height,
        claimed_checkpoint_height=transition.checkpoint_height,
    )
