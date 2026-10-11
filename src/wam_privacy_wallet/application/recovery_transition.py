"""Strict, offline-only two-snapshot recovery/rollback transition review.

The caller supplies all metadata. A matching sequence can still be forged:
neither read-only models nor sequence monotonicity authenticate WAM Core,
chain consensus, DB ownership, locks, WAL durability, or keys. No IO or RPC.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .recovery_disposition import (
    RecoveryDispositionError, evaluate_offline_recovery_disposition,
)


class OfflineRecoveryTransitionError(ValueError):
    """A fixed redacted error code; never includes a caller-supplied value."""


@dataclass(frozen=True, slots=True)
class OfflineRecoveryTransition:
    """Scalar-only, non-authorizing recovery research signal."""

    reason: Literal[
        "NO_TRUSTED_RECOVERY_EVIDENCE", "VERSION_DOWNGRADE",
        "CHECKPOINT_ROLLBACK", "CHECKPOINT_FORK_OR_RESTORE",
        "MIGRATION_RESCAN_REQUIRED", "RESCAN_REQUIRED",
    ]
    decision: Literal[
        "REVIEW_ONLY_NOT_VERIFIED", "RESCAN_REQUIRED",
        "MIGRATION_RESCAN_REQUIRED",
    ]
    old_revision: int
    new_revision: int
    checkpoint_height: int
    status: Literal["SYNTHETIC_TRANSITION_UNTRUSTED"] = field(
        default="SYNTHETIC_TRANSITION_UNTRUSTED", init=False
    )
    writer_verified: bool = field(default=False, init=False)
    chain_verified: bool = field(default=False, init=False)
    recovery_completed: bool = field(default=False, init=False)
    wallet_enabled: bool = field(default=False, init=False)


def evaluate_offline_recovery_transition(
    *, old: object, candidate: object,
    old_revision: object, new_revision: object,
) -> OfflineRecoveryTransition:
    """Fail closed on invalid inputs; classify a synthetic checkpoint change.

    Exact sequential revision prevents accidental stale/cross-session reuse.
    A *normal* transition remains REVIEW_ONLY_NOT_VERIFIED; it cannot prove
    persistence or actual chain progress. Never writes any state.
    """
    if (type(old_revision) is not int or not 0 <= old_revision < 2**63 - 1
            or type(new_revision) is not int
            or new_revision != old_revision + 1):
        raise OfflineRecoveryTransitionError("RECOVERY_TRANSITION_REVISION_DENIED")
    try:
        previous = evaluate_offline_recovery_disposition(old)
        current = evaluate_offline_recovery_disposition(candidate)
    except RecoveryDispositionError:
        raise OfflineRecoveryTransitionError("RECOVERY_TRANSITION_INPUT_DENIED") from None
    # The validated input dictionaries are still untrusted Python fixtures.
    # Use hash equality transiently for fork/restore *detection*, not identity
    # attestation; do not retain any hashes or raw input in the output.
    if current.store_schema_version < previous.store_schema_version:
        decision, reason = "RESCAN_REQUIRED", "VERSION_DOWNGRADE"
    elif current.store_schema_version in (0, 2):
        decision, reason = "MIGRATION_RESCAN_REQUIRED", "MIGRATION_RESCAN_REQUIRED"
    elif current.checkpoint_height < previous.checkpoint_height:
        decision, reason = "RESCAN_REQUIRED", "CHECKPOINT_ROLLBACK"
    elif (current.checkpoint_height == previous.checkpoint_height
            and candidate["checkpoint_hash"] != old["checkpoint_hash"]):
        decision, reason = "RESCAN_REQUIRED", "CHECKPOINT_FORK_OR_RESTORE"
    elif current.decision == "RESCAN_REQUIRED":
        decision, reason = "RESCAN_REQUIRED", "RESCAN_REQUIRED"
    else:
        decision, reason = "REVIEW_ONLY_NOT_VERIFIED", "NO_TRUSTED_RECOVERY_EVIDENCE"
    return OfflineRecoveryTransition(
        reason=reason, decision=decision,
        old_revision=old_revision, new_revision=new_revision,
        checkpoint_height=current.checkpoint_height,
    )
