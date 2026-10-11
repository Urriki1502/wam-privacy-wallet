"""Bounded in-memory rescan segment / replay consistency model.

This NEVER scans a blockchain, persists a checkpoint or authorizes resumption.
Segments are hostile synthetic metadata; hash continuity is not chain proof.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Literal

from .offline_resume_review import OfflineResumeReview

_MAX_HEIGHT = 100_000_000
_MAX_SEGMENTS = 8
_MAX_BLOCKS_PER_SEGMENT = 16
_MAX_TOTAL_TX = 20_000
_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_FIELDS = frozenset({
    "start_height", "end_height", "parent_hash", "end_hash",
    "transaction_count", "attempt",
})


class OfflineRescanSegmentsError(ValueError):
    """Redacted structural failure, never containing a caller-supplied value."""


@dataclass(frozen=True, slots=True)
class OfflineRescanSegments:
    """Scalar-only synthetic accounting preview, NOT a persisted progress token."""

    status: Literal["OFFLINE_RESCAN_UNTRUSTED"] = field(
        default="OFFLINE_RESCAN_UNTRUSTED", init=False
    )
    disposition: Literal["NO_SEGMENTS", "CONTIGUOUS_UNVERIFIED", "REPLAY_NOT_APPLIED"]
    resume_action: Literal[
        "REVALIDATE_BEFORE_RESCAN", "REWIND_RESCAN_REVIEW",
        "MIGRATION_RESCAN_REVIEW",
    ]
    revision: int
    start_height: int
    observed_end_height: int
    unique_segment_count: int
    replay_count: int
    observed_block_count: int
    observed_transaction_count: int
    scanner_enabled: bool = field(default=False, init=False)
    resume_authorized: bool = field(default=False, init=False)
    checkpoint_durable: bool = field(default=False, init=False)
    chain_verified: bool = field(default=False, init=False)
    wallet_enabled: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)


def _valid_hash(x: object) -> bool:
    return type(x) is str and _HASH.fullmatch(x) is not None


def _valid_resume(x: object) -> bool:
    if type(x) is not OfflineResumeReview:
        return False
    allowed = {
        "REVALIDATE_BEFORE_RESCAN": "UNVERIFIED_INTERRUPTION",
        "REWIND_RESCAN_REVIEW": "REORG_OR_ROLLBACK_SUSPECTED",
        "MIGRATION_RESCAN_REVIEW": "SCHEMA_MIGRATION_REQUIRED",
    }
    return (
        type(x.revision) is int and 1 <= x.revision < 2**63
        and type(x.interrupted_height) is int
        and type(x.claimed_checkpoint_height) is int
        and 0 <= x.claimed_checkpoint_height <= x.interrupted_height <= _MAX_HEIGHT
        and type(x.action) is str and type(x.reason) is str
        and allowed.get(x.action) == x.reason
        and type(x.status) is str and x.status == "OFFLINE_RESUME_UNTRUSTED"
        and x.scanner_enabled is False and x.resume_authorized is False
        and x.checkpoint_durable is False and x.chain_verified is False
        and x.wallet_enabled is False and x.release_allowed is False
    )


def inspect_offline_rescan_segments(
    *, resume: object, expected_revision: object,
    start_height: object, segments: object,
) -> OfflineRescanSegments:
    """Inspect a small contiguous batch and at most one immediate exact replay.

    A repeated segment is NOT double-counted only when ALL six fields match
    the preceding segment. No hashes or input objects survive in output.
    There is no persistent deduplication across calls or crash restarts.
    """
    if not _valid_resume(resume):
        raise OfflineRescanSegmentsError("RESCAN_RESUME_DENIED")
    if (type(expected_revision) is not int
            or expected_revision != resume.revision):
        raise OfflineRescanSegmentsError("RESCAN_REVISION_DENIED")
    if type(start_height) is not int or not 0 <= start_height <= _MAX_HEIGHT:
        raise OfflineRescanSegmentsError("RESCAN_ANCHOR_DENIED")
    if type(segments) is not tuple or len(segments) > _MAX_SEGMENTS:
        raise OfflineRescanSegmentsError("RESCAN_BATCH_DENIED")

    expected = start_height
    prev_hash = None
    seen_hashes = set()
    previous_segment = None
    unique_count = 0
    replay_count = 0
    block_count = 0
    tx_count = 0
    for piece in segments:
        if type(piece) is not dict or set(piece) != _FIELDS or any(
            type(k) is not str for k in piece
        ):
            raise OfflineRescanSegmentsError("RESCAN_SEGMENT_SHAPE_DENIED")
        start, end = piece["start_height"], piece["end_height"]
        tx, attempt = piece["transaction_count"], piece["attempt"]
        parent, terminal = piece["parent_hash"], piece["end_hash"]
        if (type(start) is not int or type(end) is not int
                or not 0 <= start < end <= _MAX_HEIGHT
                or end - start > _MAX_BLOCKS_PER_SEGMENT
                or type(tx) is not int or not 0 <= tx <= _MAX_TOTAL_TX
                or type(attempt) is not int or not 1 <= attempt <= 4
                or not _valid_hash(parent) or not _valid_hash(terminal)):
            raise OfflineRescanSegmentsError("RESCAN_SEGMENT_SHAPE_DENIED")

        if previous_segment is not None and piece == previous_segment:
            if replay_count != 0:
                raise OfflineRescanSegmentsError("RESCAN_REPLAY_EXCESS_DENIED")
            replay_count = 1
            continue
        if start != expected:
            raise OfflineRescanSegmentsError("RESCAN_GAP_OR_OVERLAP_DENIED")
        if parent == terminal or terminal in seen_hashes or parent in seen_hashes and parent != prev_hash:
            raise OfflineRescanSegmentsError("RESCAN_SEGMENT_CYCLE_DENIED")
        if prev_hash is not None and parent != prev_hash:
            raise OfflineRescanSegmentsError("RESCAN_LINK_CONFLICT_DENIED")
        # Replay may only appear as the final piece: once observed, another
        # *new* interval would make this untrusted accounting ambiguous.
        if replay_count:
            raise OfflineRescanSegmentsError("RESCAN_REPLAY_ORDER_DENIED")
        tx_count += tx
        if tx_count > _MAX_TOTAL_TX:
            raise OfflineRescanSegmentsError("RESCAN_WORK_DENIED")
        block_count += end - start
        expected = end
        prev_hash = terminal
        seen_hashes.add(parent)
        seen_hashes.add(terminal)
        previous_segment = piece
        unique_count += 1

    return OfflineRescanSegments(
        disposition=("REPLAY_NOT_APPLIED" if replay_count
                     else "CONTIGUOUS_UNVERIFIED" if unique_count
                     else "NO_SEGMENTS"),
        resume_action=resume.action,
        revision=resume.revision,
        start_height=start_height,
        observed_end_height=expected,
        unique_segment_count=unique_count,
        replay_count=replay_count,
        observed_block_count=block_count,
        observed_transaction_count=tx_count,
    )
