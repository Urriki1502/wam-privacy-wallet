"""Pure, bounded WSP scanner window coherence model (offline fixtures only).

No WSP scanner/Store import, network/RPC, filesystem, wallet state, keys, or
process launch. Matching block links and stable reported tips CANNOT attest
WAM Core, prevent a dishonest node, or establish authority to scan/spend.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Literal

from .scanner_response_contract import (
    ScannerResponseShapeError, validate_offline_confirmed_block,
)

_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_HEIGHT = 100_000_000
_MAX_BLOCKS = 16
_MAX_WINDOW_TX = 20_000


class OfflineScanWindowError(ValueError):
    """Non-sensitive fail-closed error code; never includes fixture data."""


@dataclass(frozen=True, slots=True)
class OfflineScanWindowSummary:
    """Scalar-only untrusted summary, not a chain or wallet attestation."""

    start_height: int
    end_height: int
    block_count: int
    transaction_count: int
    status: Literal["SYNTHETIC_COHERENCE_ONLY"] = field(
        default="SYNTHETIC_COHERENCE_ONLY", init=False
    )
    chain_identity_verified: bool = field(default=False, init=False)
    rpc_authenticated: bool = field(default=False, init=False)
    scanner_enabled: bool = field(default=False, init=False)
    wallet_ready: bool = field(default=False, init=False)


def _hash(value: object) -> bool:
    return type(value) is str and _HASH.fullmatch(value) is not None


def validate_offline_scan_window(
    *, start_height: object, start_hash: object,
    reported_tip_before: object, reported_tip_after: object,
    blocks: object,
) -> OfflineScanWindowSummary:
    """Validate an in-memory synthetic contiguous sequence, all-or-nothing.

    Both tips are caller-supplied (height, hash) tuples, not RPC attestations.
    The sequence is a research model of the pinned WSP _sync reorg checks.
    It is NOT an adapter or permission to call getblock or a real WAM daemon.
    All nested data is consumed as untrusted input and discarded.
    """
    if (type(start_height) is not int
            or not 0 <= start_height <= _MAX_HEIGHT
            or not _hash(start_hash)):
        raise OfflineScanWindowError("SCAN_WINDOW_ANCHOR_DENIED")
    if (type(reported_tip_before) is not tuple
            or type(reported_tip_after) is not tuple
            or len(reported_tip_before) != 2
            or len(reported_tip_after) != 2):
        raise OfflineScanWindowError("SCAN_WINDOW_TIP_SHAPE_DENIED")
    for tip in (reported_tip_before, reported_tip_after):
        if (type(tip[0]) is not int
                or not 0 <= tip[0] <= _MAX_HEIGHT
                or not _hash(tip[1])):
            raise OfflineScanWindowError("SCAN_WINDOW_TIP_SHAPE_DENIED")
    if reported_tip_before != reported_tip_after:
        raise OfflineScanWindowError("SCAN_WINDOW_TIP_CHANGED")
    height, tiphash = reported_tip_before
    if height < start_height:
        raise OfflineScanWindowError("SCAN_WINDOW_HEIGHT_REWIND")
    if type(blocks) is not tuple or len(blocks) > _MAX_BLOCKS:
        raise OfflineScanWindowError("SCAN_WINDOW_BATCH_DENIED")
    if len(blocks) > height - start_height:
        raise OfflineScanWindowError("SCAN_WINDOW_OVERRUN")
    if height > start_height and not blocks:
        raise OfflineScanWindowError("SCAN_WINDOW_EMPTY_BEHIND")
    if height == start_height and start_hash != tiphash:
        raise OfflineScanWindowError("SCAN_WINDOW_ANCHOR_MISMATCH")
    previous = start_hash
    seen_block_hashes = {start_hash}
    count = 0
    for index, block in enumerate(blocks, 1):
        if type(block) is not dict or not _hash(block.get("hash")):
            raise OfflineScanWindowError("SCAN_WINDOW_BLOCK_DENIED")
        current_hash = block["hash"]
        # A canonical chain window cannot revisit the anchor or reuse a block
        # identity at a second height, even if previous-hash links look valid.
        if current_hash in seen_block_hashes:
            raise OfflineScanWindowError("SCAN_WINDOW_DUPLICATE_BLOCK_HASH")
        seen_block_hashes.add(current_hash)
        try:
            validated = validate_offline_confirmed_block(
                block, expected_hash=block["hash"],
                expected_previous_hash=previous, height=start_height + index,
            )
        except ScannerResponseShapeError:
            raise OfflineScanWindowError("SCAN_WINDOW_BLOCK_DENIED") from None
        count += validated.item_count
        if count > _MAX_WINDOW_TX:
            raise OfflineScanWindowError("SCAN_WINDOW_WORK_DENIED")
        previous = block["hash"]
    end_height = start_height + len(blocks)
    if end_height == height and previous != tiphash:
        raise OfflineScanWindowError("SCAN_WINDOW_TIP_LINK_DENIED")
    return OfflineScanWindowSummary(
        start_height, end_height, len(blocks), count,
    )
