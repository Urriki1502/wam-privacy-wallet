"""Fail-closed OFFLINE scanner response-shape prefilter; no wallet authority.

Complements the frozen Phase 010 RPC request contract without importing it.
A matching payload could still be invented by an attacker: this module cannot
attest chain identity, detect reorgs, authenticate RPC or process real coins.
Neither scanner nor node is executed; inputs are not retained or logged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Literal

_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_HEIGHT = 100_000_000
_MAX_BLOCK_TX = 10_000  # Exact WSP-1 Limits.max_block_transactions pin.
_MAX_MEMPOOL_TX = 10_000  # Exact WSP-1 Scanner.sync_mempool() pin.


class ScannerResponseShapeError(ValueError):
    """Stable redacted errors; never includes node-supplied response fields."""


@dataclass(frozen=True, slots=True)
class OfflineScannerResponseSummary:
    """Non-authorizing metadata only; no transaction data, addresses or keys."""

    item_count: int
    height: int | None
    phase: Literal["confirmed", "mempool"]
    status: Literal["SHAPE_ONLY_UNTRUSTED"] = field(
        default="SHAPE_ONLY_UNTRUSTED", init=False
    )
    scanner_enabled: bool = field(default=False, init=False)
    chain_identity_verified: bool = field(default=False, init=False)
    wallet_ready: bool = field(default=False, init=False)


def _hash(value: object) -> bool:
    return type(value) is str and _HASH.fullmatch(value) is not None


def validate_offline_confirmed_block(
    block: object, *, expected_hash: object,
    expected_previous_hash: object, height: object,
) -> OfflineScannerResponseSummary:
    """Check bounded WSP getblock(hash,3) response *shape*, not authenticity.

    Height >= 1 because the pinned upstream Scanner._sync() processes blocks
    after its stored ancestor; genesis must instead be independently attested.
    No transaction processing, fee parsing, storage, WSP import or RPC.
    """
    if (not _hash(expected_hash) or not _hash(expected_previous_hash)
            or type(height) is not int or not 1 <= height <= _MAX_HEIGHT):
        raise ScannerResponseShapeError("SCAN_BLOCK_EXPECTATION_INVALID")
    if type(block) is not dict:
        raise ScannerResponseShapeError("SCAN_BLOCK_SHAPE_DENIED")
    if (type(block.get("hash")) is not str
            or block["hash"] != expected_hash
            or type(block.get("previousblockhash")) is not str
            or block["previousblockhash"] != expected_previous_hash
            or type(block.get("height")) is not int
            or block["height"] != height):
        raise ScannerResponseShapeError("SCAN_BLOCK_CHAIN_MISMATCH")
    transactions = block.get("tx")
    if type(transactions) is not list or len(transactions) > _MAX_BLOCK_TX:
        raise ScannerResponseShapeError("SCAN_BLOCK_TX_LIMIT")
    seen: set[str] = set()
    for tx in transactions:
        if type(tx) is not dict or not _hash(tx.get("txid")):
            raise ScannerResponseShapeError("SCAN_BLOCK_TX_SHAPE_DENIED")
        txid = tx["txid"]
        if txid in seen:
            raise ScannerResponseShapeError("SCAN_BLOCK_DUPLICATE_TX")
        seen.add(txid)
    return OfflineScannerResponseSummary(len(transactions), height, "confirmed")


def validate_offline_mempool_ids(ids: object) -> OfflineScannerResponseSummary:
    """Check a bounded list of untrusted tx IDs; no mempool RPC or persistence."""
    if type(ids) is not list or len(ids) > _MAX_MEMPOOL_TX:
        raise ScannerResponseShapeError("SCAN_MEMPOOL_LIMIT")
    seen: set[str] = set()
    for txid in ids:
        if not _hash(txid):
            raise ScannerResponseShapeError("SCAN_MEMPOOL_TXID_DENIED")
        if txid in seen:
            raise ScannerResponseShapeError("SCAN_MEMPOOL_DUPLICATE_TX")
        seen.add(txid)
    return OfflineScannerResponseSummary(len(ids), None, "mempool")
