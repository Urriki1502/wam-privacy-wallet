"""Explicitly consented WSP-1 scan-only coordinator for a prequalified engine.

This module invokes REAL Scanner.sync()/sync_mempool(), unlike the older
scalar-only RPC observation. It does NOT auto-import WSP-1 or construct account
keys: engine source approval and scan-only account custody must be established
by the calling integration (source-pinned native tests exercise this path).
All returned data is non-sensitive and untrusted until genuine Core E2E passes.
No signer, wallet spend role, transaction construction, broadcast or Core launch.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Literal

from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import Wsp1ScannerOnlyRpc

_MAX_BLOCKS_PER_RUN = 16
_MAX_TRANSACTIONS = 160_000
_MAX_MEMPOOL_TRANSACTIONS = 10_000
_MAX_REORG = 100_000


class ApplicationScanError(ValueError):
    """Fixed denial codes; upstream node, account and OS errors are redacted."""


@dataclass(frozen=True, slots=True)
class WspScanSessionSummary:
    """A result from *real WSP-1 code* against untrusted locally reported data.

    Deliberately does not expose spend/scan secrets, account identifiers, txids,
    balance, addresses, chain authority, a scanner handle or a signer.
    """

    blocks_processed: int
    transactions_processed: int
    rollback_blocks: int
    mempool_transactions_processed: int
    status: Literal["WSP1_SCAN_EXECUTED_UNTRUSTED_CORE"] = field(
        default="WSP1_SCAN_EXECUTED_UNTRUSTED_CORE", init=False,
    )
    core_authenticated: bool = field(default=False, init=False)
    wallet_operational: bool = field(default=False, init=False)
    balance_qualified: bool = field(default=False, init=False)
    signer_enabled: bool = field(default=False, init=False)
    broadcast_allowed: bool = field(default=False, init=False)
    mainnet_allowed: bool = field(default=False, init=False)


def run_consented_wsp_scan(
    scanner: object,
    rpc: Wsp1ScannerOnlyRpc,
    *,
    user_consented: bool,
    max_blocks: int = 1,
    include_mempool: bool = False,
    cancelled: Callable[[], bool] | None = None,
) -> WspScanSessionSummary:
    """Perform a bounded scan with an externally source-qualified WSP Scanner.

    This is NOT a WSP source loader or wallet authorization. The caller must
    independently verify the WSP source commit and provide scan-only accounts;
    the native integration CI verifies this against the exact pinned revision.
    Scanner.sync() itself owns the upstream OS/SQLite single-writer lease.
    Do not duplicate a fake application lock or assume a successful scan proves
    the local node's consensus or executable identity.
    """
    if (
        user_consented is not True
        or type(rpc) is not Wsp1ScannerOnlyRpc
        or type(max_blocks) is not int or not 1 <= max_blocks <= _MAX_BLOCKS_PER_RUN
        or type(include_mempool) is not bool
        or (cancelled is not None and not callable(cancelled))
    ):
        raise ApplicationScanError("APP_WSP_SCAN_INPUT_DENIED")

    # Scanner objects must be explicitly supplied by the upstream source-pinned
    # coordinator. There is no built-in mock fallback or engine autoload.
    if scanner is None or not callable(getattr(scanner, "sync", None)):
        raise ApplicationScanError("APP_WSP_SCAN_ENGINE_REQUIRED")
    if include_mempool:
        if not rpc._mempool or not callable(getattr(scanner, "sync_mempool", None)):
            raise ApplicationScanError("APP_WSP_SCAN_MEMPOOL_SCOPE_DENIED")

    def stop_if_requested() -> bool:
        if cancelled is None:
            return False
        try:
            response = cancelled()
            # Invalid callback outputs must stop, never silently continue.
            return type(response) is not bool or response
        except Exception:
            return True

    if stop_if_requested():
        raise ApplicationScanError("APP_WSP_SCAN_CANCELLED")

    try:
        # This is the REAL pinned WSP Scanner.sync() entrypoint in native CI.
        result = scanner.sync(rpc, max_blocks=max_blocks, cancel=stop_if_requested)
        blocks = result.blocks
        transactions = result.transactions
        rollback = result.rollback
        if (
            type(blocks) is not int or not 0 <= blocks <= max_blocks
            or type(transactions) is not int
            or not 0 <= transactions <= _MAX_TRANSACTIONS
            or type(rollback) is not int or not 0 <= rollback <= _MAX_REORG
        ):
            raise ApplicationScanError("APP_WSP_SCAN_RESULT_DENIED")

        mempool_count = 0
        if include_mempool:
            # An incomplete chain scan may not qualify a mempool snapshot.
            if getattr(scanner, "ready", False) is not True:
                raise ApplicationScanError("APP_WSP_SCAN_INCOMPLETE")
            if stop_if_requested():
                raise ApplicationScanError("APP_WSP_SCAN_CANCELLED")
            mempool_count = scanner.sync_mempool(rpc)
            if (type(mempool_count) is not int or not
                    0 <= mempool_count <= _MAX_MEMPOOL_TRANSACTIONS):
                raise ApplicationScanError("APP_WSP_SCAN_RESULT_DENIED")

        # Do not propagate the external metrics, accounts or mutable scanner
        # object. Even successful scans receive NO application wallet authority.
        return WspScanSessionSummary(
            blocks_processed=blocks,
            transactions_processed=transactions,
            rollback_blocks=rollback,
            mempool_transactions_processed=mempool_count,
        )
    except ApplicationScanError:
        raise
    except Exception:
        # Upstream scanner, callback and SQLite errors may embed private data.
        raise ApplicationScanError("APP_WSP_SCAN_RUNTIME_DENIED") from None
