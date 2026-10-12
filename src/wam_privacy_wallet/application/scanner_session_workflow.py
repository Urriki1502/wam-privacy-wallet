"""Explicit-consent application workflow for local WSP-1-shaped RPC observations.

This is a read-only, bounded *observation*, not a wallet scanner. No WSP engine
import, wallet keys/database, signing, broadcast, Core launch or remote peers.
Credentials remain only in an ephemeral RPC instance, never returned in DTOs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Literal

from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import (
    Wsp1ScannerOnlyRpc, WspScannerRpcError,
)
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth

_MAX_BATCH = 16
_MAX_TX_OBSERVED = 20_000


class ScannerObservationError(ValueError):
    """Fixed denial code, never a source credential or block payload."""


@dataclass(frozen=True, slots=True)
class ScannerReadOnlyObservation:
    """Scalar-only, untrusted projection. No endpoint/auth/binary/keys retained."""

    reported_tip_height: int
    blocks_observed: int
    transactions_observed: int
    mempool_ids_observed: int
    status: Literal["LOCAL_RPC_OBSERVED_UNTRUSTED"] = field(
        default="LOCAL_RPC_OBSERVED_UNTRUSTED", init=False,
    )
    scanner_enabled: bool = field(default=False, init=False)
    wallet_ready: bool = field(default=False, init=False)
    chain_verified: bool = field(default=False, init=False)
    core_execution_allowed: bool = field(default=False, init=False)
    signer_enabled: bool = field(default=False, init=False)
    broadcast_allowed: bool = field(default=False, init=False)
    mainnet_allowed: bool = field(default=False, init=False)


def observe_local_scanner_session(
    endpoint: LocalRegtestEndpoint,
    auth: ExplicitRpcAuth,
    *,
    user_consented: bool,
    first_height: int | None = None,
    max_blocks: int = 1,
    include_mempool: bool = False,
    cancelled: Callable[[], bool] | None = None,
    timeout: float = 3.0,
) -> ScannerReadOnlyObservation:
    """Observe only bounded hashes/blocks/mempool counts after explicit consent.

    Actual WSP-1 Scanner.sync/Store is intentionally NOT used. This function
    does not create a persistent scanner authorization or cached session.
    """
    if (
        user_consented is not True
        or type(endpoint) is not LocalRegtestEndpoint
        or type(auth) is not ExplicitRpcAuth
        or type(include_mempool) is not bool
        or type(max_blocks) is not int or not 1 <= max_blocks <= _MAX_BATCH
        or (first_height is not None and
            (type(first_height) is not int
             or not 1 <= first_height <= 100_000_000))
        or (cancelled is not None and not callable(cancelled))
        or type(timeout) not in (int, float) or not 0 < timeout <= 10
    ):
        raise ScannerObservationError("APP_SCANNER_INPUT_DENIED")

    try:
        session = Wsp1ScannerOnlyRpc(
            endpoint, auth, include_mempool=include_mempool, timeout=timeout,
        )
        session.attest()
        height = session.call("getblockcount")
        tip = session.call("getbestblockhash")
        if (type(height) is not int or not 0 <= height <= 100_000_000
                or type(tip) is not str or len(tip) != 64):
            raise ScannerObservationError("APP_SCANNER_OBSERVATION_DENIED")
        if first_height is not None and first_height > height:
            raise ScannerObservationError("APP_SCANNER_HEIGHT_AHEAD")
        observed_blocks = 0
        observed_tx = 0
        if first_height is not None:
            for block_height in range(
                first_height, min(height + 1, first_height + max_blocks),
            ):
                if cancelled is not None:
                    cancelled_result = cancelled()
                    if type(cancelled_result) is not bool or cancelled_result:
                        raise ScannerObservationError("APP_SCANNER_CANCELLED")
                block_hash = session.call("getblockhash", [block_height])
                block = session.call("getblock", [block_hash, 3])
                # The RPC adapter has validated the transaction list shape.
                observed_blocks += 1
                observed_tx += len(block["tx"])
                if observed_tx > _MAX_TX_OBSERVED:
                    raise ScannerObservationError("APP_SCANNER_WORK_LIMIT")
        mempool_count = 0
        if include_mempool:
            if cancelled is not None:
                cancelled_result = cancelled()
                if type(cancelled_result) is not bool or cancelled_result:
                    raise ScannerObservationError("APP_SCANNER_CANCELLED")
            mempool_count = len(session.call("getrawmempool", []))
        # Explicitly re-attest after application observation. This detects
        # reported tip drift but is not consensus or Core binary identity.
        session.attest()
        if (session.call("getblockcount") != height
                or session.call("getbestblockhash") != tip):
            raise ScannerObservationError("APP_SCANNER_CHAIN_DRIFT")
        return ScannerReadOnlyObservation(
            reported_tip_height=height,
            blocks_observed=observed_blocks,
            transactions_observed=observed_tx,
            mempool_ids_observed=mempool_count,
        )
    except ScannerObservationError:
        raise
    except Exception:
        # Cancel/UI callbacks and untrusted transports can raise arbitrary
        # exceptions. Never surface endpoint/credential/payload repr to Qt.
        raise ScannerObservationError("APP_SCANNER_OBSERVATION_DENIED") from None
