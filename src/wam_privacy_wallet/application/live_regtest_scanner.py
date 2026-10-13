"""Real localhost Core-shaped REGTEST → pinned WSP-1 Scanner/SQLite seam.

Actual network requests; NO mock, synthetic peer, subprocess, Core launch,
Signer, Keyring, broadcast, mainnet, or hosted scanner fallback. A localhost
peer can lie about process identity: all returned values remain UNTRUSTED.
"""
from __future__ import annotations

from pathlib import Path
from collections.abc import Callable

from wam_privacy_wallet.application.qualified_scan_session import (
    SourceQualifiedScanRuntime,
)
from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import Wsp1ScannerOnlyRpc
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
from wam_privacy_wallet.node.regtest_gateway import LocalRegtestIdentityGateway


class LiveRegtestScanError(ValueError):
    """Fixed-code failure; no URL, credential, account or raw RPC leak."""


def scan_existing_regtest(
    source_root: Path,
    private_dir: Path,
    scan_password: bytes,
    *,
    endpoint: LocalRegtestEndpoint,
    rpc_auth: ExplicitRpcAuth,
    user_consented: bool,
    acknowledge_unverified_binary: bool,
    max_blocks: int = 16,
    history_limit: int | None = None,
    save_checkpoint: bool = False,
    restore_checkpoint: bool = False,
    receive_account_index: int | None = None,
    show_observed_balance: bool = False,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, object]:
    """Execute genuine pinned WSP Scanner.sync against an existing RPC socket.

    This scans disposable scan-only accounts on Linux x64 and does NOT launch
    or authenticate the WAM Core executable. The identity/profile probes are
    before and after scan: a moving peer fails closed. No success fallback.
    """
    if (user_consented is not True or acknowledge_unverified_binary is not True
            or type(endpoint) is not LocalRegtestEndpoint
            or type(rpc_auth) is not ExplicitRpcAuth
            or type(max_blocks) is not int or not 1 <= max_blocks <= 16
            or (history_limit is not None and
                (type(history_limit) is not int or not 1 <= history_limit <= 100))
            or type(save_checkpoint) is not bool
            or type(restore_checkpoint) is not bool
            or (restore_checkpoint and save_checkpoint)
            or (receive_account_index is not None and (
                type(receive_account_index) is not int
                or not 0 <= receive_account_index < 16))
            or type(show_observed_balance) is not bool
            or (cancelled is not None and not callable(cancelled))):
        raise LiveRegtestScanError("LIVE_SCAN_CONSENT_OR_SCOPE_DENIED")
    if (type(source_root) is not type(Path()) or not source_root.is_absolute()
            or type(private_dir) is not type(Path()) or not private_dir.is_absolute()
            or type(scan_password) is not bytes
            or not 12 <= len(scan_password) <= 1024):
        raise LiveRegtestScanError("LIVE_SCAN_INPUT_DENIED")
    session = None
    try:
        if cancelled is not None and cancelled():
            raise LiveRegtestScanError("LIVE_SCAN_CANCELLED")
        gateway = LocalRegtestIdentityGateway(endpoint, rpc_auth, timeout=3)
        before = gateway.probe_core_profile()
        runtime = SourceQualifiedScanRuntime(source_root, user_consented=True)
        session = (runtime.restore(private_dir, scan_password, user_consented=True)
                   if restore_checkpoint else
                   runtime.open(private_dir, scan_password, user_consented=True))
        rpc = Wsp1ScannerOnlyRpc(endpoint, rpc_auth, timeout=3)
        scan_args = {"cancelled": cancelled} if cancelled is not None else {}
        snapshot = session.scan(
            rpc, user_consented=True, max_blocks=max_blocks, **scan_args,
        )
        if cancelled is not None and cancelled():
            raise LiveRegtestScanError("LIVE_SCAN_CANCELLED")
        after = gateway.probe_core_profile()
        if before != after or session.closed:
            raise LiveRegtestScanError("LIVE_SCAN_PEER_MOVED_DENIED")
        if (history_limit is not None or save_checkpoint
                or receive_account_index is not None or show_observed_balance
                or restore_checkpoint) and not snapshot.chain_current:
            raise LiveRegtestScanError("LIVE_SCAN_INCOMPLETE_DENIED")
        history = (session.history(user_consented=True, limit=history_limit)
                   if history_limit is not None else None)
        receive = (session.receive_code(
            user_consented=True, account_index=receive_account_index)
            if receive_account_index is not None else None)
        if save_checkpoint:
            session.save_checkpoint(private_dir, scan_password, user_consented=True)
        # A second post-read identity check also brackets receive/history and
        # checkpoint operations: no private output from a drifting live chain.
        if gateway.probe_core_profile() != before:
            raise LiveRegtestScanError("LIVE_SCAN_PEER_MOVED_DENIED")
        if cancelled is not None and cancelled():
            raise LiveRegtestScanError("LIVE_SCAN_CANCELLED")
        if (snapshot.core_authenticated or snapshot.wallet_operational
                or snapshot.balance_qualified or snapshot.signer_enabled
                or snapshot.broadcast_allowed or snapshot.mainnet_allowed):
            raise LiveRegtestScanError("LIVE_SCAN_AUTHORITY_DENIED")
        receipt = {
            "status": "REAL_LOOPBACK_WSP_SCAN_UNQUALIFIED_CORE",
            "source_commit": snapshot.source_commit,
            "tip_height": snapshot.tip_height,
            "blocks_processed": snapshot.blocks_processed,
            "transactions_processed": snapshot.transactions_processed,
            "rollback_blocks": snapshot.rollback_blocks,
            "chain_current": snapshot.chain_current,
            # No txids, addresses, wallet amounts, credentials or secret info.
            "observed_utxos": (snapshot.confirmed_utxo_count
                                if snapshot.chain_current else None),
            "core_binary_authenticated": False,
            "real_two_node_regtest_qualified": False,
            "wallet_operational": False,
            "signer_enabled": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
            "checkpoint_created": save_checkpoint,
            "checkpoint_restored_then_reattested": restore_checkpoint,
        }
        if receive is not None:
            # Private local, explicit operator-only receive projection.
            # Not evidence that the Core executable or wallet is qualified.
            receipt["unqualified_receive_code"] = receive.code
        if show_observed_balance:
            # Never call this a spendable or validated wallet balance.
            receipt["unqualified_confirmed_atoms"] = snapshot.unqualified_confirmed_atoms
        if history is not None:
            # Explicit local-interactive private view. Never log these records
            # or put them in read-only public Qt evidence/CI output.
            receipt["private_history"] = [
                {
                    "txid": row.txid,
                    "height": row.height,
                    "confirmations": row.confirmations,
                    "credit_atoms": row.credit_atoms,
                    "debit_atoms": row.debit_atoms,
                } for row in history.records
            ]
        return receipt
    except LiveRegtestScanError:
        raise
    except Exception:
        raise LiveRegtestScanError("LIVE_SCAN_DENIED") from None
    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                # A scanner close failure leaves SQLite/file custody ambiguous.
                # Never return a success receipt after an unqualified close.
                raise LiveRegtestScanError("LIVE_SCAN_CLOSE_DENIED") from None
