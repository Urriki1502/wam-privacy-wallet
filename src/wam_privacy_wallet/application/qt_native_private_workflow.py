"""Native Linux, user-consented private WSP history or one-shot AES-GCM checkpoint.

An existing two-node localhost REGTEST RPC endpoint drives the actual pinned
WSP Scanner and Store. This bridge has NO signer, broadcast, fake peer or
Node binary launch. Only an explicit history request exports private txids to
the in-memory Qt worker; checkpoints expose a STATUS, never archive bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import Event
import platform
import re
import sys

from wam_privacy_wallet.application.two_node_wsp_session import scan_two_existing_regtest_nodes
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth


class QtPrivateWorkflowError(ValueError):
    """Redacted native workflow failure without customer txids or credentials."""


_OPERATIONS = frozenset(("history", "checkpoint", "restore"))
_TXID = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True, repr=False)
class PrivateQtHistoryRow:
    txid: str
    height: int
    confirmations: int
    credit_atoms: int
    debit_atoms: int

    def __post_init__(self):
        if (type(self.txid) is not str or _TXID.fullmatch(self.txid) is None
                or any(type(x) is not int for x in (
                    self.height, self.confirmations,
                    self.credit_atoms, self.debit_atoms))
                or not 1 <= self.height <= 100_000_000
                or not 1 <= self.confirmations <= 100_000_000
                or not 0 <= self.credit_atoms <= 2**63 - 1
                or not 0 <= self.debit_atoms <= 2**63 - 1
                or not (self.credit_atoms or self.debit_atoms)):
            raise QtPrivateWorkflowError("QT_PRIVATE_HISTORY_ROW_DENIED")


@dataclass(frozen=True, slots=True, repr=False)
class PrivateQtWorkflowEvidence:
    operation: str
    tip_height: int
    rows: tuple[PrivateQtHistoryRow, ...] = ()
    status: str = "REAL_WSP_TWO_NODE_PRIVATE_UNQUALIFIED"
    core_authenticated: bool = False
    wallet_operational: bool = False
    signing_allowed: bool = False
    broadcast_allowed: bool = False
    mainnet_allowed: bool = False

    def __post_init__(self):
        if (type(self.operation) is not str or self.operation not in _OPERATIONS
                or type(self.tip_height) is not int
                or not 0 <= self.tip_height <= 100_000_000
                or type(self.rows) is not tuple or len(self.rows) > 20
                or any(type(row) is not PrivateQtHistoryRow
                       for row in self.rows)
                or (self.operation != "history" and self.rows)
                or self.status != "REAL_WSP_TWO_NODE_PRIVATE_UNQUALIFIED"
                or any(getattr(self, x) is not False for x in (
                    "core_authenticated", "wallet_operational",
                    "signing_allowed", "broadcast_allowed", "mainnet_allowed"))):
            raise QtPrivateWorkflowError("QT_PRIVATE_RECEIPT_DENIED")


def run_private_wsp_workflow(*, operation: str,
                             source_root: Path, private_dir: Path,
                             passphrase: bytes, a: LocalRegtestEndpoint,
                             aa: ExplicitRpcAuth, b: LocalRegtestEndpoint,
                             bb: ExplicitRpcAuth, p2p_a: int, p2p_b: int,
                             user_consented: bool, unverified_core_ack: bool,
                             private_display_ack: bool,
                             cancelled: Event) -> PrivateQtWorkflowEvidence:
    """Perform exactly one explicitly requested operation; no fallback/telemetry."""
    if (type(operation) is not str or operation not in _OPERATIONS
            or sys.platform != "linux"
            or platform.machine().lower() not in ("x86_64", "amd64")
            or user_consented is not True or unverified_core_ack is not True
            or private_display_ack is not True
            or type(cancelled) is not Event
            or type(source_root) is not type(Path()) or not source_root.is_absolute()
            or type(private_dir) is not type(Path()) or not private_dir.is_absolute()
            or type(passphrase) is not bytes or not 12 <= len(passphrase) <= 1024
            or type(a) is not LocalRegtestEndpoint or type(b) is not LocalRegtestEndpoint
            or type(aa) is not ExplicitRpcAuth or type(bb) is not ExplicitRpcAuth
            or a == b or aa == bb
            or type(p2p_a) is not int or type(p2p_b) is not int
            or len({a.port, b.port, p2p_a, p2p_b}) != 4):
        raise QtPrivateWorkflowError("QT_PRIVATE_SCOPE_DENIED")
    if cancelled.is_set():
        raise QtPrivateWorkflowError("QT_PRIVATE_CANCELLED")
    try:
        receipt = scan_two_existing_regtest_nodes(
            source_root, private_dir, passphrase,
            node_a=a, auth_a=aa, node_b=b, auth_b=bb,
            node_a_p2p_port=p2p_a, node_b_p2p_port=p2p_b,
            user_consented=True, acknowledge_unverified_binaries=True,
            max_blocks=16,
            history_limit=20 if operation == "history" else None,
            save_checkpoint=operation == "checkpoint",
            restore_checkpoint=operation == "restore",
            cancelled=cancelled.is_set,
        )
        if cancelled.is_set():
            raise QtPrivateWorkflowError("QT_PRIVATE_CANCELLED")
        if (type(receipt) is not dict
                or receipt.get("status") != "REAL_TWO_NODE_WSP_SCAN_UNQUALIFIED_BINARIES"
                or receipt.get("chain_current") is not True
                or receipt.get("two_node_p2p_observed") is not True
                or receipt.get("two_node_reported_chain_agrees") is not True
                or type(receipt.get("tip_height")) is not int
                or any(receipt.get(k) is not False for k in (
                    "core_binary_authenticated", "independent_core_processes_verified",
                    "real_two_node_regtest_qualified", "wallet_operational",
                    "signer_enabled", "broadcast_allowed", "mainnet_allowed"))
                or "unqualified_receive_code" in receipt
                or "unqualified_confirmed_atoms" in receipt
                or receipt.get("checkpoint_created") is not (operation == "checkpoint")
                or receipt.get("checkpoint_restored_then_reattested") is not (
                    operation == "restore")
                or (operation == "history") != ("private_history" in receipt)):
            raise QtPrivateWorkflowError("QT_PRIVATE_RECEIPT_DENIED")
        records = receipt.get("private_history", ())
        if (type(records) not in (tuple, list)
                or len(records) > 20 or
                (operation != "history" and records)):
            raise QtPrivateWorkflowError("QT_PRIVATE_RECEIPT_DENIED")
        rows = []
        for item in records:
            if type(item) is not dict or set(item) != {
                "txid", "height", "confirmations", "credit_atoms", "debit_atoms",
            }:
                raise QtPrivateWorkflowError("QT_PRIVATE_RECEIPT_DENIED")
            rows.append(PrivateQtHistoryRow(
                item["txid"], item["height"], item["confirmations"],
                item["credit_atoms"], item["debit_atoms"],
            ))
        evidence = PrivateQtWorkflowEvidence(
            operation, receipt["tip_height"], tuple(rows),
        )
        if cancelled.is_set():
            raise QtPrivateWorkflowError("QT_PRIVATE_CANCELLED")
        return evidence
    except QtPrivateWorkflowError:
        raise
    except Exception:
        raise QtPrivateWorkflowError("QT_PRIVATE_WORK_DENIED") from None
