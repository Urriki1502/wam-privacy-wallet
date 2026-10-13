"""Linux-only Qt -> REAL two-node source-pinned WSP scan, scalar evidence only.

No synthetic operational backend, no signer, no address, amount, txid, key,
telemetry or user-wallet authority. The native WSP Store MAY advance before
cancellation; no stale GUI receipt is allowed after cancellation.
"""
from __future__ import annotations

from dataclasses import dataclass
import platform
import sys
from pathlib import Path
from threading import Event

from wam_privacy_wallet.application.two_node_wsp_session import scan_two_existing_regtest_nodes
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth


class QtNativeScanError(ValueError):
    """Redacted and non-authorizing native scan error."""


@dataclass(frozen=True, slots=True, repr=False)
class QtNativeScanEvidence:
    tip_height: int
    chain_current: bool
    blocks_processed: int
    transactions_processed: int
    observed_utxos: int | None
    status: str = "REAL_WSP_TWO_NODE_SCAN_UNTRUSTED"
    core_authenticated: bool = False
    wallet_operational: bool = False
    signing_allowed: bool = False
    broadcast_allowed: bool = False
    mainnet_allowed: bool = False

    def __post_init__(self):
        if (type(self.tip_height) is not int or not 0 <= self.tip_height <= 100_000_000
                or type(self.chain_current) is not bool
                or type(self.blocks_processed) is not int
                or not 0 <= self.blocks_processed <= 16
                or type(self.transactions_processed) is not int
                or not 0 <= self.transactions_processed <= 1_000_000
                or ((self.chain_current and (type(self.observed_utxos) is not int
                      or not 0 <= self.observed_utxos <= 1_000_000))
                    or (not self.chain_current and self.observed_utxos is not None))
                or type(self.status) is not str
                or self.status != "REAL_WSP_TWO_NODE_SCAN_UNTRUSTED"
                or any(getattr(self, field) is not False for field in (
                    "core_authenticated", "wallet_operational", "signing_allowed",
                    "broadcast_allowed", "mainnet_allowed"))):
            raise QtNativeScanError("QT_NATIVE_WSP_EVIDENCE_DENIED")


def run_existing_two_node_scan(*, source_root: Path, private_dir: Path,
                               passphrase: bytes,
                               a: LocalRegtestEndpoint, aa: ExplicitRpcAuth,
                               b: LocalRegtestEndpoint, bb: ExplicitRpcAuth,
                               p2p_a: int, p2p_b: int,
                               user_consented: bool,
                               unverified_core_ack: bool,
                               cancelled: Event) -> QtNativeScanEvidence:
    if (sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64")
            or type(source_root) is not type(Path()) or not source_root.is_absolute()
            or type(private_dir) is not type(Path()) or not private_dir.is_absolute()
            or type(passphrase) is not bytes or not 12 <= len(passphrase) <= 1024
            or type(cancelled) is not Event
            or user_consented is not True or unverified_core_ack is not True
            or type(a) is not LocalRegtestEndpoint or type(b) is not LocalRegtestEndpoint
            or type(aa) is not ExplicitRpcAuth or type(bb) is not ExplicitRpcAuth
            or a == b or aa == bb or
            type(p2p_a) is not int or type(p2p_b) is not int
            or len({a.port,b.port,p2p_a,p2p_b}) != 4):
        raise QtNativeScanError("QT_NATIVE_WSP_SCOPE_DENIED")
    if cancelled.is_set():
        raise QtNativeScanError("QT_NATIVE_WSP_CANCELLED")
    try:
        # No app parameter offers private projections or alternate backend.
        data = scan_two_existing_regtest_nodes(
            source_root, private_dir, passphrase,
            node_a=a, auth_a=aa, node_b=b, auth_b=bb,
            node_a_p2p_port=p2p_a, node_b_p2p_port=p2p_b,
            user_consented=True, acknowledge_unverified_binaries=True,
            max_blocks=16, cancelled=cancelled.is_set,
        )
        if cancelled.is_set():
            raise QtNativeScanError("QT_NATIVE_WSP_CANCELLED")
        if (type(data) is not dict or
                data.get("status") != "REAL_TWO_NODE_WSP_SCAN_UNQUALIFIED_BINARIES" or
                data.get("two_node_p2p_observed") is not True or
                data.get("two_node_reported_chain_agrees") is not True or
                any(data.get(k) is not False for k in (
                    "core_binary_authenticated", "independent_core_processes_verified",
                    "real_two_node_regtest_qualified", "wallet_operational",
                    "signer_enabled", "broadcast_allowed", "mainnet_allowed")) or
                any(k in data for k in ("private_history", "unqualified_receive_code",
                                        "unqualified_confirmed_atoms"))):
            raise QtNativeScanError("QT_NATIVE_WSP_RECEIPT_DENIED")
        proof = QtNativeScanEvidence(
            data.get("tip_height"), data.get("chain_current"),
            data.get("blocks_processed"), data.get("transactions_processed"),
            data.get("observed_utxos"),
        )
        if cancelled.is_set():
            raise QtNativeScanError("QT_NATIVE_WSP_CANCELLED")
        return proof
    except QtNativeScanError:
        raise
    except Exception:
        raise QtNativeScanError("QT_NATIVE_WSP_DENIED") from None
