"""Explicit, untrusted real two-node REGTEST Qt diagnostic; no wallet role.

Always actual loopback RPC/P2P. No fixture, node launcher, signer, storage,
mock/fallback transport or success on cancellation. Real network responses
do NOT authenticate the WAM Core executable or separate processes.
"""
from __future__ import annotations

from dataclasses import dataclass
from threading import Event

from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
from wam_privacy_wallet.node.regtest_gateway import LocalRegtestIdentityGateway
from wam_privacy_wallet.node.two_node_p2p_readonly import TwoNodeP2PReadOnlyAudit
from wam_privacy_wallet.node.two_node_core_readiness import inspect_existing_core_readiness


class LiveNodeGuiProbeError(ValueError):
    """Fixed non-sensitive refusal; never include RPC credentials or paths."""


@dataclass(frozen=True, slots=True, repr=False)
class LiveNodeGuiEvidence:
    tip_height: int
    status: str = "TWO_NODE_REPORTED_CHAIN_ONLY_UNTRUSTED"
    two_peer_topology_observed: bool = True
    same_reported_chain: bool = True
    synchronized_indexes_observed: bool = False
    core_authenticated: bool = False
    independent_processes_verified: bool = False
    wallet_operational: bool = False
    signing_allowed: bool = False
    broadcast_allowed: bool = False
    mainnet_allowed: bool = False

    def __post_init__(self):
        if (type(self.tip_height) is not int or
                not 0 <= self.tip_height <= 100_000_000 or
                self.status != "TWO_NODE_REPORTED_CHAIN_ONLY_UNTRUSTED" or
                self.two_peer_topology_observed is not True or
                self.same_reported_chain is not True or
                type(self.synchronized_indexes_observed) is not bool or
                any(getattr(self, field) is not False for field in (
                    "core_authenticated", "independent_processes_verified",
                    "wallet_operational", "signing_allowed",
                    "broadcast_allowed", "mainnet_allowed"))):
            raise LiveNodeGuiProbeError("LIVE_NODE_GUI_EVIDENCE_DENIED")


def inspect_existing_two_nodes(
    a: LocalRegtestEndpoint, aa: ExplicitRpcAuth,
    b: LocalRegtestEndpoint, bb: ExplicitRpcAuth, *,
    p2p_a: int, p2p_b: int, user_consented: bool,
    acknowledged_unverified_core: bool, cancelled: Event,
    check_index_filters: bool = False,
) -> LiveNodeGuiEvidence:
    """A blocking background-worker ONLY operation with genuine RPC I/O."""
    if (type(a) is not LocalRegtestEndpoint or
            type(b) is not LocalRegtestEndpoint or a == b or
            a.host != "127.0.0.1" or b.host != "127.0.0.1" or
            type(aa) is not ExplicitRpcAuth or type(bb) is not ExplicitRpcAuth or
            aa == bb or type(p2p_a) is not int or type(p2p_b) is not int or
            len({a.port, b.port, p2p_a, p2p_b}) != 4 or
            user_consented is not True or acknowledged_unverified_core is not True or
            type(check_index_filters) is not bool or type(cancelled) is not Event):
        raise LiveNodeGuiProbeError("LIVE_NODE_GUI_SCOPE_DENIED")
    if cancelled.is_set():
        raise LiveNodeGuiProbeError("LIVE_NODE_GUI_CANCELLED")
    try:
        if check_index_filters:
            # Reuse the opt-in true RPC/P2P/index audit from PR #208.
            # A positive untrusted index report never grants wallet authority.
            evidence = inspect_existing_core_readiness(
                a=a, aa=aa, b=b, bb=bb, p2p_a=p2p_a, p2p_b=p2p_b,
                consent=True, acknowledge_unverified_processes=True,
            )
            if cancelled.is_set():
                raise LiveNodeGuiProbeError("LIVE_NODE_GUI_CANCELLED")
            if (type(evidence) is not dict
                    or evidence.get("status") != "OBSERVED_LIVE_TWO_NODE_REGTEST_RPC_AND_INDEXES_UNTRUSTED"
                    or type(evidence.get("height")) is not int
                    or evidence.get("synchronized_index_and_basic_filter_reports") is not True
                    or evidence.get("two_node_loopback_p2p_observed") is not True
                    or any(evidence.get(flag) is not False for flag in (
                        "core_executable_authenticated", "independent_processes_verified",
                        "real_core_e2e_accepted", "wsp_scanning_enabled",
                        "wallet_operational", "signing_allowed", "broadcast_allowed",
                        "mainnet_allowed"))):
                raise LiveNodeGuiProbeError("LIVE_NODE_GUI_INDEX_RECEIPT_DENIED")
            return LiveNodeGuiEvidence(evidence["height"],
                synchronized_indexes_observed=True)
        gw_a = LocalRegtestIdentityGateway(a, aa, timeout=3)
        gw_b = LocalRegtestIdentityGateway(b, bb, timeout=3)
        first_a, first_b = gw_a.probe_core_profile(), gw_b.probe_core_profile()
        if cancelled.is_set():
            raise LiveNodeGuiProbeError("LIVE_NODE_GUI_CANCELLED")
        audit = TwoNodeP2PReadOnlyAudit(
            a, aa, b, bb, node_a_p2p_port=p2p_a, node_b_p2p_port=p2p_b,
        ).audit()
        if (type(audit) is not dict or
                audit.get("status") != "UNTRUSTED_LOCAL_REGTEST_P2P_TOPOLOGY_ONLY" or
                audit.get("peer_count_a") != 1 or audit.get("peer_count_b") != 1 or
                any(audit.get(k) is not True for k in (
                    "localhost_only_observed", "expected_direction_observed",
                    "reported_chain_agrees")) or
                any(audit.get(k) is not False for k in (
                    "genuine_wam_process_verified", "independent_processes_verified",
                    "external_network_exclusion_proven", "real_two_node_regtest_qualified",
                    "scanner_enabled", "wallet_ready", "signing_allowed",
                    "broadcast_allowed", "mainnet_allowed"))):
            raise LiveNodeGuiProbeError("LIVE_NODE_GUI_AUDIT_DENIED")
        if cancelled.is_set():
            raise LiveNodeGuiProbeError("LIVE_NODE_GUI_CANCELLED")
        last_a, last_b = gw_a.probe_core_profile(), gw_b.probe_core_profile()
        if (first_a != last_a or first_b != last_b or
                first_a.identity.genesis != first_b.identity.genesis or
                first_a.identity.height != first_b.identity.height or
                first_a.identity.best_block_hash != first_b.identity.best_block_hash):
            raise LiveNodeGuiProbeError("LIVE_NODE_GUI_CHAIN_MOVED_DENIED")
        if cancelled.is_set():
            raise LiveNodeGuiProbeError("LIVE_NODE_GUI_CANCELLED")
        return LiveNodeGuiEvidence(first_a.identity.height)
    except LiveNodeGuiProbeError:
        raise
    except Exception:
        raise LiveNodeGuiProbeError("LIVE_NODE_GUI_PROBE_DENIED") from None
