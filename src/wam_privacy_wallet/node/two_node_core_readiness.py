"""Cross-platform real-socket read-only WAM Core REGTEST index/P2P review.

Consumes two already-running operator-owned nodes. Does NOT download, launch,
authenticate Core executable bytes, create wallets, sign, broadcast or scan WSP.
Use only disposable loopback nodes; findings cannot assert genuine Core E2E.
"""
from __future__ import annotations

from wam_privacy_wallet.node.core_readiness_rpc import CoreRegtestReadinessRpc
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
from wam_privacy_wallet.node.regtest_gateway import LocalRegtestIdentityGateway
from wam_privacy_wallet.node.two_node_p2p_readonly import TwoNodeP2PReadOnlyAudit


class TwoNodeCoreReadinessError(ValueError):
    """Fixed and redacted, never exposes any RPC credential or peer payload."""


def inspect_existing_core_readiness(
    *,
    a: LocalRegtestEndpoint, aa: ExplicitRpcAuth, p2p_a: int,
    b: LocalRegtestEndpoint, bb: ExplicitRpcAuth, p2p_b: int,
    consent: bool, acknowledge_unverified_processes: bool,
) -> dict[str, object]:
    """Bound BOTH real localhost Core-shaped RPC endpoints with P2P/index checks.

    Same-network/tip/index/filter reports are useful compatibility evidence,
    NOT binary provenance, isolated-process identity or WSP scan authority.
    """
    if (type(a) is not LocalRegtestEndpoint or type(b) is not LocalRegtestEndpoint
            or a == b or a.host != "127.0.0.1" or b.host != "127.0.0.1"
            or type(aa) is not ExplicitRpcAuth or type(bb) is not ExplicitRpcAuth
            or aa == bb
            or type(p2p_a) is not int or type(p2p_b) is not int
            or len({a.port, b.port, p2p_a, p2p_b}) != 4
            or consent is not True or acknowledge_unverified_processes is not True):
        raise TwoNodeCoreReadinessError("TWO_CORE_READINESS_SCOPE_DENIED")
    try:
        ga = LocalRegtestIdentityGateway(a, aa, timeout=3)
        gb = LocalRegtestIdentityGateway(b, bb, timeout=3)
        before_a, before_b = ga.probe_core_profile(), gb.probe_core_profile()
        audit = TwoNodeP2PReadOnlyAudit(
            a, aa, b, bb, node_a_p2p_port=p2p_a, node_b_p2p_port=p2p_b,
        )
        first = audit.audit()
        if (type(first) is not dict
                or first.get("status") != "UNTRUSTED_LOCAL_REGTEST_P2P_TOPOLOGY_ONLY"
                or any(first.get(k) is not True for k in
                       ("localhost_only_observed", "expected_direction_observed",
                        "reported_chain_agrees"))
                or any(first.get(k) is not False for k in
                       ("genuine_wam_process_verified", "independent_processes_verified",
                        "external_network_exclusion_proven", "real_two_node_regtest_qualified",
                        "scanner_enabled", "wallet_ready", "signing_allowed",
                        "broadcast_allowed", "mainnet_allowed"))):
            raise TwoNodeCoreReadinessError("TWO_CORE_READINESS_TOPOLOGY_DENIED")
        ra = CoreRegtestReadinessRpc(a, aa, timeout=3).observe()
        rb = CoreRegtestReadinessRpc(b, bb, timeout=3).observe()
        last = audit.audit()
        after_a, after_b = ga.probe_core_profile(), gb.probe_core_profile()
        if (first != last or before_a != after_a or before_b != after_b
                or before_a.identity.genesis != before_b.identity.genesis
                or before_a.identity.height != before_b.identity.height
                or before_a.identity.best_block_hash != before_b.identity.best_block_hash
                or ra.height != rb.height
                or ra.block_hash != rb.block_hash
                or ra.filter_header != rb.filter_header
                or ra.height != before_a.identity.height
                or ra.block_hash != before_a.identity.best_block_hash):
            raise TwoNodeCoreReadinessError("TWO_CORE_READINESS_DRIFT_DENIED")
        return {
            "status": "OBSERVED_LIVE_TWO_NODE_REGTEST_RPC_AND_INDEXES_UNTRUSTED",
            "height": ra.height,
            "synchronized_index_and_basic_filter_reports": True,
            "two_node_loopback_p2p_observed": True,
            "core_executable_authenticated": False,
            "independent_processes_verified": False,
            "real_core_e2e_accepted": False,
            "wsp_scanning_enabled": False,
            "wallet_operational": False,
            "signing_allowed": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
        }
    except TwoNodeCoreReadinessError:
        raise
    except Exception:
        raise TwoNodeCoreReadinessError("TWO_CORE_READINESS_RPC_DENIED") from None
