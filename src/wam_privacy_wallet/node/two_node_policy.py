"""G1-03: inspect a proposed two-node regtest topology; execute NOTHING.

This is a fail-closed offline equality/policy check against G1-01's canonical
planner. It is not a WAM Core option compatibility check or permission to run.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Literal

from .two_node_topology import TwoNodePlan, PlannedNode, TwoNodeTopologyError, plan_two_node_topology


class TwoNodePolicyError(ValueError):
    """Redacted, stable denial code."""


@dataclass(frozen=True, slots=True)
class TopologyPolicyEvidence:
    status: Literal["OFFLINE_CANDIDATE_SHAPE_ONLY"] = "OFFLINE_CANDIDATE_SHAPE_ONLY"
    nodes: int = 2
    loopback_only: bool = True
    real_regtest_qualified: bool = False
    external_network_allowed: bool = False
    scanner_enabled: bool = False
    signer_enabled: bool = False
    release_allowed: bool = False


def audit_two_node_policy(candidate: object) -> TopologyPolicyEvidence:
    """Deny forged plans, altered config, public peers, or authority escalation.

    Recomputes a canonical proposal from strictly validated ports. Equality
    rejects even a single extra, removed, changed or reordered config setting.
    G1-01 is a *candidate* template: accepting its exact bytes does NOT prove
    the real binary accepts the options or behaves safely.
    """
    if type(candidate) is not TwoNodePlan:
        raise TwoNodePolicyError("G1_POLICY_PLAN_REQUIRED")
    if type(candidate.nodes) is not tuple or len(candidate.nodes) != 2:
        raise TwoNodePolicyError("G1_POLICY_PLAN_INVALID")
    a, b = candidate.nodes
    if type(a) is not PlannedNode or type(b) is not PlannedNode:
        raise TwoNodePolicyError("G1_POLICY_PLAN_INVALID")
    ports = (a.rpc_port, a.p2p_port, b.rpc_port, b.p2p_port)
    try:
        canonical = plan_two_node_topology(ports)
    except (TwoNodeTopologyError, ValueError, TypeError):
        raise TwoNodePolicyError("G1_POLICY_PLAN_INVALID") from None
    if candidate != canonical:
        raise TwoNodePolicyError("G1_POLICY_PLAN_INVALID")
    return TopologyPolicyEvidence()
