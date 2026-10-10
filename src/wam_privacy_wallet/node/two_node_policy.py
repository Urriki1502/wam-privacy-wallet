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



# Compare types *before* dataclass equality: Python intentionally treats
# False == 0 == 0.0 and integer ports == their floating-point equivalents.
# A security boundary must reject these schema changes even if values compare
# equal. This audit is still non-authorizing and never runs Core.
_PLAN_BOOL_FIELDS = (
    "real_regtest_qualified", "publisher_identity_verified",
    "scanner_enabled", "signing_enabled", "release_allowed",
)
_NODE_INT_FIELDS = ("rpc_port", "p2p_port", "peer_p2p_port")
_NODE_TEXT_FIELDS = ("label", "rpc_host", "p2p_host", "config_preview")


def _has_exact_field_types(candidate: TwoNodePlan) -> bool:
    try:
        if type(candidate.status) is not str:
            return False
        if any(type(getattr(candidate, field)) is not bool
               for field in _PLAN_BOOL_FIELDS):
            return False
        for node in candidate.nodes:
            if any(type(getattr(node, field)) is not int
                   for field in _NODE_INT_FIELDS):
                return False
            if any(type(getattr(node, field)) is not str
                   for field in _NODE_TEXT_FIELDS):
                return False
    except AttributeError:
        # Even a deliberately uninitialized frozen/slots object is denied
        # with the same redacted error code rather than leaking internals.
        return False
    return True

def audit_two_node_policy(candidate: object) -> TopologyPolicyEvidence:
    """Deny forged plans, altered config, public peers, or authority escalation.

    Recomputes a canonical proposal from strictly validated ports. Equality
    rejects even a single extra, removed, changed or reordered config setting.
    G1-01 is a *candidate* template: accepting its exact bytes does NOT prove
    the real binary accepts the options or behaves safely.
    """
    if type(candidate) is not TwoNodePlan:
        raise TwoNodePolicyError("G1_POLICY_PLAN_REQUIRED")
    try:
        nodes = candidate.nodes
    except AttributeError:
        raise TwoNodePolicyError("G1_POLICY_PLAN_INVALID") from None
    if type(nodes) is not tuple or len(nodes) != 2:
        raise TwoNodePolicyError("G1_POLICY_PLAN_INVALID")
    a, b = nodes
    if type(a) is not PlannedNode or type(b) is not PlannedNode:
        raise TwoNodePolicyError("G1_POLICY_PLAN_INVALID")
    # A numeric stand-in (0 / 0.0 for False; 32002.0 for port 32002)
    # can pass Python dataclass ==, so exact schema is mandatory first.
    if not _has_exact_field_types(candidate):
        raise TwoNodePolicyError("G1_POLICY_PLAN_INVALID")
    ports = (a.rpc_port, a.p2p_port, b.rpc_port, b.p2p_port)
    try:
        canonical = plan_two_node_topology(ports)
    except (TwoNodeTopologyError, ValueError, TypeError):
        raise TwoNodePolicyError("G1_POLICY_PLAN_INVALID") from None
    if candidate != canonical:
        raise TwoNodePolicyError("G1_POLICY_PLAN_INVALID")
    return TopologyPolicyEvidence()
