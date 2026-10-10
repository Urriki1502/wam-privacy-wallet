"""G1-01: pure, non-executing topology contract for future two-node WAM regtest.

This module plans only *candidate* localhost addresses and config previews.
It never creates directories, opens sockets, fetches Core, launches processes,
loads keys, connects to a node, or permits real-world funds.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


class TwoNodeTopologyError(ValueError):
    """Stable, redacted failure code; never echo untrusted input."""


@dataclass(frozen=True, slots=True)
class PlannedNode:
    label: Literal["node-a", "node-b"]
    rpc_host: Literal["127.0.0.1"]
    rpc_port: int
    p2p_host: Literal["127.0.0.1"]
    p2p_port: int
    peer_p2p_port: int
    config_preview: str


@dataclass(frozen=True, slots=True)
class TwoNodePlan:
    """An in-memory, non-authorizing design artifact, never launch permission."""

    nodes: tuple[PlannedNode, PlannedNode]
    status: Literal["BLOCKED_UNVERIFIED_CORE"] = "BLOCKED_UNVERIFIED_CORE"
    real_regtest_qualified: bool = False
    publisher_identity_verified: bool = False
    scanner_enabled: bool = False
    signing_enabled: bool = False
    release_allowed: bool = False


def _config_preview(rpc: int, p2p: int, peer_p2p: int) -> str:
    # Informational template, NOT a validated WAM Core runtime configuration.
    # connect=0 from the single-node identity diagnostic cannot support a
    # two-node peer connection. Explicit loopback-only peers are proposed.
    return "\n".join((
        "regtest=1",
        "server=1",
        "daemon=0",
        "listen=1",
        "bind=127.0.0.1",
        "dns=0",
        "dnsseed=0",
        "discover=0",
        "upnp=0",
        "natpmp=0",
        "listenonion=0",
        "onion=0",
        "proxy=0",
        "rpcbind=127.0.0.1",
        "rpcallowip=127.0.0.1",
        "[regtest]",
        f"rpcport={rpc}",
        f"port={p2p}",
        f"connect=127.0.0.1:{peer_p2p}",
        "",
    ))


def plan_two_node_topology(ports: object) -> TwoNodePlan:
    """Build a strictly offline candidate for (A RPC, A P2P, B RPC, B P2P).

    Ports are caller-provided placeholders only. They are NOT reserved or
    checked for availability; actual isolated execution remains BLOCKED.
    """
    if type(ports) is not tuple or len(ports) != 4:
        raise TwoNodeTopologyError("G1_TOPOLOGY_FOUR_PORTS_REQUIRED")
    if any(type(port) is not int or not 1024 <= port <= 65535 for port in ports):
        raise TwoNodeTopologyError("G1_TOPOLOGY_INVALID_PORT")
    if len(set(ports)) != 4:
        raise TwoNodeTopologyError("G1_TOPOLOGY_PORT_COLLISION")

    a_rpc, a_p2p, b_rpc, b_p2p = ports
    nodes = (
        PlannedNode(
            "node-a", "127.0.0.1", a_rpc, "127.0.0.1", a_p2p, b_p2p,
            _config_preview(a_rpc, a_p2p, b_p2p),
        ),
        PlannedNode(
            "node-b", "127.0.0.1", b_rpc, "127.0.0.1", b_p2p, a_p2p,
            _config_preview(b_rpc, b_p2p, a_p2p),
        ),
    )
    return TwoNodePlan(nodes=nodes)
