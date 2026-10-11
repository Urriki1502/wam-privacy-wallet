"""Fail-closed network privacy policy.

This module performs no networking. It validates a proposed endpoint/transport
plan before any network-capable component is allowed to use it.
"""

from __future__ import annotations

from collections import defaultdict

from .model import Endpoint, NetworkPlan, NetworkPolicy


class NetworkPrivacyError(ValueError):
    """Fixed-code network privacy policy failure."""


PRIVATE_ROUTES = {"tor", "i2p", "ohttp"}


def _fail(code: str) -> None:
    raise NetworkPrivacyError(code)


def validate_network_plan(
    plan: NetworkPlan,
    policy: NetworkPolicy | None = None,
) -> dict:
    policy = NetworkPolicy() if policy is None else policy

    try:
        plan.validate()
        policy.validate()
    except ValueError as exc:
        raise NetworkPrivacyError(str(exc)) from None

    by_role: dict[str, list[Endpoint]] = defaultdict(list)
    for endpoint in plan.endpoints:
        by_role[endpoint.role].append(endpoint)

    # Chain scanning defaults to a local validating node. Remote scan backends
    # correlate wallet interests and are therefore explicit opt-in.
    primary_scan = [e for e in by_role["chain_scan"] if not e.fallback]
    if len(primary_scan) != 1:
        _fail("CHAIN_SCAN_PRIMARY_COUNT")
    scan = primary_scan[0]
    if not policy.allow_remote_scan and scan.route != "local":
        _fail("REMOTE_SCAN_NOT_ALLOWED")

    # Private broadcast is a route property, not an encryption property.
    # A direct BIP324-like encrypted connection is still a direct public route.
    primary_broadcast = [e for e in by_role["tx_broadcast"] if not e.fallback]
    if len(primary_broadcast) != 1:
        _fail("BROADCAST_PRIMARY_COUNT")
    broadcast = primary_broadcast[0]
    if policy.require_private_broadcast and broadcast.route not in PRIVATE_ROUTES:
        _fail("PRIVATE_BROADCAST_REQUIRED")

    # Never silently downgrade to a clearnet fallback when privacy is required.
    if not policy.allow_direct_fallback:
        for endpoint in plan.endpoints:
            if endpoint.fallback and endpoint.route == "direct":
                _fail("DIRECT_FALLBACK_FORBIDDEN")

    # Async PayJoin uses an OHTTP-style directory path in the v0.1 policy.
    if policy.async_payjoin:
        directories = [e for e in by_role["payjoin_directory"] if not e.fallback]
        if len(directories) != 1:
            _fail("PAYJOIN_DIRECTORY_PRIMARY_COUNT")
        if policy.require_ohttp_for_async_payjoin and directories[0].route != "ohttp":
            _fail("ASYNC_PAYJOIN_REQUIRES_OHTTP")

    # Avoid reusing one public endpoint identity for multiple wallet roles.
    # A local node can legitimately serve local scan/broadcast plumbing.
    if policy.require_public_role_separation:
        identities: dict[tuple[str, int], set[str]] = defaultdict(set)
        for endpoint in plan.endpoints:
            if endpoint.route != "local":
                identities[endpoint.public_identity].add(endpoint.role)
        if any(len(roles) > 1 for roles in identities.values()):
            _fail("PUBLIC_ROLE_REUSE")

    return {
        "schema": 1,
        "scan_route": scan.route,
        "broadcast_route": broadcast.route,
        "broadcast_encrypted": broadcast.encrypted_transport,
        "async_payjoin": policy.async_payjoin,
        "payjoin_route": (
            next(
                (
                    e.route
                    for e in by_role.get("payjoin_directory", [])
                    if not e.fallback
                ),
                None,
            )
            if policy.async_payjoin
            else None
        ),
        "direct_fallback_present": any(
            e.fallback and e.route == "direct" for e in plan.endpoints
        ),
        "result": "PASS",
    }


def redacted_network_event(evidence: dict) -> dict:
    """Return route-level telemetry without host, port, credentials, or IDs."""

    allowed = {
        "schema",
        "scan_route",
        "broadcast_route",
        "broadcast_encrypted",
        "async_payjoin",
        "payjoin_route",
        "direct_fallback_present",
        "result",
    }
    return {k: evidence[k] for k in allowed if k in evidence}
