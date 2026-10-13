"""Consent-gated offline review using the unchanged pinned upstream policy.

Caller annotations are untrusted. This evaluates a synthetic plan, never a
transport, endpoint identity, Core connection or permission to send.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address, IPv6Address
import re

from ..node.endpoint import LocalRegtestEndpoint

from .synthetic_policy_demo import _verify_source_bytes
from .synthetic_input_shape import has_exact_primitive_fields

_FIELDS = frozenset(("role", "host", "port", "route", "encrypted_transport",
                     "authenticated_transport", "fallback"))


class NetworkPlanReviewError(ValueError):
    """Fixed redacted code; no endpoint or underlying exception escapes."""


@dataclass(frozen=True, slots=True)
class NetworkPlanReview:
    source_commit: str = "db3d2dcaa540f1129d540101813b761167d33174"
    evidence: str = "PINNED_MODEL_EXECUTED_UNTRUSTED_INPUT"
    transport_verified: bool = False
    scan_allowed: bool = False
    sign_allowed: bool = False
    broadcast_allowed: bool = False
    runtime_status: str = field(default="NOT_QUALIFIED_NO_CONNECTION", init=False)


def review_synthetic_network_plan(
    endpoints: object, *, scope: object, consent: object,
    async_payjoin: object = False,
) -> NetworkPlanReview:
    """Evaluate up to 32 exact-shape synthetic endpoints under strict defaults.

    Consent permits local computation only; no I/O except source integrity
    reads. No caller-controlled policy relaxation, callback or object method.
    The output retains neither endpoints nor correlation-prone route telemetry.
    """
    try:
        if (type(scope) is not str or scope != "synthetic-regtest"
                or consent is not True or type(async_payjoin) is not bool
                or type(endpoints) is not tuple or not 1 <= len(endpoints) <= 32):
            raise ValueError
        for row in endpoints:
            if not has_exact_primitive_fields(row, _FIELDS):
                raise ValueError
            for key, limit in (("role", 32), ("host", 255), ("route", 16)):
                value = row[key]
                if (type(value) is not str or not 1 <= len(value) <= limit
                        or any(ord(c) < 33 or ord(c) > 126 for c in value)):
                    raise ValueError
            if type(row["port"]) is not int or not 1 <= row["port"] <= 65535:
                raise ValueError
            if any(type(row[k]) is not bool for k in (
                "encrypted_transport", "authenticated_transport", "fallback"
            )):
                raise ValueError
            # The application supports one explicit route per operation. The
            # upstream model only forbids DIRECT fallbacks; private or scan
            # fallbacks still need runtime qualification and cannot be selected.
            if row["fallback"] is not False:
                raise ValueError
            host = row["host"]
            if row["role"] == "chain_scan":
                # Reuse the actual RPC descriptor boundary (numeric loopback,
                # no DNS, zone identifier or mapped-address ambiguity).
                LocalRegtestEndpoint(host, row["port"])
            else:
                # Require a canonical identity so DNS case/trailing-dot/IP
                # aliases cannot evade upstream public-role separation.
                try:
                    address = ip_address(host)
                except ValueError:
                    if (host != host.lower() or len(host) > 253
                            or any(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
                                   for label in host.split("."))):
                        raise ValueError
                else:
                    if (str(address) != host or address.is_loopback
                            or isinstance(address, IPv6Address) and address.ipv4_mapped is not None):
                        raise ValueError
                if row["route"] not in ("tor", "i2p", "ohttp"):
                    raise ValueError
                if row["role"] == "payjoin_directory" and not async_payjoin:
                    raise ValueError
        _verify_source_bytes()
        from ..research_models.network_privacy.model import Endpoint, NetworkPlan, NetworkPolicy
        from ..research_models.network_privacy.policy import validate_network_plan

        # Construct fresh exact upstream values. Never dispatch caller methods.
        plan = NetworkPlan(tuple(Endpoint(**dict(row)) for row in endpoints))
        validate_network_plan(plan, NetworkPolicy(async_payjoin=async_payjoin))
    except Exception:
        raise NetworkPlanReviewError("APP_NETWORK_PLAN_REVIEW_DENIED") from None
    return NetworkPlanReview()
