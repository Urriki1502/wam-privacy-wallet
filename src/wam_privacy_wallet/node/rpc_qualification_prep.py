"""G1-04 readiness inventory: NO WAM Core execution or RPC.

This validates *planned cases*, not observations. Every case remains BLOCKED
until a separate, independently reviewed real-binary qualification workflow.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# Ordered, immutable scenario inventory. Outcomes describe REQUIRED behavior,
# not behavior observed against a real node.
RPC_CASES = (
    ("VALID_COOKIE_READONLY_PROFILE", "READONLY_SNAPSHOT_ONLY"),
    ("INVALID_COOKIE_DENIED", "DENY"),
    ("ROTATED_COOKIE_STALE_AUTH_DENIED", "DENY"),
    ("RESTART_INVALIDATES_STALE_SNAPSHOT", "DENY"),
    ("UNREACHABLE_NODE_FAIL_CLOSED", "DENY"),
    ("RPC_TIMEOUT_FAIL_CLOSED", "DENY"),
    ("WRONG_GENESIS_FAIL_CLOSED", "DENY"),
    ("PRUNED_NODE_FAIL_CLOSED", "DENY"),
    ("CHANGING_TIP_FAIL_CLOSED", "DENY"),
    ("OVERSIZED_RESPONSE_FAIL_CLOSED", "DENY"),
)
_REQUIRED_FIELDS = frozenset((
    "schema", "case_expectations", "publisher_identity_verified",
    "isolated_runner_verified", "live_core_executed", "release_allowed",
))


class RpcQualificationPrepError(ValueError):
    """Fixed, redacted error code; never echo submitted data."""


@dataclass(frozen=True, slots=True)
class RpcCase:
    case_id: str
    expected_outcome: str
    status: Literal["BLOCKED_NO_REAL_CORE_EVIDENCE"] = field(default="BLOCKED_NO_REAL_CORE_EVIDENCE", init=False)


@dataclass(frozen=True, slots=True)
class RpcReadinessPlan:
    cases: tuple[RpcCase, ...]
    status: Literal["BLOCKED_VERIFIED_BINARY_AND_ISOLATED_RUNNER"] = field(
        default="BLOCKED_VERIFIED_BINARY_AND_ISOLATED_RUNNER", init=False
    )
    publisher_identity_verified: bool = field(default=False, init=False)
    isolated_runner_verified: bool = field(default=False, init=False)
    live_core_executed: bool = field(default=False, init=False)
    scanner_enabled: bool = field(default=False, init=False)
    signer_enabled: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)


def prepare_rpc_qualification(payload: object) -> RpcReadinessPlan:
    """Validate a caller's exact offline test inventory, never its results."""
    if (type(payload) is not dict or any(type(key) is not str for key in payload)
            or set(payload) != _REQUIRED_FIELDS):
        raise RpcQualificationPrepError("G1_RPC_PREP_SCHEMA_REJECTED")
    if (type(payload["schema"]) is not str
            or payload["schema"] != "g1-04-rpc-qualification-prep/v1"):
        raise RpcQualificationPrepError("G1_RPC_PREP_SCHEMA_REJECTED")
    outcomes = payload["case_expectations"]
    if (type(outcomes) is not dict
            or any(type(key) is not str or type(value) is not str
                   for key, value in outcomes.items())
            or outcomes != dict(RPC_CASES)):
        raise RpcQualificationPrepError("G1_RPC_PREP_CASES_REJECTED")
    for key in ("publisher_identity_verified", "isolated_runner_verified",
                "live_core_executed", "release_allowed"):
        if payload[key] is not False:
            raise RpcQualificationPrepError("G1_RPC_PREP_AUTHORITY_REJECTED")
    return RpcReadinessPlan(tuple(RpcCase(*item) for item in RPC_CASES))
