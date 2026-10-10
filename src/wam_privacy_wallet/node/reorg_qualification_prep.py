"""G1-05 offline case inventory for reorg/recovery and scanner safety.

NO blockchain, signer, wallet or scanner is instantiated here. These are
reviewed *test expectations*, never evidence of real WAM Core behavior.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# Immutable required future live test cases, not results.
REORG_CASES = (
    ("TWO_NODE_P2P_CONVERGENCE", "RECHECK_CONSENSUS"),
    ("FORK_DIVERGENCE_DETECTED", "INVALIDATE_STALE_TIP"),
    ("REORG_RECONFIRMATION", "REVALIDATE"),
    ("RESTART_RESTORE_STATE", "REVALIDATE"),
    ("MISSING_PREVOUT_FAIL_CLOSED", "DENY"),
    ("STALE_SCANNER_TIP_FAIL_CLOSED", "DENY"),
    ("ONLY_USER_LOCAL_FULL_NODE", "LOCAL_ONLY"),
    ("EXCLUSIVE_SCANNER_LEASE", "MUST_ENFORCE_LOCK"),
    ("LOCK_CRASH_RECOVERY", "MUST_REACQUIRE"),
    ("BROADCAST_OR_SIGNER_AUTH_DENIED", "DENY"),
)
_FIELDS = frozenset((
    "schema", "case_expectations", "real_rpc_qualified",
    "real_two_node_executed", "upstream_lock_reviewed",
    "scanner_security_reviewed", "release_allowed",
))


class ReorgQualificationPrepError(ValueError):
    """Non-sensitive, fixed failure identifier."""


@dataclass(frozen=True, slots=True)
class ReorgCase:
    case_id: str
    expected_outcome: str
    status: Literal["BLOCKED_NO_REAL_REORG_EVIDENCE"] = field(default="BLOCKED_NO_REAL_REORG_EVIDENCE", init=False)


@dataclass(frozen=True, slots=True)
class ReorgReadinessPlan:
    cases: tuple[ReorgCase, ...]
    status: Literal["BLOCKED_G1_04_AND_UPSTREAM_REVIEW"] = field(
        default="BLOCKED_G1_04_AND_UPSTREAM_REVIEW", init=False
    )
    real_rpc_qualified: bool = field(default=False, init=False)
    real_two_node_executed: bool = field(default=False, init=False)
    upstream_lock_reviewed: bool = field(default=False, init=False)
    scanner_security_reviewed: bool = field(default=False, init=False)
    signing_enabled: bool = field(default=False, init=False)
    broadcast_enabled: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)


def prepare_reorg_qualification(payload: object) -> ReorgReadinessPlan:
    """Require exact offline case inventory, reject fabricated approval."""
    if (type(payload) is not dict or any(type(key) is not str for key in payload)
            or set(payload) != _FIELDS):
        raise ReorgQualificationPrepError("G1_REORG_PREP_SCHEMA_REJECTED")
    if (type(payload["schema"]) is not str
            or payload["schema"] != "g1-05-reorg-qualification-prep/v1"):
        raise ReorgQualificationPrepError("G1_REORG_PREP_SCHEMA_REJECTED")
    given = payload["case_expectations"]
    if (type(given) is not dict
            or any(type(key) is not str or type(value) is not str
                   for key, value in given.items())
            or given != dict(REORG_CASES)):
        raise ReorgQualificationPrepError("G1_REORG_PREP_CASES_REJECTED")
    for key in ("real_rpc_qualified", "real_two_node_executed",
                "upstream_lock_reviewed", "scanner_security_reviewed",
                "release_allowed"):
        if payload[key] is not False:
            raise ReorgQualificationPrepError("G1_REORG_PREP_AUTHORITY_REJECTED")
    return ReorgReadinessPlan(tuple(ReorgCase(*case) for case in REORG_CASES))
