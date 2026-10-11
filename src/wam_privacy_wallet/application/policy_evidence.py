"""Source-bound, non-authorizing projection of synthetic privacy model evidence.

Only accepts redacted dicts shaped like the pinned wam-privacy Phase 4 and
Phase 5 prototype validator outputs. The input MAY BE FORGED: no code from
the upstream repositories is imported or executed. Never use this snapshot
to authorize an RPC, scanner, signer, transaction, PayJoin or network route.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# Audited research source snapshots (not runtime dependencies/attestation).
RESEARCH_REPOSITORY = "Urriki1502/wam-privacy"
RESEARCH_COMMIT_SHA = "db3d2dcaa540f1129d540101813b761167d33174"
NETWORK_POLICY_PATH = "prototypes/network_privacy/policy.py"
NETWORK_POLICY_BLOB_SHA = "3d24c9a9a010220503e6c81251da7c42309a63a0"
PAYJOIN_VALIDATOR_PATH = "prototypes/payjoin_safety/validator.py"
PAYJOIN_VALIDATOR_BLOB_SHA = "598596a8bde118204b3baf69bb53a884c6dad21a"

_NETWORK_FIELDS = frozenset((
    "schema", "scan_route", "broadcast_route", "broadcast_encrypted",
    "async_payjoin", "payjoin_route", "direct_fallback_present", "result",
))
_PAYJOIN_FIELDS = frozenset((
    "schema", "receiver_inputs_added", "output_substitution",
    "sender_fee_contribution_used", "absolute_fee_increased", "result",
))
_PRIVATE_ROUTES = frozenset(("tor", "i2p", "ohttp"))


class PolicyEvidenceError(ValueError):
    """Fixed public code, never echo caller-provided evidence."""


@dataclass(frozen=True, slots=True)
class SyntheticPolicyReport:
    """Model observation only, NEVER a spend/broadcast/privacy authorization."""

    provenance: Literal["PIN_RECORDED_UNATTESTED"]
    network: Literal["MODEL_PASS_UNTRUSTED"]
    payjoin: Literal["MODEL_PASS_UNTRUSTED"]
    authority: Literal["MODEL_ONLY_NO_AUTHORITY"]
    scan: Literal["BLOCKED"]
    sign: Literal["BLOCKED"]
    send: Literal["BLOCKED"]


def _deny() -> None:
    raise PolicyEvidenceError("APP_SYNTHETIC_POLICY_EVIDENCE_DENIED")


def inspect_synthetic_policy_evidence(
    network: object, payjoin: object,
) -> SyntheticPolicyReport:
    """Validate strictly redacted mock summaries from pinned research models.

    A PASS means only that injected synthetic metadata matches a restrictive
    display schema; anyone may construct the dicts. It is NOT validation
    of an underlying transaction, input ownership, PSBT, endpoint or route.
    No network, filesystem, secrets, wallet state or third-party imports.
    """
    if (type(network) is not dict or set(network) != _NETWORK_FIELDS
            or type(payjoin) is not dict or set(payjoin) != _PAYJOIN_FIELDS):
        _deny()

    if (
        type(network["schema"]) is not int or network["schema"] != 1
        or type(network["scan_route"]) is not str or network["scan_route"] != "local"
        or type(network["broadcast_route"]) is not str
        or network["broadcast_route"] not in _PRIVATE_ROUTES
        or type(network["broadcast_encrypted"]) is not bool
        or type(network["async_payjoin"]) is not bool
        or type(network["direct_fallback_present"]) is not bool
        or network["direct_fallback_present"] is not False
        or type(network["result"]) is not str or network["result"] != "PASS"
    ):
        _deny()
    if network["async_payjoin"]:
        if type(network["payjoin_route"]) is not str or network["payjoin_route"] != "ohttp":
            _deny()
    elif network["payjoin_route"] is not None:
        _deny()

    if (
        type(payjoin["schema"]) is not int or payjoin["schema"] != 1
        or type(payjoin["receiver_inputs_added"]) is not int
        or not 1 <= payjoin["receiver_inputs_added"] <= 128
        or type(payjoin["output_substitution"]) is not bool
        or payjoin["output_substitution"] is not False
        or type(payjoin["sender_fee_contribution_used"]) is not bool
        or type(payjoin["absolute_fee_increased"]) is not bool
        or type(payjoin["result"]) is not str or payjoin["result"] != "PASS"
    ):
        _deny()

    # Fixed codes only. Never return or retain caller data, even if valid.
    return SyntheticPolicyReport(
        "PIN_RECORDED_UNATTESTED",
        "MODEL_PASS_UNTRUSTED",
        "MODEL_PASS_UNTRUSTED",
        "MODEL_ONLY_NO_AUTHORITY",
        "BLOCKED", "BLOCKED", "BLOCKED",
    )
