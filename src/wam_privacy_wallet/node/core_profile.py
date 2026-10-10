"""WAM Core regtest read-only profile validation; no consensus modifications.

Uses Bitcoin Core-compatible getblockchaininfo fields documented for WAM Core.
The validation is an ephemeral consistency check, not node authentication.
"""

from __future__ import annotations

from dataclasses import dataclass

from .attestation import ChainIdentity


class CoreProfileError(RuntimeError):
    """Stable error identifier. Never attach untrusted RPC text."""


@dataclass(frozen=True, slots=True)
class VerifiedCoreProfile:
    """Read-only snapshot, not authorization to scan or spend."""

    identity: ChainIdentity
    headers: int
    pruned: bool


def validate_core_profile(payload: object, identity: ChainIdentity) -> VerifiedCoreProfile:
    """Fail closed unless Core reports unpruned regtest matching the probe tip."""
    if type(identity) is not ChainIdentity:
        raise CoreProfileError("WAM_CORE_IDENTITY_REQUIRED")
    if type(payload) is not dict:
        raise CoreProfileError("WAM_CORE_PROFILE_INVALID")

    if payload.get("chain") != "regtest" or type(payload.get("chain")) is not str:
        raise CoreProfileError("WAM_CORE_WRONG_CHAIN")

    if type(payload.get("pruned")) is not bool or payload["pruned"]:
        raise CoreProfileError("WAM_CORE_PRUNED_OR_UNKNOWN")

    blocks = payload.get("blocks")
    headers = payload.get("headers")
    if (
        type(blocks) is not int
        or type(headers) is not int
        or blocks != identity.height
        or headers < blocks
        or headers > 100_000_000
    ):
        raise CoreProfileError("WAM_CORE_HEIGHT_MISMATCH")

    if (
        type(payload.get("bestblockhash")) is not str
        or payload["bestblockhash"] != identity.best_block_hash
    ):
        raise CoreProfileError("WAM_CORE_TIP_MISMATCH")

    return VerifiedCoreProfile(identity=identity, headers=headers, pruned=False)
