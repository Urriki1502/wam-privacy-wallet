"""Pure WSP-1 storage/recovery disposition for synthetic metadata only.

A checkpoint claim can be forged. This module never opens a SQLite wallet,
checks filesystem permissions, decrypts keys, validates ownership or proves a
chain tip. Outputs can only require migration/rescan or manual review; NEVER
authorize an operational wallet, scanner, signer, broadcast, or real funds.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Literal

from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS

_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SCHEMA = "wam-wallet-storage-review/v1"
_REQUIRED = frozenset({
    "schema", "profile", "network", "genesis", "store_schema_version",
    "checkpoint_height", "checkpoint_hash", "reported_height",
    "reported_tip", "writer_lock", "db_integrity", "wallet_identity",
})
_MAX_HEIGHT = 100_000_000


class RecoveryDispositionError(ValueError):
    """Stable, redacted malformed-data failure (no input or path reflection)."""


@dataclass(frozen=True, slots=True)
class OfflineRecoveryDisposition:
    """Research-only direction, no database/path/credential/transaction data."""

    decision: Literal[
        "REVIEW_ONLY_NOT_VERIFIED", "RESCAN_REQUIRED", "MIGRATION_RESCAN_REQUIRED",
    ]
    checkpoint_height: int
    observed_height: int
    store_schema_version: int
    authority: Literal["BLOCKED"] = field(default="BLOCKED", init=False)
    writer_verified: bool = field(default=False, init=False)
    chain_verified: bool = field(default=False, init=False)
    wallet_enabled: bool = field(default=False, init=False)
    recovery_completed: bool = field(default=False, init=False)


def _hash(value: object) -> bool:
    return type(value) is str and _HASH.fullmatch(value) is not None


def evaluate_offline_recovery_disposition(payload: object) -> OfflineRecoveryDisposition:
    """Interpret UNTRUSTED synthetic metadata, without touching a wallet.

    Schema 0/2 reflects the pinned WSP-1 Store's migration/rescan candidates;
    this pure check DOES NOT run migration. Even the v3 fully matching snapshot
    requires independent writer lock, DB validation, wallet identity and
    trusted full-node provenance, none of which this helper can establish.
    """
    if (type(payload) is not dict
            or any(type(key) is not str for key in payload)
            or set(payload) != _REQUIRED):
        raise RecoveryDispositionError("RECOVERY_SCHEMA_DENIED")
    if (type(payload["schema"]) is not str or payload["schema"] != _SCHEMA
            or type(payload["profile"]) is not str
            or payload["profile"] != "WSP-1"
            or type(payload["network"]) is not str
            or payload["network"] != "regtest"
            or type(payload["genesis"]) is not str
            or payload["genesis"] != WAM_REGTEST_GENESIS):
        raise RecoveryDispositionError("RECOVERY_PROFILE_DENIED")
    version = payload["store_schema_version"]
    if type(version) is not int or version not in (0, 2, 3):
        raise RecoveryDispositionError("RECOVERY_VERSION_DENIED")
    for field in ("checkpoint_height", "reported_height"):
        val = payload[field]
        if type(val) is not int or not 0 <= val <= _MAX_HEIGHT:
            raise RecoveryDispositionError("RECOVERY_HEIGHT_DENIED")
    if not _hash(payload["checkpoint_hash"]) or not _hash(payload["reported_tip"]):
        raise RecoveryDispositionError("RECOVERY_HASH_DENIED")
    # No untrusted caller may assert verified lock, identity or integrity.
    if (type(payload["writer_lock"]) is not str
            or payload["writer_lock"] != "UNATTESTED"
            or type(payload["db_integrity"]) is not str
            or payload["db_integrity"] != "UNATTESTED"
            or type(payload["wallet_identity"]) is not str
            or payload["wallet_identity"] != "UNATTESTED"):
        raise RecoveryDispositionError("RECOVERY_AUTHORITY_DENIED")
    checkpoint = payload["checkpoint_height"]
    reported = payload["reported_height"]
    if version != 3:
        decision = "MIGRATION_RESCAN_REQUIRED"
    elif checkpoint != reported or payload["checkpoint_hash"] != payload["reported_tip"]:
        decision = "RESCAN_REQUIRED"
    else:
        decision = "REVIEW_ONLY_NOT_VERIFIED"
    return OfflineRecoveryDisposition(decision, checkpoint, reported, version)
