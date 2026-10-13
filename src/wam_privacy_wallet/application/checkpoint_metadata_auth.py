"""Versioned HMAC metadata for exact upstream WSP encrypted checkpoints.

This authenticates metadata, not freshness. A valid MAC can be replayed with
the whole directory. Keys MUST be independently random 32-byte metadata keys,
never passwords, scan/spend keys or a home-grown WSP key derivation. The WSP
ciphertext is unchanged and only upstream WSP may authenticate/decrypt it.
No key storage, provider qualification, automatic rotation or restore permit.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
from typing import Protocol

from .versioned_checkpoint_journal import (
    _SOURCE_PIN, _MANIFEST_KEYS, _ZERO, _canonical, _hex64, _name,
)
from .encrypted_checkpoint_archive import _well_formed
from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS

_DOMAIN = b"WAM-PRIVACY-WALLET/CHECKPOINT-METADATA/V2\x00"
# Exact pinned Store.export_checkpoint emits schema 3. A different declared
# schema needs source/format requalification, not a caller-selected fallback.
_PINNED_CHECKPOINT_SCHEMA = 3
_KEYS = frozenset(("metadata_schema", "checkpoint_schema", "key_epoch", "genesis",
                   "manifest", "mac"))


class CheckpointMetadataError(ValueError):
    """Fixed denial codes; no keys, paths, account IDs or ciphertext."""


@dataclass(frozen=True, slots=True)
class CheckpointExpectation:
    scope_digest: str = field(repr=False)
    generation: int
    checkpoint_schema: int
    key_epoch: int


class IndependentAnchorProvider(Protocol):
    """Contract only: no concrete provider is approved or accepted here.

    Implementations must independently authenticate scope/network/source,
    generation+manifest digest and a durable monotonic counter. CAS must be
    atomic outside the local rollback domain; caller assertions are not proof.
    Attestations require freshness/challenge verification, not signatures alone.
    """
    def qualify(self) -> bytes: ...
    def read_high_water(self, challenge: bytes) -> bytes: ...
    def commit_high_water(self, previous_attestation: bytes,
                          next_record: bytes, challenge: bytes) -> bytes: ...
    def verify_high_water(self, attestation: bytes, challenge: bytes) -> None: ...
    def recover_after_anchor_ahead(self) -> None: ...  # Must STOP/HUMAN REVIEW.


def require_independent_anchor(provider: object = None) -> None:
    # No provider/callback, UI approval or local digest may remove the HOLD.
    raise CheckpointMetadataError("CHECKPOINT_INDEPENDENT_ANCHOR_UNQUALIFIED")


def _expectation(value: object) -> CheckpointExpectation:
    if (type(value) is not CheckpointExpectation
            or not _hex64(value.scope_digest)
            or type(value.checkpoint_schema) is not int
            or value.checkpoint_schema != _PINNED_CHECKPOINT_SCHEMA
            or type(value.key_epoch) is not int
            or not 1 <= value.key_epoch <= 2**63 - 1):
        raise CheckpointMetadataError("CHECKPOINT_METADATA_BINDING_DENIED")
    try:
        _name(value.generation)
    except ValueError:
        raise CheckpointMetadataError("CHECKPOINT_METADATA_BINDING_DENIED") from None
    return value


def _key(value: object) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise CheckpointMetadataError("CHECKPOINT_METADATA_KEY_DENIED")
    return value


def validate_checkpoint_binding(expected: CheckpointExpectation, key: bytes) -> None:
    """Reject unsupported source/schema/key selection before persistence I/O."""
    _expectation(expected)
    _key(key)


def _manifest(value: object, ciphertext: bytes,
              expected: CheckpointExpectation) -> dict:
    if (type(value) is not dict or frozenset(value) != _MANIFEST_KEYS
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["network"] != "regtest" or type(value["network"]) is not str
            or value["source_pin"] != _SOURCE_PIN
            or type(value["source_pin"]) is not str
            or type(value["generation"]) is not int
            or value["generation"] != expected.generation
            or value["scope_digest"] != expected.scope_digest
            or not _hex64(value["scope_digest"])
            or type(value["tip_height"]) is not int
            or not 0 <= value["tip_height"] <= 2**31
            or not _hex64(value["tip_hash"])
            or not _hex64(value["predecessor"])
            or (expected.generation == 1 and value["predecessor"] != _ZERO)
            or (expected.generation > 1 and value["predecessor"] == _ZERO)
            or not _hex64(value["checkpoint_sha256"])
            or not _well_formed(ciphertext)
            or hashlib.sha256(ciphertext).hexdigest() != value["checkpoint_sha256"]):
        raise CheckpointMetadataError("CHECKPOINT_METADATA_BINDING_DENIED")
    return dict(value)


def authenticate_checkpoint_metadata(manifest: dict, ciphertext: bytes, *,
                                     key: bytes,
                                     expected: CheckpointExpectation) -> bytes:
    """Return canonical v2 MAC envelope. Never alter/decrypt WSP ciphertext."""
    expected = _expectation(expected)
    key = _key(key)
    body = {"metadata_schema": 2, "checkpoint_schema": expected.checkpoint_schema,
            "key_epoch": expected.key_epoch,
            "genesis": WAM_REGTEST_GENESIS,
            "manifest": _manifest(manifest, ciphertext, expected)}
    tag = hmac.digest(key, _DOMAIN + _canonical(body), "sha256").hex()
    return _canonical({**body, "mac": tag})


def verify_checkpoint_metadata(raw: bytes, ciphertext: bytes, *, key: bytes,
                               expected: CheckpointExpectation) -> dict:
    """Verify MAC and caller-selected identity/epoch/schema before any restore.

    No fallback key search: old keys/epochs require explicit separate selection.
    A success does NOT prove current high water or authentic WSP AES-GCM tag.
    """
    expected = _expectation(expected)
    key = _key(key)
    if type(raw) is not bytes or not 1 <= len(raw) <= 4096:
        raise CheckpointMetadataError("CHECKPOINT_METADATA_FORMAT_DENIED")
    try:
        body = json.loads(raw)
        if (type(body) is not dict or frozenset(body) != _KEYS
                or _canonical(body) != raw
                or type(body["metadata_schema"]) is not int
                or body["metadata_schema"] != 2
                or body["genesis"] != WAM_REGTEST_GENESIS
                or type(body["checkpoint_schema"]) is not int
                or body["checkpoint_schema"] != expected.checkpoint_schema
                or type(body["key_epoch"]) is not int
                or body["key_epoch"] != expected.key_epoch
                or not _hex64(body["mac"])):
            raise ValueError("invalid metadata")
        tag = body.pop("mac")
        if not hmac.compare_digest(
            tag, hmac.digest(key, _DOMAIN + _canonical(body), "sha256").hex()
        ):
            raise CheckpointMetadataError("CHECKPOINT_METADATA_AUTHENTICATION_DENIED")
        return _manifest(body["manifest"], ciphertext, expected)
    except CheckpointMetadataError:
        raise
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise CheckpointMetadataError("CHECKPOINT_METADATA_FORMAT_DENIED") from None
