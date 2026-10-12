"""Synthetic/regtest-only WSP encrypted snapshot lineage and crash preflight.

Every file belongs to the SAME rollback domain. SHA-256 predecessor links
check local integrity, NEVER prove anti-rollback against directory replay.
No trusted high-water mark/TPM/platform anchor exists in this application.
All production reads must refuse; no automatic latest or silent downgrade.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from wam_privacy_wallet.application.versioned_checkpoint_journal import (
    VersionedCheckpointError, read_unanchored_regtest_generation,
)


class SnapshotLineageError(ValueError):
    """Fixed failure codes, never raw checkpoint bytes or private paths."""


@dataclass(frozen=True, slots=True)
class SyntheticLineageReceipt:
    generation: int
    manifest_digest: str
    scope_digest: str
    protection: str = "UNANCHORED_SYNTHETIC_REGTEST_ONLY"
    trusted_anchor_verified: bool = False
    wallet_operational: bool = False
    mainnet_allowed: bool = False
    signer_enabled: bool = False
    broadcast_allowed: bool = False


def _digest(manifest: dict) -> str:
    encoded = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def inspect_untrusted_generation_lineage(
    directory: Path,
    expected_generation: int,
    *,
    allow_unanchored_synthetic: bool = False,
) -> SyntheticLineageReceipt:
    """Explicit bounded-gen synthetic witness, never a trusted latest.

    Missing/unfinished versions, chain gaps, altered predecessors, or a
    mismatched account scope lead to a fixed denial; no older-version fallback.
    A consistent self-contained chain may still be replayed wholesale.
    """
    if allow_unanchored_synthetic is not True:
        raise SnapshotLineageError("LINEAGE_INDEPENDENT_ANCHOR_REQUIRED")
    if (type(expected_generation) is not int
            or not 1 <= expected_generation <= 32):
        raise SnapshotLineageError("LINEAGE_EXPECTED_GENERATION_DENIED")
    previous = "0" * 64
    scope = None
    tip = None
    try:
        for generation in range(1, expected_generation + 1):
            manifest, ciphertext = read_unanchored_regtest_generation(
                directory, generation, allow_unanchored_synthetic=True,
            )
            # The journal validates the digest/ready marker, regtest-only
            # network, pinned source revision and bounded ciphertext.
            if (manifest["predecessor"] != previous
                    or manifest["generation"] != generation):
                raise SnapshotLineageError("LINEAGE_PREDECESSOR_DENIED")
            if scope is not None and manifest["scope_digest"] != scope:
                raise SnapshotLineageError("LINEAGE_ACCOUNT_SCOPE_DENIED")
            if scope is None:
                scope = manifest["scope_digest"]
            tip = manifest["tip_hash"]
            previous = _digest(manifest)
            # Never retain upstream encrypted bytes in a presentation DTO.
            del ciphertext
        if scope is None or tip is None:
            raise SnapshotLineageError("LINEAGE_EMPTY_DENIED")
        return SyntheticLineageReceipt(
            generation=expected_generation,
            manifest_digest=previous,
            scope_digest=scope,
        )
    except SnapshotLineageError:
        raise
    except (VersionedCheckpointError, ValueError, TypeError, KeyError):
        raise SnapshotLineageError("LINEAGE_CRASH_OR_FILE_DENIED") from None
    except Exception:
        raise SnapshotLineageError("LINEAGE_RUNTIME_DENIED") from None


def evaluate_trusted_rollback_status(
    receipt: SyntheticLineageReceipt,
    *,
    independent_anchor_proof: object = None,
) -> None:
    """Fail-closed placeholder; no independently qualified anchor yet.

    Passing a string, callback, mock, file path, or even a forged proof object
    does NOT enable anti-rollback. A future approved implementation must
    implement exact platform attestation, atomic anchoring and recovery rules
    under separate review; it must never simply accept caller-provided hashes.
    """
    if type(receipt) is not SyntheticLineageReceipt:
        raise SnapshotLineageError("LINEAGE_RECEIPT_DENIED")
    # independent_anchor_proof deliberately ignored: absolutely NO
    # fallback to trusting a supplied local digest or UI approval.
    raise SnapshotLineageError("LINEAGE_INDEPENDENT_ANCHOR_REQUIRED")
