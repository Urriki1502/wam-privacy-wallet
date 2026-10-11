"""Read-only integration status for untrusted offline research projections.

This module deliberately makes NO operational decision: all three sources
are independently unverified synthetic evidence. A cohesive display status
must never be promoted into scanner, signer, wallet, Core or release authority.
Inputs are inspected as scalars; no source payloads, secrets or handles retained.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .presentation_lifecycle import OfflinePresentationState
from .recovery_disposition import OfflineRecoveryDisposition
from wam_privacy_wallet.integrations.scanner_window_contract import OfflineScanWindowSummary


class OfflineIntegrationStatusError(ValueError):
    """Fixed, redacted failure code, never includes untrusted input repr."""


@dataclass(frozen=True, slots=True)
class OfflineIntegrationStatus:
    """Non-authorizing combined research view; not a capability ticket."""

    revision: int
    presentation: Literal["EMPTY", "SYNTHETIC_ONLY"]
    scan_window: Literal["ABSENT", "SYNTHETIC_ONLY"]
    storage: Literal[
        "ABSENT", "REVIEW_ONLY_NOT_VERIFIED", "RESCAN_REQUIRED",
        "MIGRATION_RESCAN_REQUIRED",
    ]
    # Intentionally fixed even if all three previews appear internally
    # consistent. No dynamic "ready" or "approved" status exists.
    status: Literal["REVIEW_ONLY_UNTRUSTED"] = field(
        default="REVIEW_ONLY_UNTRUSTED", init=False
    )
    core_verified: bool = field(default=False, init=False)
    scanner_enabled: bool = field(default=False, init=False)
    storage_verified: bool = field(default=False, init=False)
    signer_enabled: bool = field(default=False, init=False)
    send_enabled: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)


def _valid_presentation(s: object) -> bool:
    return (
        type(s) is OfflinePresentationState
        and type(s.revision) is int and 0 <= s.revision <= 2**63 - 1
        and type(s.node) is str and s.node in ("ABSENT", "UNVERIFIED")
        and type(s.privacy) is str and s.privacy in ("ABSENT", "RESEARCH_ONLY")
        and type(s.policy) is str and s.policy in ("ABSENT", "MODEL_ONLY")
        and type(s.receive) is str and s.receive in ("ABSENT", "PUBLIC_FIXTURE")
        and type(s.authority) is str and s.authority == "BLOCKED"
        and type(s.network) is str and s.network == "OFFLINE_REGTEST_ONLY"
        and type(s.wallet) is str and s.wallet == "NO_WALLET_LOADED"
        and type(s.transition) is str
        and s.transition in ("INITIAL", "REPLACED", "CLEARED", "REJECTED")
        # Cleared/rejected/initial revisions cannot retain display evidence.
        and (
            s.transition == "REPLACED"
            or (s.node, s.privacy, s.policy, s.receive) == ("ABSENT",) * 4
        )
        and (
            (s.transition == "INITIAL" and s.revision == 0)
            or (s.transition != "INITIAL" and s.revision >= 1)
        )
    )


def _valid_scan(s: object) -> bool:
    return (
        type(s) is OfflineScanWindowSummary
        and type(s.start_height) is int
        and type(s.end_height) is int
        and type(s.block_count) is int
        and type(s.transaction_count) is int
        and 0 <= s.start_height <= s.end_height <= 100_000_000
        and 0 <= s.block_count <= 16
        and s.end_height - s.start_height == s.block_count
        and 0 <= s.transaction_count <= 20_000
        # A synthetically empty scan window cannot report any transactions.
        # Reject impossible forged DTOs before producing a combined summary.
        and (s.block_count != 0 or s.transaction_count == 0)
        and type(s.status) is str
        and s.status == "SYNTHETIC_COHERENCE_ONLY"
        and s.chain_identity_verified is False
        and s.rpc_authenticated is False
        and s.scanner_enabled is False
        and s.wallet_ready is False
    )


def _valid_storage(s: object) -> bool:
    if (
        type(s) is not OfflineRecoveryDisposition
        or type(s.checkpoint_height) is not int
        or type(s.observed_height) is not int
        or type(s.store_schema_version) is not int
        or not 0 <= s.checkpoint_height <= 100_000_000
        or not 0 <= s.observed_height <= 100_000_000
        or s.store_schema_version not in (0, 2, 3)
        or type(s.decision) is not str
        or s.authority != "BLOCKED"
        or s.writer_verified is not False
        or s.chain_verified is not False
        or s.wallet_enabled is not False
        or s.recovery_completed is not False
    ):
        return False
    if s.store_schema_version in (0, 2):
        return s.decision == "MIGRATION_RESCAN_REQUIRED"
    if s.decision == "REVIEW_ONLY_NOT_VERIFIED":
        return s.checkpoint_height == s.observed_height
    return s.decision == "RESCAN_REQUIRED"


def inspect_offline_integration(
    presentation: object,
    *, scan_window: object = None, storage: object = None,
) -> OfflineIntegrationStatus:
    """Summarize strictly typed, untrusted DTOs without activating anything.

    Dataclasses can be fabricated in the same Python process. Exact type and
    field checks reject contradictory claims but do not attest their origins.
    """
    if not _valid_presentation(presentation):
        raise OfflineIntegrationStatusError("APP_INTEGRATION_PRESENTATION_DENIED")
    if scan_window is not None and not _valid_scan(scan_window):
        raise OfflineIntegrationStatusError("APP_INTEGRATION_SCANNER_DENIED")
    if storage is not None and not _valid_storage(storage):
        raise OfflineIntegrationStatusError("APP_INTEGRATION_STORAGE_DENIED")

    has_presentation = any((
        presentation.node != "ABSENT",
        presentation.privacy != "ABSENT",
        presentation.policy != "ABSENT",
        presentation.receive != "ABSENT",
    ))
    return OfflineIntegrationStatus(
        revision=presentation.revision,
        presentation="SYNTHETIC_ONLY" if has_presentation else "EMPTY",
        scan_window="SYNTHETIC_ONLY" if scan_window is not None else "ABSENT",
        storage=storage.decision if storage is not None else "ABSENT",
    )
