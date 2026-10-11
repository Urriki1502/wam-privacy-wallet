"""Fail-closed, offline-only lifecycle for immutable GUI research projections.

A complete replacement is atomic at the application boundary. No source
profiles, model inputs, wallet handles, endpoints, addresses, callbacks or
credentials are retained. Even accepted observations carry ZERO authority.
This is a display-state coordinator, not a security attestation or wallet.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .node_status import NodeOverview
from .recovery_transition import OfflineRecoveryTransition
from .policy_evidence import SyntheticPolicyReport
from .privacy_readiness import PrivacyResearchSnapshot
from .receive_vector import ReceiveVectorPreview, _FIXED_FINGERPRINT


class OfflineLifecycleError(ValueError):
    """Fixed public error; never echo supplied objects or their repr."""


@dataclass(frozen=True, slots=True)
class OfflinePresentationState:
    revision: int
    node: Literal["ABSENT", "UNVERIFIED"]
    privacy: Literal["ABSENT", "RESEARCH_ONLY"]
    policy: Literal["ABSENT", "MODEL_ONLY"]
    receive: Literal["ABSENT", "PUBLIC_FIXTURE"]
    authority: Literal["BLOCKED"]
    network: Literal["OFFLINE_REGTEST_ONLY"]
    wallet: Literal["NO_WALLET_LOADED"]
    transition: Literal["INITIAL", "REPLACED", "CLEARED", "REJECTED"]
    recovery: Literal[
        "ABSENT", "REVIEW_ONLY_NOT_VERIFIED", "RESCAN_REQUIRED",
        "MIGRATION_RESCAN_REQUIRED",
    ] = "ABSENT"


def _empty(revision: int, transition: str) -> OfflinePresentationState:
    return OfflinePresentationState(
        revision, "ABSENT", "ABSENT", "ABSENT", "ABSENT",
        "BLOCKED", "OFFLINE_REGTEST_ONLY", "NO_WALLET_LOADED", transition,
    )


def _valid_node(value: object) -> bool:
    return (
        type(value) is NodeOverview
        and type(value.network) is str and value.network == "regtest"
        and type(value.height) is int and 0 <= value.height <= 100_000_000
        and type(value.status) is str and value.status == "READ_ONLY_SNAPSHOT"
        and type(value.notice) is str and value.notice == "EXPERIMENTAL_NO_REAL_FUNDS"
    )


def _valid_privacy(value: object) -> bool:
    return (
        type(value) is PrivacyResearchSnapshot
        and type(value.research_state) is str and value.research_state == "RESEARCH_ONLY"
        and type(value.wsp_source) is str and value.wsp_source == "PIN_RECORDED_UNATTESTED"
        and type(value.wallet_privacy) is str and value.wallet_privacy == "MODEL_ONLY"
        and type(value.payjoin) is str and value.payjoin == "MODEL_ONLY"
        and type(value.network_privacy) is str and value.network_privacy == "MODEL_ONLY"
        and type(value.selective_disclosure) is str
        and value.selective_disclosure == "NOT_INTEGRATED"
        and type(value.scan) is str and value.scan == "BLOCKED"
        and type(value.sign) is str and value.sign == "BLOCKED"
        and type(value.send) is str and value.send == "BLOCKED"
    )


def _valid_policy(value: object) -> bool:
    return (
        type(value) is SyntheticPolicyReport
        and type(value.provenance) is str and value.provenance == "PIN_RECORDED_UNATTESTED"
        and type(value.network) is str and value.network == "MODEL_PASS_UNTRUSTED"
        and type(value.payjoin) is str and value.payjoin == "MODEL_PASS_UNTRUSTED"
        and type(value.authority) is str and value.authority == "MODEL_ONLY_NO_AUTHORITY"
        and type(value.scan) is str and value.scan == "BLOCKED"
        and type(value.sign) is str and value.sign == "BLOCKED"
        and type(value.send) is str and value.send == "BLOCKED"
    )


def _valid_receive(value: object) -> bool:
    return (
        type(value) is ReceiveVectorPreview
        and type(value.profile) is str and value.profile == "WSP-1"
        and type(value.network) is str and value.network == "regtest"
        and type(value.provenance) is str and value.provenance == "PIN_RECORDED_UNATTESTED"
        and type(value.sample) is str and value.sample == "PUBLIC_SYNTHETIC_FIXTURE"
        and type(value.fingerprint) is str and value.fingerprint == _FIXED_FINGERPRINT
        and type(value.receive) is str and value.receive == "BLOCKED"
        and type(value.scanner) is str and value.scanner == "BLOCKED"
        and type(value.signer) is str and value.signer == "BLOCKED"
    )


def _valid_recovery(value: object) -> bool:
    """Accept only bounded non-authorizing synthetic recovery transitions."""
    if type(value) is not OfflineRecoveryTransition:
        return False
    if (
        type(value.old_revision) is not int
        or type(value.new_revision) is not int
        or not 0 <= value.old_revision < 2**63 - 1
        or value.new_revision != value.old_revision + 1
        or type(value.checkpoint_height) is not int
        or not 0 <= value.checkpoint_height <= 100_000_000
        or type(value.reason) is not str
        or type(value.decision) is not str
        or type(value.status) is not str
        or value.status != "SYNTHETIC_TRANSITION_UNTRUSTED"
        or value.writer_verified is not False
        or value.chain_verified is not False
        or value.recovery_completed is not False
        or value.wallet_enabled is not False
    ):
        return False
    cases = {
        "NO_TRUSTED_RECOVERY_EVIDENCE": "REVIEW_ONLY_NOT_VERIFIED",
        "VERSION_DOWNGRADE": "MIGRATION_RESCAN_REQUIRED",
        "MIGRATION_RESCAN_REQUIRED": "MIGRATION_RESCAN_REQUIRED",
        "CHECKPOINT_ROLLBACK": "RESCAN_REQUIRED",
        "REPORTED_TIP_REWIND": "RESCAN_REQUIRED",
        "CHECKPOINT_FORK_OR_RESTORE": "RESCAN_REQUIRED",
        "RESCAN_REQUIRED": "RESCAN_REQUIRED",
    }
    return cases.get(value.reason) == value.decision


class OfflinePresentationController:
    """Whole-view replacements with revision checks and fail-closed rejection.

    Callers must pass the revision obtained before composing a replacement.
    A stale revision or malformed DTO invalidates *all* prior observations.
    None means absent; there is no implicit reuse of an earlier observation.
    """

    __slots__ = ("_state",)

    def __init__(self) -> None:
        self._state = _empty(0, "INITIAL")

    @property
    def state(self) -> OfflinePresentationState:
        return self._state

    def reset(self) -> OfflinePresentationState:
        self._state = _empty(self._state.revision + 1, "CLEARED")
        return self._state

    def _reject(self) -> None:
        self._state = _empty(self._state.revision + 1, "REJECTED")
        raise OfflineLifecycleError("APP_OFFLINE_LIFECYCLE_DENIED")

    def replace(
        self, expected_revision: object, *,
        node: object = None,
        privacy: object = None,
        policy: object = None,
        receive: object = None,
        recovery: object = None,
    ) -> OfflinePresentationState:
        if type(expected_revision) is not int or expected_revision != self._state.revision:
            self._reject()
        if (
            (node is not None and not _valid_node(node))
            or (privacy is not None and not _valid_privacy(privacy))
            or (policy is not None and not _valid_policy(policy))
            or (receive is not None and not _valid_receive(receive))
            or (recovery is not None and not _valid_recovery(recovery))
        ):
            self._reject()
        self._state = OfflinePresentationState(
            self._state.revision + 1,
            "UNVERIFIED" if node is not None else "ABSENT",
            "RESEARCH_ONLY" if privacy is not None else "ABSENT",
            "MODEL_ONLY" if policy is not None else "ABSENT",
            "PUBLIC_FIXTURE" if receive is not None else "ABSENT",
            "BLOCKED", "OFFLINE_REGTEST_ONLY", "NO_WALLET_LOADED", "REPLACED",
            recovery.decision if recovery is not None else "ABSENT",
        )
        return self._state
