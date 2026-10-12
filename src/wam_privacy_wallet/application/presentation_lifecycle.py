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
from .offline_resume_review import OfflineResumeReview
from .offline_rescan_segments import OfflineRescanSegments
from .offline_reorg_reconciliation import OfflineReorgReconciliation
from .policy_evidence import SyntheticPolicyReport
from .privacy_readiness import PrivacyResearchSnapshot
from .receive_vector import ReceiveVectorPreview, _FIXED_FINGERPRINT
from .scanner_session_workflow import ScannerReadOnlyObservation


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
    resume: Literal[
        "ABSENT", "REVALIDATE_BEFORE_RESCAN", "REWIND_RESCAN_REVIEW",
        "MIGRATION_RESCAN_REVIEW",
    ] = "ABSENT"
    rescan: Literal[
        "ABSENT", "NO_SEGMENTS", "CONTIGUOUS_UNVERIFIED", "REPLAY_NOT_APPLIED",
    ] = "ABSENT"
    reorg: Literal[
        "ABSENT", "NO_PROGRESS_EVIDENCE", "CONTIGUOUS_BUT_UNVERIFIED",
        "REPLAY_NOT_DOUBLE_COUNTED", "ROLLBACK_RESCAN_REVIEW",
        "MIGRATION_RESCAN_REVIEW",
    ] = "ABSENT"
    scanner_session: Literal[
        "ABSENT", "LOCAL_RPC_OBSERVED_UNTRUSTED",
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


def _valid_scanner(value: object) -> bool:
    """Only untrusted bounded scalar observations may reach GUI state."""
    return (
        type(value) is ScannerReadOnlyObservation
        and type(value.reported_tip_height) is int
        and 0 <= value.reported_tip_height <= 100_000_000
        and type(value.blocks_observed) is int
        and 0 <= value.blocks_observed <= 16
        and type(value.transactions_observed) is int
        and 0 <= value.transactions_observed <= 20_000
        and type(value.mempool_ids_observed) is int
        and 0 <= value.mempool_ids_observed <= 20_000
        and value.status == "LOCAL_RPC_OBSERVED_UNTRUSTED"
        and value.scanner_enabled is False
        and value.wallet_ready is False
        and value.chain_verified is False
        and value.core_execution_allowed is False
        and value.signer_enabled is False
        and value.broadcast_allowed is False
        and value.mainnet_allowed is False
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


def _valid_resume(value: object) -> bool:
    """Strict scalar shape check: a resume preview never grants authority."""
    if type(value) is not OfflineResumeReview:
        return False
    if (
        type(value.revision) is not int or not 1 <= value.revision < 2**63
        or type(value.interrupted_height) is not int
        or type(value.claimed_checkpoint_height) is not int
        or not 0 <= value.claimed_checkpoint_height <= value.interrupted_height <= 100_000_000
        or type(value.action) is not str or type(value.reason) is not str
        or type(value.status) is not str
        or value.status != "OFFLINE_RESUME_UNTRUSTED"
        or value.scanner_enabled is not False
        or value.wallet_enabled is not False
        or value.resume_authorized is not False
        or value.checkpoint_durable is not False
        or value.chain_verified is not False
        or value.release_allowed is not False
    ):
        return False
    cases = {
        "REVALIDATE_BEFORE_RESCAN": "UNVERIFIED_INTERRUPTION",
        "REWIND_RESCAN_REVIEW": "REORG_OR_ROLLBACK_SUSPECTED",
        "MIGRATION_RESCAN_REVIEW": "SCHEMA_MIGRATION_REQUIRED",
    }
    return cases.get(value.action) == value.reason


def _valid_rescan(value: object) -> bool:
    """Valid only as nonauthorizing in-memory rescan accounting evidence."""
    if type(value) is not OfflineRescanSegments:
        return False
    if (
        type(value.revision) is not int or not 1 <= value.revision < 2**63
        or type(value.start_height) is not int
        or type(value.observed_end_height) is not int
        or not 0 <= value.start_height <= value.observed_end_height <= 100_000_000
        or type(value.unique_segment_count) is not int
        or type(value.replay_count) is not int
        or not 0 <= value.unique_segment_count <= 8
        or not 0 <= value.replay_count <= 1
        or value.unique_segment_count + value.replay_count > 8
        or type(value.observed_block_count) is not int
        or value.observed_block_count != value.observed_end_height - value.start_height
        or not value.unique_segment_count <= value.observed_block_count <= 16 * value.unique_segment_count
        or type(value.observed_transaction_count) is not int
        or not 0 <= value.observed_transaction_count <= 20_000
        or type(value.status) is not str or value.status != "OFFLINE_RESCAN_UNTRUSTED"
        or type(value.disposition) is not str
        or type(value.resume_action) is not str
        or value.resume_action not in (
            "REVALIDATE_BEFORE_RESCAN", "REWIND_RESCAN_REVIEW",
            "MIGRATION_RESCAN_REVIEW",
        )
        or value.scanner_enabled is not False
        or value.resume_authorized is not False
        or value.checkpoint_durable is not False
        or value.chain_verified is not False
        or value.wallet_enabled is not False
        or value.release_allowed is not False
    ):
        return False
    if value.replay_count:
        return value.unique_segment_count > 0 and value.disposition == "REPLAY_NOT_APPLIED"
    if value.unique_segment_count == 0:
        return (value.disposition == "NO_SEGMENTS"
                and value.observed_transaction_count == 0)
    return value.disposition == "CONTIGUOUS_UNVERIFIED"


def _valid_reorg(value: object) -> bool:
    """Only bounded, non-authorizing synthetic reconciliation projections."""
    if type(value) is not OfflineReorgReconciliation:
        return False
    if (
        type(value.revision) is not int or not 1 <= value.revision < 2**63
        or type(value.claimed_start_height) is not int
        or type(value.claimed_end_height) is not int
        or not 0 <= value.claimed_start_height <= value.claimed_end_height <= 100_000_000
        or type(value.unique_segments) is not int
        or type(value.replay_segments) is not int
        or not 0 <= value.unique_segments <= 8
        or not 0 <= value.replay_segments <= 1
        or value.unique_segments + value.replay_segments > 8
        or not value.unique_segments <= (
            value.claimed_end_height - value.claimed_start_height
        ) <= 16 * value.unique_segments
        or type(value.status) is not str
        or value.status != "REORG_RECONCILIATION_UNTRUSTED"
        or type(value.verdict) is not str
        or value.chain_verified is not False
        or value.checkpoint_durable is not False
        or value.restart_authorized is not False
        or value.rescan_authorized is not False
        or value.scanner_enabled is not False
        or value.wallet_enabled is not False
        or value.release_allowed is not False
    ):
        return False
    if value.verdict == "NO_PROGRESS_EVIDENCE":
        return value.unique_segments == 0 and value.replay_segments == 0
    if value.verdict == "CONTIGUOUS_BUT_UNVERIFIED":
        return value.unique_segments > 0 and value.replay_segments == 0
    if value.verdict == "REPLAY_NOT_DOUBLE_COUNTED":
        return value.unique_segments > 0 and value.replay_segments == 1
    return value.verdict in ("ROLLBACK_RESCAN_REVIEW", "MIGRATION_RESCAN_REVIEW")


def _matched_reorg(reorg: OfflineReorgReconciliation, *,
                   resume: object, rescan: object, recovery: object) -> bool:
    if resume is not None:
        expected_verdicts = {
            "REVALIDATE_BEFORE_RESCAN": (
                "NO_PROGRESS_EVIDENCE", "CONTIGUOUS_BUT_UNVERIFIED",
                "REPLAY_NOT_DOUBLE_COUNTED",
            ),
            "REWIND_RESCAN_REVIEW": ("ROLLBACK_RESCAN_REVIEW",),
            "MIGRATION_RESCAN_REVIEW": ("MIGRATION_RESCAN_REVIEW",),
        }
        if (reorg.revision != resume.revision
                or reorg.verdict not in expected_verdicts[resume.action]):
            return False
    if rescan is not None:
        if (
            reorg.revision != rescan.revision
            or reorg.claimed_start_height != rescan.start_height
            or reorg.claimed_end_height != rescan.observed_end_height
            or reorg.unique_segments != rescan.unique_segment_count
            or reorg.replay_segments != rescan.replay_count
        ):
            return False
    if recovery is not None:
        expected_recovery = {
            "NO_PROGRESS_EVIDENCE": "REVIEW_ONLY_NOT_VERIFIED",
            "CONTIGUOUS_BUT_UNVERIFIED": "REVIEW_ONLY_NOT_VERIFIED",
            "REPLAY_NOT_DOUBLE_COUNTED": "REVIEW_ONLY_NOT_VERIFIED",
            "ROLLBACK_RESCAN_REVIEW": "RESCAN_REQUIRED",
            "MIGRATION_RESCAN_REVIEW": "MIGRATION_RESCAN_REQUIRED",
        }
        if expected_recovery[reorg.verdict] != recovery.decision:
            return False
    return True


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
        resume: object = None,
        rescan: object = None,
        reorg: object = None,
        scanner_observation: object = None,
    ) -> OfflinePresentationState:
        if type(expected_revision) is not int or expected_revision != self._state.revision:
            self._reject()
        if (
            (node is not None and not _valid_node(node))
            or (scanner_observation is not None
                and not _valid_scanner(scanner_observation))
            or (privacy is not None and not _valid_privacy(privacy))
            or (policy is not None and not _valid_policy(policy))
            or (receive is not None and not _valid_receive(receive))
            or (recovery is not None and not _valid_recovery(recovery))
            or (resume is not None and not _valid_resume(resume))
            or (rescan is not None and not _valid_rescan(rescan))
            or (resume is not None and rescan is not None and (
                rescan.revision != resume.revision
                or rescan.resume_action != resume.action
            ))
            or (reorg is not None and not _valid_reorg(reorg))
            or (reorg is not None and not _matched_reorg(
                reorg, resume=resume, rescan=rescan, recovery=recovery
            ))
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
            resume.action if resume is not None else "ABSENT",
            rescan.disposition if rescan is not None else "ABSENT",
            reorg.verdict if reorg is not None else "ABSENT",
            scanner_session=("LOCAL_RPC_OBSERVED_UNTRUSTED"
                             if scanner_observation is not None else "ABSENT"),
        )
        return self._state
