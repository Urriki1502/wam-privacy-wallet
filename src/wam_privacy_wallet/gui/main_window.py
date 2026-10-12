"""A navigable, offline-only Qt shell for the future cross-platform wallet.

No wallet key material, filesystem state, node RPC, or network access belongs
in this module. The content is intentionally static until backend contracts
have been qualified on both macOS and Windows.
"""

from __future__ import annotations

from PySide6.QtCore import Qt

from wam_privacy_wallet.application.presentation_lifecycle import OfflinePresentationController, OfflineLifecycleError, _valid_recovery, _valid_resume, _valid_rescan, _valid_reorg, _valid_scanner, _valid_psbt
from wam_privacy_wallet.application.node_status import NodeOverview
from wam_privacy_wallet.application.scanner_session_workflow import ScannerReadOnlyObservation
from wam_privacy_wallet.application.wsp_scan_coordinator import WspScanSessionSummary
from wam_privacy_wallet.application.privacy_readiness import PrivacyResearchSnapshot
from wam_privacy_wallet.application.policy_evidence import SyntheticPolicyReport
from wam_privacy_wallet.application.receive_vector import ReceiveVectorPreview, _FIXED_FINGERPRINT
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

PAGE_CONTENT: tuple[tuple[str, str], ...] = (
    (
        "Overview",
        "This is an interface prototype. No wallet is loaded and no blockchain "
        "connection is active.",
    ),
    (
        "Receive",
        "Silent Payment addresses will appear here after WSP-1 integration "
        "and the network profile are approved. No address is generated now.",
    ),
    (
        "Send",
        "Transaction construction, signing, and broadcasting are disabled. "
        "This prototype cannot move funds.",
    ),
    (
        "Privacy",
        "Wallet privacy, PayJoin, and network safeguards will require "
        "separate, reviewed adapters. None is enabled in this preview.",
    ),
    (
        "Node",
        "A future release will connect to the user's own validating WAM "
        "Core node. No RPC connection is made by this preview.",
    ),
    (
        "Recovery",
        "Backup and recovery are unavailable until the WSP-1 key-custody "
        "and recovery boundaries are independently tested.",
    ),
)

_STYLESHEET = """
QMainWindow, QWidget#mainRoot { background: #111827; color: #e5e7eb; }
QFrame#topBar, QFrame#sidebar, QFrame#pagePanel {
    background: #182334; border: 1px solid #344256; border-radius: 12px;
}
QFrame#statusCard {
    background: #202d3f; border: 1px solid #405269; border-radius: 9px;
}
QLabel#appTitle { color: #f8fafc; font-size: 23px; font-weight: 700; }
QLabel#subtitle, QLabel#smallText { color: #abb8cc; font-size: 12px; }
QLabel#notice { color: #fcd34d; font-size: 12px; font-weight: 600; }
QLabel#pageHeading { color: #f8fafc; font-size: 26px; font-weight: 700; }
QLabel#pageDescription { color: #cbd5e1; font-size: 14px; }
QLabel#sectionHeading { color: #cbd5e1; font-size: 12px; font-weight: 700; }
QLabel#statusValue { color: #e2e8f0; font-size: 13px; font-weight: 600; }
QListWidget#navigation {
    background: transparent; border: 0; color: #cbd5e1;
    font-size: 14px; outline: none;
}
QListWidget#navigation::item { padding: 12px 14px; border-radius: 7px; }
QListWidget#navigation::item:selected { background: #265479; color: #ffffff; }
QListWidget#navigation::item:hover:!selected { background: #26364a; }
"""


class MainWindow(QMainWindow):
    """Presentation-only shell with no operational wallet actions."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._offline_controller = OfflinePresentationController()
        # Internal Qt projection writes must not recursively mutate revision.
        self._managed_render_depth = 0
        # Nested Qt callbacks may re-enter public updates. Poison the
        # enclosing transition even when the callback swallows its error.
        self._managed_transition_active = False
        self._managed_transition_interrupted = False
        self.setObjectName("wamPrivacyWalletWindow")
        self.setWindowTitle("WAM Privacy Wallet — Experimental")
        self.setMinimumSize(960, 620)
        self.setStyleSheet(_STYLESHEET)

        root = QWidget(self)
        root.setObjectName("mainRoot")
        layout = QVBoxLayout(root)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(18)

        layout.addWidget(self._build_header())

        body = QHBoxLayout()
        body.setSpacing(18)
        body.addWidget(self._build_sidebar())

        self.page_stack = QStackedWidget(self)
        self.page_stack.setObjectName("pageStack")
        self._page_titles: list[QLabel] = []
        for title, description in PAGE_CONTENT:
            self.page_stack.addWidget(self._build_page(title, description))
        body.addWidget(self.page_stack, stretch=1)
        layout.addLayout(body, stretch=1)

        self.setCentralWidget(root)
        self.navigation.currentRowChanged.connect(self._select_page)
        self.navigation.setCurrentRow(0)

    @property
    def page_names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in PAGE_CONTENT)

    @property
    def current_page_title(self) -> str:
        return self._page_titles[self.page_stack.currentIndex()].text()

    def _build_header(self) -> QFrame:
        frame = QFrame(self)
        frame.setObjectName("topBar")
        row = QHBoxLayout(frame)
        row.setContentsMargins(20, 16, 20, 16)

        title_group = QVBoxLayout()
        title = QLabel("WAM Privacy Wallet")
        title.setObjectName("appTitle")
        title_group.addWidget(title)
        tagline = QLabel("Cross-platform desktop research preview")
        tagline.setObjectName("subtitle")
        title_group.addWidget(tagline)
        row.addLayout(title_group)
        row.addStretch(1)

        self.experimental_banner = QLabel("EXPERIMENTAL · NO REAL FUNDS")
        self.experimental_banner.setObjectName("notice")
        self.experimental_banner.setAlignment(Qt.AlignmentFlag.AlignRight)
        row.addWidget(self.experimental_banner)
        return frame

    def _build_sidebar(self) -> QFrame:
        frame = QFrame(self)
        frame.setObjectName("sidebar")
        frame.setFixedWidth(225)
        column = QVBoxLayout(frame)
        column.setContentsMargins(12, 18, 12, 16)
        column.setSpacing(14)

        heading = QLabel("WORKSPACE")
        heading.setObjectName("sectionHeading")
        column.addWidget(heading)

        self.navigation = QListWidget(frame)
        self.navigation.setObjectName("navigation")
        self.navigation.addItems([name for name, _ in PAGE_CONTENT])
        self.navigation.setSpacing(3)
        self.navigation.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        column.addWidget(self.navigation, stretch=1)

        footer = QLabel("OFFLINE PREVIEW · 0.0.0")
        footer.setObjectName("smallText")
        column.addWidget(footer)
        return frame

    def _build_page(self, title: str, description: str) -> QFrame:
        panel = QFrame(self)
        panel.setObjectName("pagePanel")
        column = QVBoxLayout(panel)
        column.setContentsMargins(28, 28, 28, 28)
        column.setSpacing(18)

        heading = QLabel(title)
        heading.setObjectName("pageHeading")
        self._page_titles.append(heading)
        column.addWidget(heading)

        message = QLabel(description)
        message.setObjectName("pageDescription")
        message.setWordWrap(True)
        column.addWidget(message)

        column.addSpacing(12)
        if title == "Overview":
            self.node_status = QLabel("DISCONNECTED · NO RPC")
            self.session_status = QLabel("NO WALLET LOADED")
            column.addWidget(self._status_card("LOCAL NODE", self.node_status))
            column.addWidget(self._status_card("WALLET SESSION", self.session_status))
            caution = QLabel(
                "No addresses, balances, transactions, signing, or backups "
                "are available in this shell."
            )
            caution.setObjectName("smallText")
            caution.setWordWrap(True)
            column.addWidget(caution)
        elif title == "Receive":
            self.receive_vector_status = QLabel("NO PUBLIC SAMPLE · NO ADDRESS GENERATED")
            column.addWidget(self._status_card("PINNED WSP-1 PUBLIC TEST VECTOR", self.receive_vector_status))
            self.receive_vector_notice = QLabel(
                "NOT A RECEIVING ADDRESS · NO QR / COPY · SCANNER AND SIGNER BLOCKED"
            )
            self.receive_vector_notice.setObjectName("smallText")
            self.receive_vector_notice.setWordWrap(True)
            column.addWidget(self.receive_vector_notice)
            placeholder = QLabel("REAL RECEIVE, DERIVATION & SCANNING · BLOCKED")
            placeholder.setObjectName("notice")
            column.addWidget(placeholder)
        elif title == "Node":
            self.node_diagnostic_status = QLabel("NO DIAGNOSTIC SNAPSHOT · NO RPC")
            column.addWidget(self._status_card("LOCAL OFFLINE DIAGNOSTIC", self.node_diagnostic_status))
            self.node_diagnostic_notice = QLabel(
                "UNVERIFIED DATA ONLY · NOT A CONNECTION OR WALLET AUTHORIZATION"
            )
            self.node_diagnostic_notice.setObjectName("smallText")
            self.node_diagnostic_notice.setWordWrap(True)
            column.addWidget(self.node_diagnostic_notice)
            self.scanner_read_only_status = QLabel("NO LOCAL SCANNER OBSERVATION")
            column.addWidget(self._status_card(
                "LOCAL SCAN DATA (READ-ONLY)", self.scanner_read_only_status
            ))
            self.scanner_read_only_notice = QLabel(
                "NOT A WALLET SCAN · NO SCANNER / SIGNER / BROADCAST AUTHORITY"
            )
            self.scanner_read_only_notice.setObjectName("smallText")
            self.scanner_read_only_notice.setWordWrap(True)
            column.addWidget(self.scanner_read_only_notice)
            self.wsp_session_status = QLabel("NO WSP-1 APPLICATION SCAN RECEIPT")
            column.addWidget(self._status_card(
                "WSP-1 APPLICATION SCAN · UNTRUSTED", self.wsp_session_status
            ))
            self.wsp_session_notice = QLabel(
                "REAL WSP SCANNER TEST EVIDENCE ONLY · NO VALIDATED CORE / WALLET / SEND"
            )
            self.wsp_session_notice.setObjectName("smallText")
            self.wsp_session_notice.setWordWrap(True)
            column.addWidget(self.wsp_session_notice)
            placeholder = QLabel("REAL WAM CORE INTEGRATION · BLOCKED")
            placeholder.setObjectName("notice")
            column.addWidget(placeholder)
        elif title == "Privacy":
            self.privacy_readiness_status = QLabel("RESEARCH INVENTORY · NOT LOADED")
            column.addWidget(self._status_card("PRIVACY RESEARCH", self.privacy_readiness_status))
            self.privacy_readiness_notice = QLabel(
                "WSP-1, PAYJOIN AND NETWORK PRIVACY · NO ACTIVE INTEGRATION"
            )
            self.privacy_readiness_notice.setObjectName("smallText")
            self.privacy_readiness_notice.setWordWrap(True)
            column.addWidget(self.privacy_readiness_notice)
            self.privacy_policy_status = QLabel("NO SYNTHETIC POLICY EVIDENCE")
            column.addWidget(self._status_card("SYNTHETIC POLICY MODEL", self.privacy_policy_status))
            self.privacy_policy_notice = QLabel(
                "PAYJOIN & NETWORK POLICY · NOT AUTHORIZED"
            )
            self.privacy_policy_notice.setObjectName("smallText")
            self.privacy_policy_notice.setWordWrap(True)
            column.addWidget(self.privacy_policy_notice)
            self.psbt_review_status = QLabel("NO UNSIGNED PSBT REVIEW")
            column.addWidget(self._status_card("UNSIGNED PSBT · EXPERIMENTAL", self.psbt_review_status))
            self.psbt_review_notice = QLabel("NO VERIFIED OWNERSHIP OR CHAIN · SIGNING / SENDING BLOCKED")
            self.psbt_review_notice.setObjectName("smallText")
            self.psbt_review_notice.setWordWrap(True)
            column.addWidget(self.psbt_review_notice)
            placeholder = QLabel("SCANNING, SIGNING AND SENDING · BLOCKED")
            placeholder.setObjectName("notice")
            column.addWidget(placeholder)
        elif title == "Recovery":
            self.recovery_review_status = QLabel("NO OFFLINE RECOVERY EVIDENCE")
            column.addWidget(self._status_card(
                "RECOVERY STATE · SYNTHETIC ONLY", self.recovery_review_status
            ))
            self.recovery_review_notice = QLabel(
                "NO WALLET RESTORED · NO DATABASE OPENED · SCANNER / SIGNER BLOCKED"
            )
            self.recovery_review_notice.setObjectName("smallText")
            self.recovery_review_notice.setWordWrap(True)
            column.addWidget(self.recovery_review_notice)
            self.resume_review_status = QLabel("RESUME DISABLED · NO RESTART EVIDENCE")
            column.addWidget(self._status_card(
                "RESTART / RESCAN · SYNTHETIC REVIEW", self.resume_review_status
            ))
            self.resume_review_notice = QLabel(
                "NO AUTOMATIC RESUME · NO DATABASE WRITER OR LIVE SCANNER"
            )
            self.resume_review_notice.setObjectName("smallText")
            self.resume_review_notice.setWordWrap(True)
            column.addWidget(self.resume_review_notice)
            self.rescan_segments_status = QLabel("NO RESCAN SEGMENT EVIDENCE")
            column.addWidget(self._status_card(
                "RESCAN SEGMENTS · SIMULATED ACCOUNTING", self.rescan_segments_status
            ))
            self.rescan_segments_notice = QLabel(
                "NO DURABLE CHECKPOINT · NO SCANNER · NO WALLET"
            )
            self.rescan_segments_notice.setObjectName("smallText")
            self.rescan_segments_notice.setWordWrap(True)
            column.addWidget(self.rescan_segments_notice)
            self.reorg_review_status = QLabel("NO REORG RECONCILIATION EVIDENCE")
            column.addWidget(self._status_card(
                "CHECKPOINT / REORG · SYNTHETIC REVIEW", self.reorg_review_status
            ))
            self.reorg_review_notice = QLabel(
                "NO TRUSTED CURSOR · NO SCANNER / WALLET / RELEASE"
            )
            self.reorg_review_notice.setObjectName("smallText")
            self.reorg_review_notice.setWordWrap(True)
            column.addWidget(self.reorg_review_notice)
            placeholder = QLabel("REAL BACKUP, RESTORE AND MIGRATION · BLOCKED")
            placeholder.setObjectName("notice")
            column.addWidget(placeholder)
        else:
            placeholder = QLabel("NOT IMPLEMENTED · REVIEW REQUIRED")
            placeholder.setObjectName("notice")
            column.addWidget(placeholder)

        column.addStretch(1)
        return panel

    def _status_card(self, caption: str, value: QLabel) -> QFrame:
        frame = QFrame(self)
        frame.setObjectName("statusCard")
        contents = QVBoxLayout(frame)
        contents.setContentsMargins(16, 14, 16, 14)
        contents.setSpacing(7)
        label = QLabel(caption)
        label.setObjectName("sectionHeading")
        contents.addWidget(label)
        value.setObjectName("statusValue")
        contents.addWidget(value)
        return frame

    @property
    def offline_presentation_state(self):
        """Immutable offline evidence state; never confers wallet authority."""
        return self._offline_controller.state

    def _clear_managed_panels(self) -> None:
        """Attempt ALL panel resets and signal any failure without leaking Qt details.

        Partial cleanup is never silently accepted; a broken label setter must
        not stop the other seven panels from being cleared.
        """
        self._managed_render_depth += 1
        failed = False
        try:
            for clear in (
                self.clear_offline_node_snapshot,
                self.clear_offline_privacy_readiness,
                self.clear_offline_policy_report,
                self.clear_unsigned_psbt_review,
                self.clear_public_receive_vector,
                self.clear_offline_recovery_review,
                self.clear_offline_resume_review,
                self.clear_offline_rescan_segments,
                self.clear_offline_reorg_reconciliation,
                self.clear_scanner_read_only_observation,
                self.clear_wsp_scan_session_summary,
            ):
                try:
                    clear()
                except Exception:
                    failed = True
        finally:
            self._managed_render_depth -= 1
        if failed:
            raise OfflineLifecycleError("APP_OFFLINE_RENDER_DENIED") from None

    def _begin_managed_transition(self) -> None:
        """Reject nested public transactions without mutating their revision."""
        if self._managed_transition_active:
            self._managed_transition_interrupted = True
            raise OfflineLifecycleError("APP_OFFLINE_REENTRANT_DENIED") from None
        self._managed_transition_active = True
        self._managed_transition_interrupted = False

    def _assert_managed_transition_clean(self) -> None:
        """A swallowed nested exception still poisons the outer operation."""
        if self._managed_transition_interrupted:
            raise OfflineLifecycleError("APP_OFFLINE_REENTRANT_DENIED") from None

    def _end_managed_transition(self) -> None:
        self._managed_transition_active = False
        self._managed_transition_interrupted = False

    def clear_offline_presentation(self) -> None:
        """Invalidate revision before cleanup; reject reentrant view resets."""
        self._begin_managed_transition()
        try:
            self._offline_controller.reset()
            try:
                self._clear_managed_panels()
                self._assert_managed_transition_clean()
            except Exception:
                # A faulty/reentrant Qt callback cannot restore a stale view.
                try:
                    self._clear_managed_panels()
                except Exception:
                    pass
                raise OfflineLifecycleError("APP_OFFLINE_RENDER_DENIED") from None
        finally:
            self._end_managed_transition()

    def replace_offline_presentation(
        self, expected_revision: object, *, node: object = None,
        privacy: object = None, policy: object = None, receive: object = None,
        recovery: object = None, resume: object = None,
        rescan: object = None, reorg: object = None,
        scanner_observation: object = None, psbt_review: object = None,
    ) -> None:
        """Atomically validate all eight synthetic DTOs before displaying."""
        self._begin_managed_transition()
        try:
            try:
                state = self._offline_controller.replace(
                    expected_revision, node=node, privacy=privacy,
                    policy=policy, receive=receive, recovery=recovery, resume=resume,
                    rescan=rescan, reorg=reorg,
                    scanner_observation=scanner_observation, psbt_review=psbt_review,
                )
            except OfflineLifecycleError:
                # Validation already rejected the revision; still clear every
                # panel even if a broken widget raises while clearing.
                try:
                    self._clear_managed_panels()
                except OfflineLifecycleError:
                    pass
                raise
            try:
                # Reset is part of the guarded transition: previously a failure
                # here escaped before the controller revision was invalidated.
                self._clear_managed_panels()
                self._managed_render_depth += 1
                try:
                    if state.node == "UNVERIFIED":
                        self.present_offline_node_snapshot(node)
                    if state.privacy == "RESEARCH_ONLY":
                        self.present_offline_privacy_readiness(privacy)
                    if state.psbt != "ABSENT":
                        self.present_unsigned_psbt_review(psbt_review)
                    if state.policy == "MODEL_ONLY":
                        self.present_offline_policy_report(policy)
                    if state.receive == "PUBLIC_FIXTURE":
                        self.present_public_receive_vector(receive)
                    if state.recovery != "ABSENT":
                        self.present_offline_recovery_review(recovery)
                    if state.resume != "ABSENT":
                        self.present_offline_resume_review(resume)
                    if state.rescan != "ABSENT":
                        self.present_offline_rescan_segments(rescan)
                    if state.reorg != "ABSENT":
                        self.present_offline_reorg_reconciliation(reorg)
                    if state.scanner_session != "ABSENT":
                        self.present_scanner_read_only_observation(scanner_observation)
                finally:
                    self._managed_render_depth -= 1
                self._assert_managed_transition_clean()
            except Exception:
                # Presentation or reset can fail after a revision was accepted.
                # Invalidate it, attempt every panel reset, and redact the error.
                self._offline_controller.reset()
                try:
                    self._clear_managed_panels()
                except OfflineLifecycleError:
                    pass
                raise OfflineLifecycleError("APP_OFFLINE_RENDER_DENIED") from None
        finally:
            self._end_managed_transition()

    def present_scanner_read_only_observation(self, observation: object) -> None:
        """Show no-authority WSP scanner-RPC counts, NEVER a wallet scan."""
        if not _valid_scanner(observation):
            raise ValueError("APP_GUI_SCANNER_OBSERVATION_DENIED")
        if not self._managed_render_depth:
            self.replace_offline_presentation(
                self._offline_controller.state.revision,
                scanner_observation=observation,
            )
            return
        self.scanner_read_only_status.setText(
            f"UNTRUSTED · regtest height {observation.reported_tip_height} · "
            f"blocks read {observation.blocks_observed} · NO WALLET SCAN"
        )
        self.scanner_read_only_notice.setText(
            "LOCAL RPC COUNTS ONLY · NO VALIDATED CORE / SCANNER / KEYS / SEND"
        )

    def clear_scanner_read_only_observation(self) -> None:
        if not self._managed_render_depth:
            self.clear_offline_presentation()
            return
        self.scanner_read_only_status.setText("NO LOCAL SCANNER OBSERVATION")
        self.scanner_read_only_notice.setText(
            "NOT A WALLET SCAN · NO SCANNER / SIGNER / BROADCAST AUTHORITY"
        )

    def present_wsp_scan_session_summary(self, summary: object) -> None:
        """Render a sanitized REAL WSP scanner result without live wallet claims.

        External caller may supply only the immutable scalar App DTO. This
        method never imports WSP, talks to a node, stores the DTO or obtains
        account material. Any new offline UI transaction clears this receipt.
        """
        self._begin_managed_transition()
        try:
            self._offline_controller.reset()
            try:
                self._clear_managed_panels()
                if not (
                    type(summary) is WspScanSessionSummary
                    and summary.status == "WSP1_SCAN_EXECUTED_UNTRUSTED_CORE"
                    and type(summary.blocks_processed) is int
                    and 0 <= summary.blocks_processed <= 16
                    and type(summary.transactions_processed) is int
                    and 0 <= summary.transactions_processed <= 160_000
                    and type(summary.rollback_blocks) is int
                    and 0 <= summary.rollback_blocks <= 100_000
                    and type(summary.mempool_transactions_processed) is int
                    and 0 <= summary.mempool_transactions_processed <= 10_000
                    and (summary.blocks_processed > 0 or
                         summary.transactions_processed == 0)
                    and summary.core_authenticated is False
                    and summary.wallet_operational is False
                    and summary.balance_qualified is False
                    and summary.signer_enabled is False
                    and summary.broadcast_allowed is False
                    and summary.mainnet_allowed is False
                ):
                    raise ValueError("APP_GUI_WSP_RECEIPT_DENIED")
                self._managed_render_depth += 1
                try:
                    self.wsp_session_status.setText(
                        f"WSP-1 SCAN EXECUTED · UNTRUSTED CORE · "
                        f"blocks {summary.blocks_processed} · "
                        f"tx {summary.transactions_processed} · "
                        f"reorg {summary.rollback_blocks}"
                    )
                    self.wsp_session_notice.setText(
                        "TESTED WSP-1 SCANNER · NO VALIDATED CORE / BALANCE / "
                        "WALLET / SIGN / BROADCAST"
                    )
                finally:
                    self._managed_render_depth -= 1
                self._assert_managed_transition_clean()
            except Exception:
                self._offline_controller.reset()
                try:
                    self._clear_managed_panels()
                except Exception:
                    pass
                raise ValueError("APP_GUI_WSP_RECEIPT_DENIED") from None
        finally:
            self._end_managed_transition()

    def clear_wsp_scan_session_summary(self) -> None:
        """Erase the untrusted real-scanner receipt with the GUI single writer."""
        if not self._managed_render_depth:
            self.clear_offline_presentation()
            return
        self.wsp_session_status.setText("NO WSP-1 APPLICATION SCAN RECEIPT")
        self.wsp_session_notice.setText(
            "REAL WSP SCANNER TEST EVIDENCE ONLY · "
            "NO VALIDATED CORE / WALLET / SEND"
        )

    def present_offline_recovery_review(self, preview: object) -> None:
        """Display only fixed vocabulary from a synthetic recovery transition.

        Never show hashes, paths, checkpoint identifiers or raw input strings.
        Recovery decisions DO NOT grant persistence, scanner or wallet rights.
        """
        if not _valid_recovery(preview):
            raise ValueError("APP_GUI_RECOVERY_REVIEW_DENIED")
        if not self._managed_render_depth:
            self.replace_offline_presentation(
                self._offline_controller.state.revision, recovery=preview
            )
            return
        messages = {
            "REVIEW_ONLY_NOT_VERIFIED":
                "UNTRUSTED CHECKPOINT · RECOVERY NOT VERIFIED",
            "RESCAN_REQUIRED": "RESCAN REQUIRED · NOT PERFORMED",
            "MIGRATION_RESCAN_REQUIRED":
                "MIGRATION + RESCAN REQUIRED · NOT PERFORMED",
        }
        self.recovery_review_status.setText(messages[preview.decision])
        self.recovery_review_notice.setText(
            "SYNTHETIC REVIEW ONLY · NO WALLET RESTORED · "
            "SCANNER / SIGNER / SEND BLOCKED"
        )

    def clear_offline_recovery_review(self) -> None:
        """Invalidate all research panels on direct clear; no wallet IO."""
        if not self._managed_render_depth:
            self.clear_offline_presentation()
            return
        self.recovery_review_status.setText("NO OFFLINE RECOVERY EVIDENCE")
        self.recovery_review_notice.setText(
            "NO WALLET RESTORED · NO DATABASE OPENED · SCANNER / SIGNER BLOCKED"
        )

    def present_offline_resume_review(self, preview: object) -> None:
        """Show fixed crash/restart guidance, never grant resumable authority."""
        if not _valid_resume(preview):
            raise ValueError("APP_GUI_RESUME_REVIEW_DENIED")
        if not self._managed_render_depth:
            self.replace_offline_presentation(
                self._offline_controller.state.revision, resume=preview
            )
            return
        text = {
            "REVALIDATE_BEFORE_RESCAN":
                "REVALIDATE CHECKPOINT · RESUME NOT AUTHORIZED",
            "REWIND_RESCAN_REVIEW":
                "REWIND / RESCAN REVIEW · NOT STARTED",
            "MIGRATION_RESCAN_REVIEW":
                "MIGRATION + RESCAN REVIEW · NOT STARTED",
        }
        self.resume_review_status.setText(text[preview.action])
        self.resume_review_notice.setText(
            "SYNTHETIC INTERRUPTION ONLY · NO NODE / DB / SCANNER · "
            "NO AUTOMATIC RESUME"
        )

    def clear_offline_resume_review(self) -> None:
        """Clear non-persistent resume research evidence through single writer."""
        if not self._managed_render_depth:
            self.clear_offline_presentation()
            return
        self.resume_review_status.setText("RESUME DISABLED · NO RESTART EVIDENCE")
        self.resume_review_notice.setText(
            "NO AUTOMATIC RESUME · NO DATABASE WRITER OR LIVE SCANNER"
        )

    def present_offline_rescan_segments(self, report: object) -> None:
        """Render only fixed research labels, never cursor/hash or permission."""
        if not _valid_rescan(report):
            raise ValueError("APP_GUI_RESCAN_SEGMENTS_DENIED")
        if not self._managed_render_depth:
            self.replace_offline_presentation(
                self._offline_controller.state.revision, rescan=report
            )
            return
        text = {
            "NO_SEGMENTS": "NO SEGMENTS · NOTHING SCANNED",
            "CONTIGUOUS_UNVERIFIED": "CONTIGUOUS FIXTURE · NOT COMMITTED",
            "REPLAY_NOT_APPLIED": "REPLAY DETECTED · NOT DOUBLE COUNTED",
        }
        self.rescan_segments_status.setText(text[report.disposition])
        self.rescan_segments_notice.setText(
            "UNTRUSTED IN-MEMORY ACCOUNTING · NO DURABLE CHECKPOINT / LIVE SCANNER"
        )

    def clear_offline_rescan_segments(self) -> None:
        """Invalidate rescan evidence with the same whole-panel lifecycle."""
        if not self._managed_render_depth:
            self.clear_offline_presentation()
            return
        self.rescan_segments_status.setText("NO RESCAN SEGMENT EVIDENCE")
        self.rescan_segments_notice.setText(
            "NO DURABLE CHECKPOINT · NO SCANNER · NO WALLET"
        )

    def present_offline_reorg_reconciliation(self, report: object) -> None:
        """Display fixed reconciliation warning, never derive a rescan cursor."""
        if not _valid_reorg(report):
            raise ValueError("APP_GUI_REORG_REVIEW_DENIED")
        if not self._managed_render_depth:
            self.replace_offline_presentation(
                self._offline_controller.state.revision, reorg=report
            )
            return
        messages = {
            "NO_PROGRESS_EVIDENCE": "NO VERIFIED RESCAN PROGRESS",
            "CONTIGUOUS_BUT_UNVERIFIED": "CONTIGUOUS CLAIM · NOT AUTHENTICATED",
            "REPLAY_NOT_DOUBLE_COUNTED": "REPLAY CLAIM · NOT COMMITTED",
            "ROLLBACK_RESCAN_REVIEW": "ROLLBACK REVIEW · NO SAFE CURSOR",
            "MIGRATION_RESCAN_REVIEW": "MIGRATION REVIEW · NO SAFE CURSOR",
        }
        self.reorg_review_status.setText(messages[report.verdict])
        self.reorg_review_notice.setText(
            "UNTRUSTED CROSS-SOURCE RECONCILIATION · "
            "NO RESCAN / RESTART AUTHORIZATION"
        )

    def clear_offline_reorg_reconciliation(self) -> None:
        """Remove untrusted reconciliation view via the single writer."""
        if not self._managed_render_depth:
            self.clear_offline_presentation()
            return
        self.reorg_review_status.setText("NO REORG RECONCILIATION EVIDENCE")
        self.reorg_review_notice.setText(
            "NO TRUSTED CURSOR · NO SCANNER / WALLET / RELEASE"
        )

    def present_offline_node_snapshot(self, snapshot: object) -> None:
        """Display a non-authorizing, unverified projection; no node/RPC access.

        Caller must supply an exact immutable application NodeOverview. This
        presentation method never keeps the snapshot or the original profile.
        A caller-created object does not establish trusted Core provenance.
        """
        if (
            type(snapshot) is not NodeOverview
            or type(snapshot.network) is not str
            or snapshot.network != "regtest"
            or type(snapshot.height) is not int
            or not 0 <= snapshot.height <= 100_000_000
            or type(snapshot.status) is not str
            or snapshot.status != "READ_ONLY_SNAPSHOT"
            or type(snapshot.notice) is not str
            or snapshot.notice != "EXPERIMENTAL_NO_REAL_FUNDS"
        ):
            raise ValueError("APP_GUI_DIAGNOSTIC_REJECTED")
        if not self._managed_render_depth:
            self.replace_offline_presentation(
                self._offline_controller.state.revision, node=snapshot
            )
            return
        self.node_diagnostic_status.setText(
            f"UNVERIFIED · regtest height {snapshot.height} · NO RPC"
        )
        self.node_diagnostic_notice.setText(
            "POINT-IN-TIME READ-ONLY PROJECTION · NOT A NODE CONNECTION "
            "OR WALLET AUTHORIZATION"
        )

    def clear_offline_node_snapshot(self) -> None:
        """Clear the view without retaining a profile or transport handle."""
        if not self._managed_render_depth:
            self.clear_offline_presentation()
            return
        self.node_diagnostic_status.setText("NO DIAGNOSTIC SNAPSHOT · NO RPC")
        self.node_diagnostic_notice.setText(
            "UNVERIFIED DATA ONLY · NOT A CONNECTION OR WALLET AUTHORIZATION"
        )

    def present_offline_privacy_readiness(self, snapshot: object) -> None:
        """Show a fixed no-authority summary, never import or enable an engine."""
        if (
            type(snapshot) is not PrivacyResearchSnapshot
            or type(snapshot.research_state) is not str
            or snapshot.research_state != "RESEARCH_ONLY"
            or type(snapshot.wsp_source) is not str
            or snapshot.wsp_source != "PIN_RECORDED_UNATTESTED"
            or type(snapshot.wallet_privacy) is not str
            or snapshot.wallet_privacy != "MODEL_ONLY"
            or type(snapshot.payjoin) is not str
            or snapshot.payjoin != "MODEL_ONLY"
            or type(snapshot.network_privacy) is not str
            or snapshot.network_privacy != "MODEL_ONLY"
            or type(snapshot.selective_disclosure) is not str
            or snapshot.selective_disclosure != "NOT_INTEGRATED"
            or type(snapshot.scan) is not str or snapshot.scan != "BLOCKED"
            or type(snapshot.sign) is not str or snapshot.sign != "BLOCKED"
            or type(snapshot.send) is not str or snapshot.send != "BLOCKED"
        ):
            raise ValueError("APP_GUI_PRIVACY_GATE_REJECTED")
        # Fixed vocabulary prevents accidental display of untrusted manifest
        # blocker text, paths, RPC settings, keys, or authority-like claims.
        if not self._managed_render_depth:
            self.replace_offline_presentation(
                self._offline_controller.state.revision, privacy=snapshot
            )
            return
        self.privacy_readiness_status.setText(
            "RESEARCH ONLY · 0 ACTIVE WALLET CAPABILITIES"
        )
        self.privacy_readiness_notice.setText(
            "WSP-1 SOURCE PIN RECORDED (UNATTESTED) · "
            "WALLET PRIVACY / PAYJOIN / NETWORK MODELS ONLY · "
            "SCANNER / SIGNER / SEND BLOCKED"
        )

    def clear_offline_privacy_readiness(self) -> None:
        """Reset to the non-authorizing preview without storing evidence."""
        if not self._managed_render_depth:
            self.clear_offline_presentation()
            return
        self.privacy_readiness_status.setText("RESEARCH INVENTORY · NOT LOADED")
        self.privacy_readiness_notice.setText(
            "WSP-1, PAYJOIN AND NETWORK PRIVACY · NO ACTIVE INTEGRATION"
        )

    def present_offline_policy_report(self, report: object) -> None:
        """Present only fixed model vocabulary; never authorize operations."""
        if (
            type(report) is not SyntheticPolicyReport
            or type(report.provenance) is not str
            or report.provenance != "PIN_RECORDED_UNATTESTED"
            or type(report.network) is not str
            or report.network != "MODEL_PASS_UNTRUSTED"
            or type(report.payjoin) is not str
            or report.payjoin != "MODEL_PASS_UNTRUSTED"
            or type(report.authority) is not str
            or report.authority != "MODEL_ONLY_NO_AUTHORITY"
            or type(report.scan) is not str or report.scan != "BLOCKED"
            or type(report.sign) is not str or report.sign != "BLOCKED"
            or type(report.send) is not str or report.send != "BLOCKED"
        ):
            raise ValueError("APP_GUI_SYNTHETIC_POLICY_DENIED")
        if not self._managed_render_depth:
            self.replace_offline_presentation(
                self._offline_controller.state.revision, policy=report
            )
            return
        self.privacy_policy_status.setText(
            "SIMULATED MODELS · UNTRUSTED · NOT AUTHORIZED"
        )
        self.privacy_policy_notice.setText(
            "NETWORK & PAYJOIN MODEL RESULTS ONLY · NO RPC / SIGN / SEND"
        )

    def present_unsigned_psbt_review(self, review: object) -> None:
        """Display a scalar receipt only; a supplied DTO is never attestation."""
        if not _valid_psbt(review):
            self.clear_offline_presentation()
            raise ValueError("APP_GUI_PSBT_REVIEW_DENIED") from None
        if not self._managed_render_depth:
            self.replace_offline_presentation(
                self._offline_controller.state.revision, psbt_review=review
            )
            return
        self.psbt_review_status.setText(
            f"UNSIGNED PARSE · inputs {review.input_count} · outputs {review.output_count} · UNTRUSTED"
        )
        self.psbt_review_notice.setText(
            "SYNTHETIC ONLY · SOURCE ac55f134 · NO VERIFIED OWNERSHIP OR CHAIN · SIGNING / SENDING BLOCKED"
        )

    def review_unsigned_psbt_fixture(
        self, raw: object, *, source_root: object, scope: object, consent: object,
    ) -> None:
        """Explicit synthetic review; clear stale evidence before consent checks."""
        self.clear_offline_presentation()
        from wam_privacy_wallet.application.psbt_v2_review import (
            PsbtV2ReviewError, review_synthetic_psbt_v2,
        )
        try:
            review = review_synthetic_psbt_v2(
                raw, source_root=source_root, scope=scope, consent=consent,
            )
        except PsbtV2ReviewError:
            raise ValueError("APP_GUI_PSBT_REVIEW_DENIED") from None
        self.present_unsigned_psbt_review(review)

    def clear_unsigned_psbt_review(self) -> None:
        if not self._managed_render_depth:
            self.clear_offline_presentation()
            return
        self.psbt_review_status.setText("NO UNSIGNED PSBT REVIEW")
        self.psbt_review_notice.setText(
            "NO VERIFIED OWNERSHIP OR CHAIN · SIGNING / SENDING BLOCKED"
        )

    def review_offline_policy_inputs(
        self, endpoints: object, original: object, proposal: object, *,
        payment_output_index: object, scope: object, consent: object,
        async_payjoin: object = False,
    ) -> None:
        """Evaluate explicit synthetic inputs and display only model vocabulary.

        No input is retained by Qt. Clear the previous presentation before
        evaluation so rejected input/consent cannot leave a stale PASS visible.
        The existing single-writer controller owns all display transitions.
        """
        self.clear_offline_presentation()
        from wam_privacy_wallet.application.network_plan_review import (
            NetworkPlanReviewError, review_synthetic_network_plan,
        )
        from wam_privacy_wallet.application.payjoin_proposal_review import (
            PayjoinProposalReviewError, review_synthetic_payjoin_proposal,
        )
        try:
            review_synthetic_network_plan(
                endpoints, scope=scope, consent=consent, async_payjoin=async_payjoin,
            )
            review_synthetic_payjoin_proposal(
                original, proposal, payment_output_index=payment_output_index,
                scope=scope, consent=consent,
            )
        except (NetworkPlanReviewError, PayjoinProposalReviewError):
            raise ValueError("APP_GUI_POLICY_INPUT_REVIEW_DENIED") from None
        self.present_offline_policy_report(SyntheticPolicyReport(
            "PIN_RECORDED_UNATTESTED", "MODEL_PASS_UNTRUSTED",
            "MODEL_PASS_UNTRUSTED", "MODEL_ONLY_NO_AUTHORITY",
            "BLOCKED", "BLOCKED", "BLOCKED",
        ))

    def run_fixed_offline_policy_demo(self) -> None:
        """Explicitly run a pinned, no-argument synthetic-only research demo.

        No real transaction, remote plan, wallet state, signer or Core is read.
        All model results are displayed as untrusted and not authorized.
        """
        from wam_privacy_wallet.application.synthetic_policy_demo import (
            SyntheticDemoError, run_fixed_synthetic_privacy_demo,
        )
        try:
            report = run_fixed_synthetic_privacy_demo()
        except SyntheticDemoError:
            self.clear_offline_policy_report()
            raise ValueError("APP_GUI_SYNTHETIC_MODEL_DENIED") from None
        self.present_offline_policy_report(report)

    def clear_offline_policy_report(self) -> None:
        """Reset only the synthetic model panel; never persist the input."""
        if not self._managed_render_depth:
            self.clear_offline_presentation()
            return
        self.privacy_policy_status.setText("NO SYNTHETIC POLICY EVIDENCE")
        self.privacy_policy_notice.setText(
            "PAYJOIN & NETWORK POLICY · NOT AUTHORIZED"
        )

    def present_public_receive_vector(self, preview: object) -> None:
        """Render a fingerprint only; never expose an address or QR action."""
        if (
            type(preview) is not ReceiveVectorPreview
            or type(preview.profile) is not str
            or preview.profile != "WSP-1"
            or type(preview.network) is not str
            or preview.network != "regtest"
            or type(preview.provenance) is not str
            or preview.provenance != "PIN_RECORDED_UNATTESTED"
            or type(preview.sample) is not str
            or preview.sample != "PUBLIC_SYNTHETIC_FIXTURE"
            or type(preview.fingerprint) is not str
            or preview.fingerprint != _FIXED_FINGERPRINT
            or type(preview.receive) is not str or preview.receive != "BLOCKED"
            or type(preview.scanner) is not str or preview.scanner != "BLOCKED"
            or type(preview.signer) is not str or preview.signer != "BLOCKED"
        ):
            raise ValueError("APP_GUI_RECEIVE_VECTOR_DENIED")
        if not self._managed_render_depth:
            self.replace_offline_presentation(
                self._offline_controller.state.revision, receive=preview
            )
            return
        self.receive_vector_status.setText(
            f"SYNTHETIC REGTEST · PUBLIC FINGERPRINT {_FIXED_FINGERPRINT}"
        )
        self.receive_vector_notice.setText(
            "PUBLIC TEST VECTOR ONLY · NOT A RECEIVING ADDRESS · "
            "NO QR / COPY · NO SCANNER / SIGNER"
        )

    def clear_public_receive_vector(self) -> None:
        """Remove the optional preview; no wallet object is ever retained."""
        if not self._managed_render_depth:
            self.clear_offline_presentation()
            return
        self.receive_vector_status.setText("NO PUBLIC SAMPLE · NO ADDRESS GENERATED")
        self.receive_vector_notice.setText(
            "NOT A RECEIVING ADDRESS · NO QR / COPY · SCANNER AND SIGNER BLOCKED"
        )

    def run_fixed_public_receive_demo(self) -> None:
        """Explicit offline preview. Never starts a scanner or derives keys."""
        from wam_privacy_wallet.application.receive_vector import (
            ReceiveVectorError, inspect_pinned_public_vector,
        )
        try:
            preview = inspect_pinned_public_vector()
        except ReceiveVectorError:
            self.clear_public_receive_vector()
            raise ValueError("APP_GUI_RECEIVE_VECTOR_DENIED") from None
        self.present_public_receive_vector(preview)

    def _select_page(self, index: int) -> None:
        if 0 <= index < self.page_stack.count():
            self.page_stack.setCurrentIndex(index)
