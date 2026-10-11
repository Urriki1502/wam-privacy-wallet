"""A navigable, offline-only Qt shell for the future cross-platform wallet.

No wallet key material, filesystem state, node RPC, or network access belongs
in this module. The content is intentionally static until backend contracts
have been qualified on both macOS and Windows.
"""

from __future__ import annotations

from PySide6.QtCore import Qt

from wam_privacy_wallet.application.node_status import NodeOverview
from wam_privacy_wallet.application.privacy_readiness import PrivacyResearchSnapshot
from wam_privacy_wallet.application.policy_evidence import SyntheticPolicyReport
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
        elif title == "Node":
            self.node_diagnostic_status = QLabel("NO DIAGNOSTIC SNAPSHOT · NO RPC")
            column.addWidget(self._status_card("LOCAL OFFLINE DIAGNOSTIC", self.node_diagnostic_status))
            self.node_diagnostic_notice = QLabel(
                "UNVERIFIED DATA ONLY · NOT A CONNECTION OR WALLET AUTHORIZATION"
            )
            self.node_diagnostic_notice.setObjectName("smallText")
            self.node_diagnostic_notice.setWordWrap(True)
            column.addWidget(self.node_diagnostic_notice)
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
                "NO PAYJOIN OR NETWORK POLICY IS AUTHORIZED"
            )
            self.privacy_policy_notice.setObjectName("smallText")
            self.privacy_policy_notice.setWordWrap(True)
            column.addWidget(self.privacy_policy_notice)
            placeholder = QLabel("SCANNING, SIGNING AND SENDING · BLOCKED")
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
        self.node_diagnostic_status.setText(
            f"UNVERIFIED · regtest height {snapshot.height} · NO RPC"
        )
        self.node_diagnostic_notice.setText(
            "POINT-IN-TIME READ-ONLY PROJECTION · NOT A NODE CONNECTION "
            "OR WALLET AUTHORIZATION"
        )

    def clear_offline_node_snapshot(self) -> None:
        """Clear the view without retaining a profile or transport handle."""
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
        self.privacy_policy_status.setText(
            "SIMULATED MODELS · UNTRUSTED · NOT AUTHORIZED"
        )
        self.privacy_policy_notice.setText(
            "NETWORK & PAYJOIN MODEL RESULTS ONLY · NO RPC / SIGN / SEND"
        )

    def clear_offline_policy_report(self) -> None:
        """Reset only the synthetic model panel; never persist the input."""
        self.privacy_policy_status.setText("NO SYNTHETIC POLICY EVIDENCE")
        self.privacy_policy_notice.setText(
            "NO PAYJOIN OR NETWORK POLICY IS AUTHORIZED"
        )

    def _select_page(self, index: int) -> None:
        if 0 <= index < self.page_stack.count():
            self.page_stack.setCurrentIndex(index)
