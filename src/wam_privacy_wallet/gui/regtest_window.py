"""REGTEST application workspace with real local lifecycle and explicit holds.

No synthetic node/account is an application backend. The scanner adapter is
not imported or activated until Core/WSP/runtime gates have actual approval.
Only mode selection, local policy inspection, cancel and close are actionable.
"""
from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QCheckBox, QHBoxLayout, QLabel, QListWidget, QMainWindow, QPushButton,
    QStackedWidget, QVBoxLayout, QWidget,
)

from wam_privacy_wallet.application.regtest_lifecycle import BLOCKERS, RegtestLifecycleError
from wam_privacy_wallet.application.qualified_scan_session import ScanSnapshot
from wam_privacy_wallet.integrations.wsp1_source_review import PINNED_COMMIT
from .regtest_worker import RegtestWorkerController

VIEWS = (
    ("Dashboard", "No wallet is loaded. Select REGTEST and inspect local gates."),
    ("Node Connection", "BLOCKED: authenticated Core image, loader, configuration and isolated two-node approval are required (#82/#86/#153/#9)."),
    ("Receive", "BLOCKED: scan-only account provisioning and WSP review must be approved before displaying a user receive address."),
    ("Transactions", "BLOCKED: no genuine Core payment history is available."),
    ("Balance / UTXO", "BLOCKED: balance and ownership are unqualified. No amount is fabricated."),
    ("Send / Transaction Preparation", "REVIEW_ONLY: unsigned PSBT and normalized privacy policy are tested. Operational construction, signer and broadcast remain BLOCKED."),
    ("Backup / Recovery", "REVIEW_ONLY: experimental encrypted scan-only storage exists on qualified Linux. Trusted anti-rollback remains BLOCKED (#148/#151)."),
    ("Privacy", "REVIEW_ONLY: source-pinned coin selection, PayJoin, network policy and public HPKE reviews do not grant wallet or network authority."),
    ("Security / Diagnostics", "BLOCKED: WSP upstream review and Core release/runtime approval remain pending. Local gate inspection is not artifact authentication."),
)


class RegtestWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("WAM Privacy Wallet — REGTEST qualification")
        self.resize(1100, 720)
        self.controller = RegtestWorkerController(self)
        self._closing = False
        root = QWidget(self)
        column = QVBoxLayout(root)
        column.addWidget(QLabel("WAM Privacy Wallet · REGTEST ONLY · EXPERIMENTAL · NO REAL FUNDS"))
        self.lifecycle_status = QLabel("MODE_REQUIRED")
        column.addWidget(self.lifecycle_status)
        self.authority_status = QLabel("NO WALLET LOADED · SIGNER / BROADCAST BLOCKED")
        column.addWidget(self.authority_status)
        self.scan_review_status = QLabel("NO WSP-1 SCAN REVIEW")
        self.scan_review_status.setWordWrap(True)
        column.addWidget(self.scan_review_status)
        controls = QHBoxLayout()
        self.mode_button = QPushButton("Select REGTEST")
        self.consent = QCheckBox("I consent to local readiness inspection")
        self.inspect_button = QPushButton("Inspect local gates")
        self.cancel_button = QPushButton("Cancel")
        for widget in (self.mode_button, self.consent, self.inspect_button, self.cancel_button):
            controls.addWidget(widget)
        column.addLayout(controls)
        body = QHBoxLayout()
        self.navigation = QListWidget()
        self.navigation.addItems([name for name, _ in VIEWS])
        self.pages = QStackedWidget()
        for name, message in VIEWS:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.addWidget(QLabel(name))
            description = QLabel(message)
            description.setWordWrap(True)
            layout.addWidget(description)
            layout.addStretch()
            self.pages.addWidget(page)
        body.addWidget(self.navigation, 1)
        body.addWidget(self.pages, 4)
        column.addLayout(body, 1)
        self.blocker_status = QLabel("Holds: " + ", ".join(f"#{n}" for n in BLOCKERS) + " · WSP upstream review")
        self.blocker_status.setWordWrap(True)
        column.addWidget(self.blocker_status)
        self.setCentralWidget(root)
        self.navigation.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.navigation.setCurrentRow(0)
        self.mode_button.clicked.connect(self._select)
        self.inspect_button.clicked.connect(self._inspect)
        self.cancel_button.clicked.connect(self.controller.cancel)
        self.consent.toggled.connect(self._refresh_controls)
        self.controller.state_changed.connect(self._render)
        self.controller.idle.connect(self._refresh_controls)
        self._render(self.controller.lifecycle.state)

    def _select(self):
        try:
            self.controller.select_regtest()
        except RegtestLifecycleError:
            self.lifecycle_status.setText("APP_REGTEST_MODE_DENIED")

    def _inspect(self):
        try:
            self.controller.inspect(consent=self.consent.isChecked())
        except RegtestLifecycleError:
            self.lifecycle_status.setText("APP_REGTEST_CONSENT_OR_STATE_DENIED")

    def _refresh_controls(self):
        state = self.controller.lifecycle.state
        available = not self._closing and state.phase != "CLOSED" and not self.controller.busy
        self.mode_button.setEnabled(available)
        self.consent.setEnabled(available)
        self.inspect_button.setEnabled(available and state.mode == "REGTEST" and self.consent.isChecked())
        self.cancel_button.setEnabled(self.controller.busy and not self._closing)

    def _render(self, state):
        self.lifecycle_status.setText(f"{state.mode} · {state.phase} · {state.readiness}")
        # This local lifecycle never loads a wallet or authorizes a backend.
        self.authority_status.setText("NO WALLET LOADED · SIGNER / BROADCAST BLOCKED")
        self.clear_scan_review()
        self._refresh_controls()

    def clear_scan_review(self):
        """Erase prior scanner display whenever a GUI lifecycle revision changes."""
        self.scan_review_status.setText("NO WSP-1 SCAN REVIEW")

    def present_untrusted_scan_receipt(self, receipt, *, user_consented: bool):
        """Read-only Qt projection of scalar scanner evidence, never wallet state.

        This accepts a source-pinned DTO but cannot authenticate its origin.
        No node, WSP engine, wallet, signing role or RPC is loaded here.
        """
        self.clear_scan_review()
        state = self.controller.lifecycle.state
        if (user_consented is not True or state.mode != "REGTEST"
                or state.phase in ("MODE_REQUIRED", "CHECKING", "CLOSED")
                or self._closing or self.controller.busy
                or type(receipt) is not ScanSnapshot):
            raise RegtestLifecycleError("APP_REGTEST_SCAN_REVIEW_DENIED")
        try:
            # Revalidate even a frozen dataclass: Python code can mutate slots.
            checked = ScanSnapshot(
                receipt.tip_height, receipt.confirmed_utxo_count,
                receipt.unqualified_confirmed_atoms, receipt.history_count,
                receipt.mempool_observed, receipt.mempool_utxo_count,
                receipt.unqualified_mempool_atoms, receipt.mempool_spend_count,
                chain_current=receipt.chain_current,
                blocks_processed=receipt.blocks_processed,
                transactions_processed=receipt.transactions_processed,
                rollback_blocks=receipt.rollback_blocks,
                mempool_transactions_processed=receipt.mempool_transactions_processed,
            )
            if (checked != receipt or receipt.source_commit != PINNED_COMMIT
                    or receipt.evidence != "PINNED_SCAN_STORE_PROJECTED_UNTRUSTED"
                    or receipt.scope != "disposable-regtest-review"
                    or any(getattr(receipt, flag) is not False for flag in (
                        "core_authenticated", "wallet_operational", "balance_qualified",
                        "signer_enabled", "broadcast_allowed", "mainnet_allowed"))):
                raise ValueError("not a non-authorizing receipt")
        except Exception:
            raise RegtestLifecycleError("APP_REGTEST_SCAN_REVIEW_DENIED") from None
        # Do not render amounts, addresses, account IDs, txids or any user secret.
        # Chain-current is only the upstream scanner's *last observed* local tip.
        coins = (str(receipt.confirmed_utxo_count) + " UNQUALIFIED"
                 if receipt.chain_current else "UNAVAILABLE (INCOMPLETE SCAN)")
        self.scan_review_status.setText(
            "REVIEW_ONLY_UNTRUSTED · NO VERIFIED CORE · NO WALLET BALANCE · "
            f"reported tip {receipt.tip_height} · blocks {receipt.blocks_processed} · "
            f"tx {receipt.transactions_processed} · observed UTXOs {coins}"
        )

    def closeEvent(self, event):
        self._closing = True
        if not self.controller.shutdown(wait_ms=0):
            event.ignore()
            self.lifecycle_status.setText("CLOSING · waiting for cooperative worker cleanup")
            QTimer.singleShot(25, self.close)
            return
        event.accept()
