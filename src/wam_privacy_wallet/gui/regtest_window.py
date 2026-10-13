"""REGTEST application workspace with real local lifecycle and explicit holds.

No synthetic node/account is an application backend. The scanner adapter is
not imported or activated until Core/WSP/runtime gates have actual approval.
Only mode selection, local policy inspection, cancel and close are actionable.
"""
from __future__ import annotations

import sys
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QCheckBox, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QMainWindow, QPlainTextEdit, QPushButton, QSpinBox, QStackedWidget, QVBoxLayout, QWidget,
)

from wam_privacy_wallet.application.regtest_lifecycle import BLOCKERS, RegtestLifecycleError
from wam_privacy_wallet.application.qualified_scan_session import ScanSnapshot
from wam_privacy_wallet.node.gui_two_node_readonly import LiveNodeGuiEvidence
from wam_privacy_wallet.application.qt_native_wsp_bridge import QtNativeScanEvidence
from wam_privacy_wallet.application.qt_native_private_workflow import (
    PrivateQtHistoryRow, PrivateQtWorkflowEvidence,
)
from wam_privacy_wallet.integrations.wsp1_source_review import PINNED_COMMIT
from .regtest_worker import RegtestWorkerController

VIEWS = (
    ("Dashboard", "No wallet is loaded. Select REGTEST and inspect local gates."),
    ("Node Connection", "REVIEW_ONLY: inspect two existing localhost REGTEST nodes. Core image, loader, configuration and genuine two-node E2E remain BLOCKED (#82/#86/#153/#9)."),
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
            if name == "Node Connection":
                form = QFormLayout()
                self.node_ports = {}
                for label, key, initial in (
                    ("Node A RPC port", "a_rpc", 29554),
                    ("Node A P2P port", "a_p2p", 29555),
                    ("Node B RPC port", "b_rpc", 29556),
                    ("Node B P2P port", "b_p2p", 29557),
                ):
                    control = QSpinBox()
                    control.setRange(1024, 65535)
                    control.setValue(initial)
                    self.node_ports[key] = control
                    form.addRow(label, control)
                    control.valueChanged.connect(self._refresh_controls)
                self.node_inputs = {}
                for label, key, secret in (
                    ("Node A RPC username", "a_user", False),
                    ("Node A RPC password", "a_password", True),
                    ("Node B RPC username", "b_user", False),
                    ("Node B RPC password", "b_password", True),
                ):
                    control = QLineEdit()
                    if secret:
                        control.setEchoMode(QLineEdit.EchoMode.Password)
                    control.textChanged.connect(self._refresh_controls)
                    self.node_inputs[key] = control
                    form.addRow(label, control)
                layout.addLayout(form)
                self.node_ack = QCheckBox(
                    "I acknowledge these node binaries are NOT authenticated"
                )
                self.node_ack.toggled.connect(self._refresh_controls)
                layout.addWidget(self.node_ack)
                self.node_probe_button = QPushButton("Probe two existing REGTEST nodes")
                self.node_probe_button.clicked.connect(self._probe_nodes)
                layout.addWidget(self.node_probe_button)
                self.node_probe_status = QLabel("NO NODE CONNECTION INSPECTION")
                self.node_probe_status.setWordWrap(True)
                layout.addWidget(self.node_probe_status)
                form_scan = QFormLayout()
                self.scan_inputs = {}
                for label, key, secret in (
                    ("Pinned WSP-1 source checkout (absolute)", "source", False),
                    ("Disposable scan-only directory (absolute)", "private", False),
                    ("Scan-only backup passphrase", "passphrase", True),
                ):
                    control = QLineEdit()
                    if secret:
                        control.setEchoMode(QLineEdit.EchoMode.Password)
                    control.textChanged.connect(self._refresh_controls)
                    self.scan_inputs[key] = control
                    form_scan.addRow(label, control)
                layout.addLayout(form_scan)
                self.scan_button = QPushButton(
                    "Scan existing 2-node WSP-1 (Linux x64 only, max 16 blocks)"
                )
                self.scan_button.clicked.connect(self._scan_existing)
                layout.addWidget(self.scan_button)
            if name == "Receive":
                self.receive_ack = QCheckBox(
                    "I consent to view a LOCAL disposable WSP receive code (not a verified wallet)"
                )
                self.receive_ack.toggled.connect(self._refresh_controls)
                layout.addWidget(self.receive_ack)
                self.receive_button = QPushButton("Show REGTEST WSP receive code")
                self.receive_button.clicked.connect(lambda: self._private_action("receive"))
                layout.addWidget(self.receive_button)
                self.receive_status = QPlainTextEdit()
                self.receive_status.setReadOnly(True)
                self.receive_status.setPlainText("NO PRIVATE RECEIVE CODE")
                layout.addWidget(self.receive_status)
            if name == "Balance / UTXO":
                self.balance_ack = QCheckBox(
                    "I consent to view UNQUALIFIED observed atoms, not spendable balance"
                )
                self.balance_ack.toggled.connect(self._refresh_controls)
                layout.addWidget(self.balance_ack)
                self.balance_button = QPushButton("Read observed REGTEST atoms")
                self.balance_button.clicked.connect(lambda: self._private_action("balance"))
                layout.addWidget(self.balance_button)
                self.balance_status = QLabel("NO OBSERVED BALANCE")
                layout.addWidget(self.balance_status)
            if name == "Transactions":
                self.history_ack = QCheckBox(
                    "I explicitly consent to display PRIVATE local REGTEST transaction IDs and amounts"
                )
                self.history_ack.toggled.connect(self._refresh_controls)
                layout.addWidget(self.history_ack)
                self.history_button = QPushButton("Read newest 20 WSP-1 confirmed transactions")
                self.history_button.clicked.connect(lambda: self._private_action("history"))
                layout.addWidget(self.history_button)
                self.private_history_status = QPlainTextEdit()
                self.private_history_status.setReadOnly(True)
                self.private_history_status.setPlainText("NO PRIVATE TRANSACTION HISTORY")
                layout.addWidget(self.private_history_status)
            if name == "Backup / Recovery":
                self.backup_ack = QCheckBox(
                    "I understand: checkpoint is create-once; no trusted anti-rollback protection"
                )
                self.backup_ack.toggled.connect(self._refresh_controls)
                layout.addWidget(self.backup_ack)
                self.checkpoint_button = QPushButton("Save encrypted WSP-1 checkpoint once")
                self.restore_button = QPushButton(
                    "Restore checkpoint in NEW scan-only directory, then rescan"
                )
                self.checkpoint_button.clicked.connect(
                    lambda: self._private_action("checkpoint")
                )
                self.restore_button.clicked.connect(
                    lambda: self._private_action("restore")
                )
                layout.addWidget(self.checkpoint_button)
                layout.addWidget(self.restore_button)
                self.backup_status = QLabel("NO BACKUP / RECOVERY OPERATION")
                self.backup_status.setWordWrap(True)
                layout.addWidget(self.backup_status)
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
        self.navigation.currentRowChanged.connect(self._hide_private_history)
        self.navigation.setCurrentRow(0)
        self.mode_button.clicked.connect(self._select)
        self.inspect_button.clicked.connect(self._inspect)
        self.cancel_button.clicked.connect(self.controller.cancel)
        self.consent.toggled.connect(self._refresh_controls)
        self.controller.state_changed.connect(self._render)
        self.controller.idle.connect(self._refresh_controls)
        self.controller.node_probe_completed.connect(self._node_probed)
        self.controller.node_probe_failed.connect(self._node_failed)
        self.controller.scan_completed.connect(self._scan_completed)
        self.controller.scan_failed.connect(self._scan_failed)
        self.controller.private_completed.connect(self._private_completed)
        self.controller.private_failed.connect(self._private_failed)
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

    def _probe_nodes(self):
        state = self.controller.lifecycle.state
        try:
            self.node_probe_status.setText("INSPECTING · READ-ONLY · UNTRUSTED CORE")
            a_password = self.node_inputs["a_password"].text()
            b_password = self.node_inputs["b_password"].text()
            # Clear UI widgets before starting worker; neither credential is
            # logged, stored on disk or put into a public GUI status receipt.
            self.node_inputs["a_password"].clear()
            self.node_inputs["b_password"].clear()
            self.controller.inspect_nodes(
                node_a_rpc=self.node_ports["a_rpc"].value(),
                node_a_p2p=self.node_ports["a_p2p"].value(),
                node_a_user=self.node_inputs["a_user"].text(),
                node_a_password=a_password,
                node_b_rpc=self.node_ports["b_rpc"].value(),
                node_b_p2p=self.node_ports["b_p2p"].value(),
                node_b_user=self.node_inputs["b_user"].text(),
                node_b_password=b_password,
                consent=self.consent.isChecked(),
                unverified_core_ack=self.node_ack.isChecked(),
            )
        except (ValueError, RegtestLifecycleError):
            self.node_probe_status.setText("APP_REGTEST_NODE_PROBE_DENIED")

    def _scan_existing(self):
        self.clear_scan_review()
        try:
            a_password = self.node_inputs["a_password"].text()
            b_password = self.node_inputs["b_password"].text()
            scan_passphrase = self.scan_inputs["passphrase"].text()
            self.node_inputs["a_password"].clear()
            self.node_inputs["b_password"].clear()
            self.scan_inputs["passphrase"].clear()
            self.controller.scan_existing(
                source_root=self.scan_inputs["source"].text(),
                private_dir=self.scan_inputs["private"].text(),
                scan_password=scan_passphrase,
                node_a_rpc=self.node_ports["a_rpc"].value(),
                node_a_p2p=self.node_ports["a_p2p"].value(),
                node_a_user=self.node_inputs["a_user"].text(),
                node_a_password=a_password,
                node_b_rpc=self.node_ports["b_rpc"].value(),
                node_b_p2p=self.node_ports["b_p2p"].value(),
                node_b_user=self.node_inputs["b_user"].text(),
                node_b_password=b_password,
                consent=self.consent.isChecked(),
                unverified_core_ack=self.node_ack.isChecked(),
            )
        except (RegtestLifecycleError, ValueError):
            self.scan_review_status.setText("QT_NATIVE_WSP_SCAN_DENIED")

    def _hide_private_history(self, _index):
        # Never carry private txids/amounts into another GUI page.
        self.private_history_status.setPlainText("NO PRIVATE TRANSACTION HISTORY")
        self.history_ack.setChecked(False)
        self.receive_status.setPlainText("NO PRIVATE RECEIVE CODE")
        self.receive_ack.setChecked(False)
        self.balance_status.setText("NO OBSERVED BALANCE")
        self.balance_ack.setChecked(False)

    def _private_action(self, operation):
        self.private_history_status.setPlainText("NO PRIVATE TRANSACTION HISTORY")
        self.backup_status.setText("NO BACKUP / RECOVERY OPERATION")
        self.receive_status.setPlainText("NO PRIVATE RECEIVE CODE")
        self.balance_status.setText("NO OBSERVED BALANCE")
        try:
            page = self.navigation.currentRow()
            ack = ((operation == "receive" and page == 2
                    and self.receive_ack.isChecked()) or
                   (operation == "balance" and page == 4
                    and self.balance_ack.isChecked()) or
                   (operation == "history" and page == 3
                    and self.history_ack.isChecked()) or
                   (operation in ("checkpoint", "restore") and page == 6
                    and self.backup_ack.isChecked()))
            if not ack:
                raise RegtestLifecycleError("APP_REGTEST_PRIVATE_SCOPE_DENIED")
            a_password = self.node_inputs["a_password"].text()
            b_password = self.node_inputs["b_password"].text()
            passphrase = self.scan_inputs["passphrase"].text()
            self.node_inputs["a_password"].clear()
            self.node_inputs["b_password"].clear()
            self.scan_inputs["passphrase"].clear()
            self.controller.private_workflow(
                operation=operation,
                source_root=self.scan_inputs["source"].text(),
                private_dir=self.scan_inputs["private"].text(),
                scan_password=passphrase,
                node_a_rpc=self.node_ports["a_rpc"].value(),
                node_a_p2p=self.node_ports["a_p2p"].value(),
                node_a_user=self.node_inputs["a_user"].text(),
                node_a_password=a_password,
                node_b_rpc=self.node_ports["b_rpc"].value(),
                node_b_p2p=self.node_ports["b_p2p"].value(),
                node_b_user=self.node_inputs["b_user"].text(),
                node_b_password=b_password,
                consent=self.consent.isChecked(),
                unverified_core_ack=self.node_ack.isChecked(),
                private_display_ack=True,
            )
        except (ValueError, RegtestLifecycleError):
            if operation == "history":
                self.private_history_status.setPlainText("QT_PRIVATE_WORK_DENIED")
            elif operation == "receive":
                self.receive_status.setPlainText("QT_PRIVATE_WORK_DENIED")
            elif operation == "balance":
                self.balance_status.setText("QT_PRIVATE_WORK_DENIED")
            else:
                self.backup_status.setText("QT_PRIVATE_WORK_DENIED")

    def _private_completed(self, revision, receipt):
        state = self.controller.lifecycle.state
        try:
            if (self._closing or type(revision) is not int
                    or revision != state.revision
                    or state.mode != "REGTEST"
                    or state.phase in ("CLOSED", "CANCELLED")
                    or not self.consent.isChecked() or not self.node_ack.isChecked()
                    or type(receipt) is not PrivateQtWorkflowEvidence
                    or ((receipt.operation == "receive" and
                         (self.navigation.currentRow() != 2
                          or not self.receive_ack.isChecked()))
                        or (receipt.operation == "balance" and
                            (self.navigation.currentRow() != 4
                             or not self.balance_ack.isChecked()))
                        or (receipt.operation == "history" and
                         (self.navigation.currentRow() != 3
                          or not self.history_ack.isChecked()))
                        or (receipt.operation in ("checkpoint", "restore") and
                            (self.navigation.currentRow() != 6
                             or not self.backup_ack.isChecked())))):
                raise ValueError
            rows = tuple(PrivateQtHistoryRow(
                x.txid, x.height, x.confirmations,
                x.credit_atoms, x.debit_atoms
            ) for x in receipt.rows)
            checked = PrivateQtWorkflowEvidence(
                receipt.operation, receipt.tip_height, rows,
                receive_code=receipt.receive_code,
                observed_atoms=receipt.observed_atoms,
            )
            if checked != receipt:
                raise ValueError
        except Exception:
            self.private_history_status.setPlainText("NO PRIVATE TRANSACTION HISTORY")
            self.backup_status.setText("NO BACKUP / RECOVERY OPERATION")
            self.receive_status.setPlainText("NO PRIVATE RECEIVE CODE")
            self.balance_status.setText("NO OBSERVED BALANCE")
            return
        if receipt.operation == "receive":
            self.receive_status.setPlainText(
                "LOCAL DISPOSABLE REGTEST WSP CODE · UNVERIFIED CORE\n"
                + receipt.receive_code
            )
        elif receipt.operation == "balance":
            self.balance_status.setText(
                f"OBSERVED {receipt.observed_atoms} atoms · UNQUALIFIED · "
                "NOT SPENDABLE · NO VERIFIED CORE"
            )
        elif receipt.operation == "history":
            lines = [
                "PRIVATE LOCAL WSP-1 HISTORY · UNQUALIFIED CORE · NO SIGNING"
            ]
            if not receipt.rows:
                lines.append("NO CONFIRMED TRANSACTIONS IN LATEST PAGE")
            for row in receipt.rows:
                lines.append(
                    f"txid {row.txid} · block {row.height} · "
                    f"conf {row.confirmations} · credit {row.credit_atoms} atoms · "
                    f"debit {row.debit_atoms} atoms (UNQUALIFIED)"
                )
            self.private_history_status.setPlainText("\n".join(lines))
        else:
            msg = (
                "ENCRYPTED CHECKPOINT CREATED (CREATE-ONCE)"
                if receipt.operation == "checkpoint"
                else "ENCRYPTED CHECKPOINT RESTORED AND RESCANNED"
            )
            self.backup_status.setText(
                msg + " · UNTRUSTED ANTI-ROLLBACK · NO VERIFIED CORE"
            )

    def _private_failed(self, revision):
        if type(revision) is int and revision == self.controller.lifecycle.state.revision:
            self.private_history_status.setPlainText("QT_PRIVATE_WORK_DENIED")
            self.backup_status.setText("QT_PRIVATE_WORK_DENIED")
            self.receive_status.setPlainText("QT_PRIVATE_WORK_DENIED")
            self.balance_status.setText("QT_PRIVATE_WORK_DENIED")

    def _scan_completed(self, revision, receipt):
        state = self.controller.lifecycle.state
        try:
            if (self._closing or state.mode != "REGTEST" or
                    state.phase in ("CLOSED", "CANCELLED") or
                    not self.consent.isChecked() or not self.node_ack.isChecked() or
                    type(revision) is not int or state.revision != revision or
                    type(receipt) is not QtNativeScanEvidence):
                raise ValueError
            checked = QtNativeScanEvidence(
                receipt.tip_height, receipt.chain_current,
                receipt.blocks_processed, receipt.transactions_processed,
                receipt.observed_utxos,
            )
            if checked != receipt:
                raise ValueError
        except Exception:
            self.clear_scan_review()
            return
        count = (f"{receipt.observed_utxos} UNQUALIFIED"
                 if receipt.chain_current else "UNAVAILABLE: SCAN INCOMPLETE")
        self.scan_review_status.setText(
            "REAL LOCAL WSP-1 · TWO-NODE REPORTED CHAIN · "
            "NO VERIFIED CORE / WALLET / SIGNER / BROADCAST · "
            f"height {receipt.tip_height} · blocks {receipt.blocks_processed} · "
            f"tx {receipt.transactions_processed} · observed UTXOs {count}"
        )

    def _scan_failed(self, revision):
        if type(revision) is int and revision == self.controller.lifecycle.state.revision:
            self.scan_review_status.setText("QT_NATIVE_WSP_SCAN_DENIED")

    def _node_probed(self, revision, receipt):
        state = self.controller.lifecycle.state
        try:
            if (self._closing or state.mode != "REGTEST"
                    or state.phase in ("CLOSED", "CANCELLED")
                    or not self.consent.isChecked() or
                    not self.node_ack.isChecked()
                    or type(revision) is not int or
                    state.revision != revision or
                    type(receipt) is not LiveNodeGuiEvidence):
                raise ValueError
            checked = LiveNodeGuiEvidence(receipt.tip_height)
            if checked != receipt:
                raise ValueError
        except Exception:
            self.node_probe_status.setText("NO NODE CONNECTION INSPECTION")
            return
        self.node_probe_status.setText(
            "UNTRUSTED TWO-NODE REGTEST · RPC/P2P localhost observed · "
            f"reported tip {receipt.tip_height} · 1 peer/node · "
            "NO VERIFIED CORE · NO WALLET LOADED · NO SIGNER / BROADCAST"
        )

    def _node_failed(self, revision):
        if type(revision) is int and revision == self.controller.lifecycle.state.revision:
            self.node_probe_status.setText("APP_REGTEST_NODE_PROBE_DENIED")

    def _refresh_controls(self):
        state = self.controller.lifecycle.state
        available = not self._closing and state.phase != "CLOSED" and not self.controller.busy
        self.mode_button.setEnabled(available)
        self.consent.setEnabled(available)
        self.inspect_button.setEnabled(available and state.mode == "REGTEST" and self.consent.isChecked())
        self.cancel_button.setEnabled(self.controller.busy and not self._closing)
        ports = [v.value() for v in self.node_ports.values()]
        self.node_probe_button.setEnabled(
            available and state.mode == "REGTEST"
            and self.consent.isChecked() and self.node_ack.isChecked()
            and len(set(ports)) == 4
            and all(self.node_inputs[key].text()
                    for key in ("a_user", "a_password", "b_user", "b_password"))
        )
        self.scan_button.setEnabled(
            available and sys.platform == "linux" and state.mode == "REGTEST"
            and state.phase != "CANCELLED"
            and self.consent.isChecked() and self.node_ack.isChecked()
            and len(set(ports)) == 4
            and all(self.node_inputs[key].text()
                    for key in ("a_user","a_password","b_user","b_password"))
            and all(self.scan_inputs[key].text() for key in ("source","private","passphrase"))
        )
        private_ready = self.scan_button.isEnabled()
        self.receive_button.setEnabled(
            private_ready and self.receive_ack.isChecked()
            and self.navigation.currentRow() == 2
        )
        self.balance_button.setEnabled(
            private_ready and self.balance_ack.isChecked()
            and self.navigation.currentRow() == 4
        )
        self.history_button.setEnabled(
            private_ready and self.history_ack.isChecked()
            and self.navigation.currentRow() == 3
        )
        self.checkpoint_button.setEnabled(
            private_ready and self.backup_ack.isChecked()
            and self.navigation.currentRow() == 6
        )
        self.restore_button.setEnabled(
            private_ready and self.backup_ack.isChecked()
            and self.navigation.currentRow() == 6
        )

    def _render(self, state):
        self.lifecycle_status.setText(f"{state.mode} · {state.phase} · {state.readiness}")
        # This local lifecycle never loads a wallet or authorizes a backend.
        self.authority_status.setText("NO WALLET LOADED · SIGNER / BROADCAST BLOCKED")
        self.clear_scan_review()
        self.private_history_status.setPlainText("NO PRIVATE TRANSACTION HISTORY")
        self.backup_status.setText("NO BACKUP / RECOVERY OPERATION")
        self.receive_status.setPlainText("NO PRIVATE RECEIVE CODE")
        self.balance_status.setText("NO OBSERVED BALANCE")
        self.node_probe_status.setText("NO NODE CONNECTION INSPECTION")
        self._refresh_controls()

    def clear_scan_review(self):
        """Erase prior scanner display whenever a GUI lifecycle revision changes."""
        self.scan_review_status.setText("NO WSP-1 SCAN REVIEW")

    def present_untrusted_scan_receipt(self, receipt, *, user_consented: bool,
                                       expected_revision: int):
        """Read-only Qt projection of scalar scanner evidence, never wallet state.

        This accepts a source-pinned DTO but cannot authenticate its origin.
        No node, WSP engine, wallet, signing role or RPC is loaded here.
        """
        self.clear_scan_review()
        state = self.controller.lifecycle.state
        if (user_consented is not True or state.mode != "REGTEST"
                or state.phase not in ("REGTEST_SELECTED", "BLOCKED")
                or type(expected_revision) is not int
                or expected_revision != state.revision
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
        self.private_history_status.setPlainText("NO PRIVATE TRANSACTION HISTORY")
        self.backup_status.setText("NO BACKUP / RECOVERY OPERATION")
        self.receive_status.setPlainText("NO PRIVATE RECEIVE CODE")
        self.balance_status.setText("NO OBSERVED BALANCE")
        event.accept()
