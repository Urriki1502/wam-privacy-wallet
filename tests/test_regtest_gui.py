"""Actual Qt-thread/lifecycle tests. No operational node or fabricated wallet."""
import os
import sys
from pathlib import Path
import time
import unittest
from threading import Event, get_ident
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication

from wam_privacy_wallet.application.regtest_lifecycle import inspect_local_readiness, RegtestLifecycleError
from wam_privacy_wallet.application.qualified_scan_session import ScanSnapshot
from wam_privacy_wallet.node.gui_two_node_readonly import LiveNodeGuiEvidence
from wam_privacy_wallet.application.qt_native_wsp_bridge import QtNativeScanEvidence
from wam_privacy_wallet.gui.regtest_window import RegtestWindow, VIEWS


class RegtestGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = RegtestWindow()

    def drain(self, until=lambda: True):
        end = time.monotonic() + 5
        while time.monotonic() < end:
            QCoreApplication.processEvents()
            if until():
                return
            time.sleep(0.002)
        self.fail("Qt completion did not arrive")

    def tearDown(self):
        self.assertTrue(self.window.controller.shutdown(wait_ms=5000))
        self.drain(lambda: not self.window.controller.busy)
        self.window.close()
        self.window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        QCoreApplication.processEvents()

    def selected(self):
        self.window.mode_button.click()
        self.window.consent.setChecked(True)

    def show_review(self, proof, *, user_consented: bool, expected_revision=None):
        if expected_revision is None:
            expected_revision = self.window.controller.lifecycle.state.revision
        return self.window.present_untrusted_scan_receipt(
            proof, user_consented=user_consented, expected_revision=expected_revision,
        )

    def review_receipt(self, **changes):
        inputs = dict(tip_height=2, confirmed_utxo_count=1,
                      unqualified_confirmed_atoms=200000, history_count=1,
                      mempool_observed=False, mempool_utxo_count=None,
                      unqualified_mempool_atoms=None, mempool_spend_count=None,
                      blocks_processed=1, transactions_processed=2)
        inputs.update(changes)
        return ScanSnapshot(**inputs)

    def test_scan_review_requires_regtest_mode_and_explicit_consent(self):
        proof = self.review_receipt()
        with self.assertRaisesRegex(RegtestLifecycleError,
                                    "^APP_REGTEST_SCAN_REVIEW_DENIED$"):
            self.show_review(proof, user_consented=True)
        self.selected()
        with self.assertRaisesRegex(RegtestLifecycleError,
                                    "^APP_REGTEST_SCAN_REVIEW_DENIED$"):
            self.show_review(proof, user_consented=False)
        self.assertEqual(self.window.scan_review_status.text(), "NO WSP-1 SCAN REVIEW")

    def test_actual_shape_is_readonly_without_amounts_or_wallet_authority(self):
        self.selected()
        self.show_review(self.review_receipt(), user_consented=True)
        text = self.window.scan_review_status.text()
        self.assertIn("REVIEW_ONLY_UNTRUSTED", text)
        self.assertIn("reported tip 2", text)
        self.assertIn("observed UTXOs 1 UNQUALIFIED", text)
        self.assertNotIn("200000", text)
        self.assertIn("NO WALLET LOADED", self.window.authority_status.text())
        self.assertFalse(self.window.controller.lifecycle.state.wallet_operational)

    def test_partial_scan_never_displays_cached_balance_and_revision_clears(self):
        self.selected()
        partial = self.review_receipt(chain_current=False, confirmed_utxo_count=None,
                                      unqualified_confirmed_atoms=None, history_count=None)
        self.show_review(partial, user_consented=True)
        self.assertIn("UNAVAILABLE (INCOMPLETE SCAN)",
                      self.window.scan_review_status.text())
        self.assertNotIn("200000", self.window.scan_review_status.text())
        self.window.controller.select_regtest()
        self.assertEqual(self.window.scan_review_status.text(), "NO WSP-1 SCAN REVIEW")

    def test_forged_scan_authority_and_mutated_counts_clear_stale_receipt(self):
        self.selected()
        good = self.review_receipt()
        self.show_review(good, user_consented=True)
        object.__setattr__(good, "wallet_operational", True)
        with self.assertRaisesRegex(RegtestLifecycleError,
                                    "^APP_REGTEST_SCAN_REVIEW_DENIED$"):
            self.show_review(good, user_consented=True)
        self.assertEqual(self.window.scan_review_status.text(), "NO WSP-1 SCAN REVIEW")
        malformed = self.review_receipt()
        object.__setattr__(malformed, "confirmed_utxo_count", True)
        with self.assertRaises(RegtestLifecycleError):
            self.show_review(malformed, user_consented=True)
        self.assertEqual(self.window.scan_review_status.text(), "NO WSP-1 SCAN REVIEW")

    def test_late_scan_receipt_after_cancel_or_mode_revision_is_denied(self):
        self.selected()
        old_revision = self.window.controller.lifecycle.state.revision
        proof = self.review_receipt()
        self.window.controller.cancel()
        with self.assertRaisesRegex(RegtestLifecycleError,
                                    "^APP_REGTEST_SCAN_REVIEW_DENIED$"):
            self.show_review(proof, user_consented=True, expected_revision=old_revision)
        self.window.controller.select_regtest()
        with self.assertRaisesRegex(RegtestLifecycleError,
                                    "^APP_REGTEST_SCAN_REVIEW_DENIED$"):
            self.show_review(proof, user_consented=True, expected_revision=old_revision)
        self.assertEqual(self.window.scan_review_status.text(), "NO WSP-1 SCAN REVIEW")
        self.show_review(proof, user_consented=True)
        self.assertIn("REVIEW_ONLY_UNTRUSTED", self.window.scan_review_status.text())

    def test_required_nine_views_have_actual_blocked_status(self):
        self.assertEqual(self.window.pages.count(), 9)
        self.assertEqual(self.window.navigation.count(), 9)
        self.assertEqual(len(VIEWS), 9)
        self.assertIn("NO WALLET LOADED", self.window.authority_status.text())
        self.assertFalse(self.window.inspect_button.isEnabled())

    def test_mode_selection_and_explicit_consent_enable_only_local_inspection(self):
        self.window.mode_button.click()
        self.assertEqual(self.window.controller.lifecycle.state.mode, "REGTEST")
        self.assertFalse(self.window.inspect_button.isEnabled())
        self.window.consent.setChecked(True)
        self.assertTrue(self.window.inspect_button.isEnabled())

    def test_real_local_readiness_runs_on_worker_and_delivers_on_gui_thread(self):
        main = get_ident()
        calls, deliveries = [], []
        def observed(cancelled):
            calls.append(get_ident())
            return inspect_local_readiness(cancelled)
        self.window.controller.state_changed.connect(lambda _: deliveries.append(get_ident()))
        self.selected()
        with patch("wam_privacy_wallet.gui.regtest_worker.inspect_local_readiness", side_effect=observed):
            self.window.inspect_button.click()
            self.drain(lambda: not self.window.controller.busy)
        self.assertEqual(len(calls), 1)
        self.assertNotEqual(calls[0], main)
        self.assertEqual(set(deliveries), {main})
        self.assertIn("BLOCKED_EXTERNAL_APPROVAL", self.window.lifecycle_status.text())
        self.assertIn("NO WALLET LOADED", self.window.authority_status.text())

    def test_cancellation_ignores_late_result_and_keeps_ui_responsive(self):
        entered, release = Event(), Event()
        def slow(cancelled):
            entered.set()
            release.wait(3)
            return inspect_local_readiness(lambda: False)
        self.selected()
        with patch("wam_privacy_wallet.gui.regtest_worker.inspect_local_readiness", side_effect=slow):
            self.window.inspect_button.click()
            self.assertTrue(entered.wait(2))
            self.window.cancel_button.click()
            self.assertEqual(self.window.controller.lifecycle.state.phase, "CANCELLED")
            self.window.navigation.setCurrentRow(8)
            self.assertEqual(self.window.pages.currentIndex(), 8)
            self.assertFalse(self.window.inspect_button.isEnabled())
            release.set()
            self.drain(lambda: not self.window.controller.busy)
        self.assertEqual(self.window.controller.lifecycle.state.phase, "CANCELLED")
        self.assertTrue(self.window.inspect_button.isEnabled())

    def test_backend_error_redacted_and_retry_uses_real_policy(self):
        self.selected()
        with patch("wam_privacy_wallet.gui.regtest_worker.inspect_local_readiness", side_effect=RuntimeError("PRIVATE_PASSWORD_OR_PATH")):
            self.window.inspect_button.click()
            self.drain(lambda: not self.window.controller.busy)
        self.assertEqual(self.window.controller.lifecycle.state.failure, "APP_REGTEST_WORK_DENIED")
        self.assertNotIn("PRIVATE", self.window.lifecycle_status.text())
        self.window.inspect_button.click()
        self.drain(lambda: not self.window.controller.busy)
        self.assertEqual(self.window.controller.lifecycle.state.phase, "BLOCKED")

    def test_close_waits_cooperatively_without_terminating_worker(self):
        entered, release = Event(), Event()
        def slow(cancelled):
            entered.set()
            release.wait(3)
            return inspect_local_readiness(lambda: False)
        self.selected()
        with patch("wam_privacy_wallet.gui.regtest_worker.inspect_local_readiness", side_effect=slow):
            self.window.inspect_button.click()
            self.assertTrue(entered.wait(2))
            self.assertFalse(self.window.controller.shutdown(wait_ms=0))
            self.assertEqual(self.window.controller.lifecycle.state.phase, "CLOSED")
            release.set()
            self.assertTrue(self.window.controller.shutdown(wait_ms=5000))
            self.drain(lambda: not self.window.controller.busy)
        self.assertEqual(self.window.controller.lifecycle.state.phase, "CLOSED")

    def test_busy_worker_cannot_start_second_job(self):
        self.selected()
        self.window.controller.inspect(consent=True)
        with self.assertRaisesRegex(RegtestLifecycleError, "^APP_REGTEST_WORKER_BUSY$"):
            self.window.controller.inspect(consent=True)
        self.drain(lambda: not self.window.controller.busy)

    def test_denied_consent_does_not_create_worker_or_call_policy(self):
        self.window.mode_button.click()
        with patch("wam_privacy_wallet.gui.regtest_worker.inspect_local_readiness") as backend:
            with self.assertRaises(RegtestLifecycleError):
                self.window.controller.inspect(consent=False)
            backend.assert_not_called()
        self.assertFalse(self.window.controller.busy)

    def test_shutdown_input_denied(self):
        for value in (True, -1, 5001, "0"):
            with self.assertRaises(RegtestLifecycleError):
                self.window.controller.shutdown(wait_ms=value)

    def node_inputs_ready(self):
        self.selected()
        self.window.node_ack.setChecked(True)
        for key, value in (("a_user", "disposable_a"), ("b_user", "disposable_b"),
                           ("a_password", "disposable-a-secret"),
                           ("b_password", "disposable-b-secret")):
            self.window.node_inputs[key].setText(value)

    def test_two_node_gui_opt_in_and_no_secret_display(self):
        self.assertFalse(self.window.node_probe_button.isEnabled())
        self.node_inputs_ready()
        self.assertTrue(self.window.node_probe_button.isEnabled())
        with patch("wam_privacy_wallet.gui.regtest_worker.inspect_existing_two_nodes",
                   return_value=LiveNodeGuiEvidence(12)) as probe:
            self.window.node_probe_button.click()
            self.drain(lambda: not self.window.controller.busy)
            probe.assert_called_once()
        self.assertIn("reported tip 12", self.window.node_probe_status.text())
        self.assertIn("NO VERIFIED CORE", self.window.node_probe_status.text())
        self.assertNotIn("disposable", self.window.node_probe_status.text())
        self.assertEqual(self.window.node_inputs["a_password"].text(), "")
        self.assertEqual(self.window.node_inputs["b_password"].text(), "")
        self.assertFalse(self.window.controller.lifecycle.state.wallet_operational)
        self.assertFalse(self.window.node_probe_button.isEnabled())

    def test_two_node_cancel_ignores_late_rpc_evidence(self):
        entered, release = Event(), Event()
        def slow_probe(**kwargs):
            entered.set()
            release.wait(3)
            return LiveNodeGuiEvidence(12)
        self.node_inputs_ready()
        with patch("wam_privacy_wallet.gui.regtest_worker.inspect_existing_two_nodes",
                   side_effect=slow_probe):
            self.window.node_probe_button.click()
            self.assertTrue(entered.wait(2))
            self.window.cancel_button.click()
            release.set()
            self.drain(lambda: not self.window.controller.busy)
        self.assertEqual(self.window.node_probe_status.text(),
                         "NO NODE CONNECTION INSPECTION")

    def test_node_probe_refuses_invalid_ports_and_credentials_before_network(self):
        self.node_inputs_ready()
        self.window.node_ports["b_rpc"].setValue(29554)
        self.assertFalse(self.window.node_probe_button.isEnabled())
        self.window.node_ports["b_rpc"].setValue(29556)
        self.window.node_inputs["b_password"].clear()
        self.assertFalse(self.window.node_probe_button.isEnabled())
        self.window.node_inputs["b_password"].setText("disposable-b")
        self.assertTrue(self.window.node_probe_button.isEnabled())
        self.window.node_ack.setChecked(False)
        self.assertFalse(self.window.node_probe_button.isEnabled())

    def test_native_scanner_has_no_automatic_activation(self):
        self.selected()
        self.window.node_ack.setChecked(True)
        self.assertFalse(self.window.scan_button.isEnabled())
        with patch("wam_privacy_wallet.gui.regtest_worker.run_existing_two_node_scan") as backend:
            self.window.navigation.setCurrentRow(1)
            backend.assert_not_called()

    def test_native_scanner_worker_cancellation_suppresses_late_result(self):
        if sys.platform != "linux":
            self.assertFalse(self.window.scan_button.isEnabled())
            return
        from threading import Event as ThreadEvent
        entered, release = ThreadEvent(), ThreadEvent()
        self.node_inputs_ready()
        for key, value in (("source", str(Path.cwd().resolve())),
                           ("private", str(Path.cwd().resolve())),
                           ("passphrase", "disposable-ONLY-password")):
            self.window.scan_inputs[key].setText(value)
        self.assertTrue(self.window.scan_button.isEnabled())
        def slow(**kwargs):
            entered.set()
            release.wait(3)
            return QtNativeScanEvidence(12, True, 1, 1, 1)
        with patch("wam_privacy_wallet.gui.regtest_worker.run_existing_two_node_scan", side_effect=slow):
            self.window.scan_button.click()
            self.assertTrue(entered.wait(2))
            self.window.cancel_button.click()
            release.set()
            self.drain(lambda: not self.window.controller.busy)
        self.assertEqual(self.window.scan_review_status.text(), "NO WSP-1 SCAN REVIEW")

    def test_native_scanner_ui_scalar_evidence_never_exposes_amount(self):
        if sys.platform != "linux":
            return
        self.node_inputs_ready()
        for key, value in (("source", str(Path.cwd().resolve())),
                           ("private", str(Path.cwd().resolve())),
                           ("passphrase", "disposable-ONLY-password")):
            self.window.scan_inputs[key].setText(value)
        with patch("wam_privacy_wallet.gui.regtest_worker.run_existing_two_node_scan",
                   return_value=QtNativeScanEvidence(12, True, 1, 1, 3)):
            self.window.scan_button.click()
            self.drain(lambda: not self.window.controller.busy)
        self.assertIn("observed UTXOs 3 UNQUALIFIED", self.window.scan_review_status.text())
        self.assertIn("NO VERIFIED CORE", self.window.scan_review_status.text())
        self.assertNotIn("disposable", self.window.scan_review_status.text())
        self.assertEqual(self.window.scan_inputs["passphrase"].text(), "")
        self.assertFalse(self.window.controller.lifecycle.state.wallet_operational)

    def test_startup_and_inspection_do_not_connect_or_launch_core(self):
        self.selected()
        with patch("socket.socket") as network, patch("subprocess.Popen") as process:
            self.window.inspect_button.click()
            self.drain(lambda: not self.window.controller.busy)
            network.assert_not_called()
            process.assert_not_called()
