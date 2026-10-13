"""Actual Qt-thread/lifecycle tests. No operational node or fabricated wallet."""
import os
import time
import unittest
from threading import Event, get_ident
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication

from wam_privacy_wallet.application.regtest_lifecycle import inspect_local_readiness, RegtestLifecycleError
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

    def test_startup_and_inspection_do_not_connect_or_launch_core(self):
        self.selected()
        with patch("socket.socket") as network, patch("subprocess.Popen") as process:
            self.window.inspect_button.click()
            self.drain(lambda: not self.window.controller.busy)
            network.assert_not_called()
            process.assert_not_called()
