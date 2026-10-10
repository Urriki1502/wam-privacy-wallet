"""Headless GUI smoke tests; no node, key material or wallet dependencies."""

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton  # noqa: E402

from wam_privacy_wallet.gui import MainWindow  # noqa: E402


class GuiShellSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.window = MainWindow()

    def tearDown(self) -> None:
        self.window.close()

    def test_pages_and_navigation_are_consistent(self) -> None:
        self.assertEqual(
            self.window.page_names,
            ("Overview", "Receive", "Send", "Privacy", "Node", "Recovery"),
        )
        self.assertEqual(self.window.page_stack.count(), 6)
        for index, name in enumerate(self.window.page_names):
            with self.subTest(page=name):
                self.window.navigation.setCurrentRow(index)
                self.assertEqual(self.window.current_page_title, name)
                self.assertEqual(self.window.page_stack.currentIndex(), index)

    def test_offline_safety_notice_and_no_funds_state(self) -> None:
        self.assertIn("NO REAL FUNDS", self.window.experimental_banner.text())
        self.assertEqual(self.window.node_status.text(), "DISCONNECTED · NO RPC")
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")

    def test_no_payment_actions_are_exposed(self) -> None:
        self.assertEqual(self.window.findChildren(QPushButton), [])
        self.window.navigation.setCurrentRow(2)
        self.assertEqual(self.window.current_page_title, "Send")
        self.assertIn("EXPERIMENTAL", self.window.windowTitle().upper())

    def test_window_is_portable_qt_widget(self) -> None:
        self.assertEqual(self.window.objectName(), "wamPrivacyWalletWindow")
        self.assertGreaterEqual(self.window.minimumWidth(), 900)
        self.assertGreaterEqual(self.window.minimumHeight(), 600)


if __name__ == "__main__":
    unittest.main()
