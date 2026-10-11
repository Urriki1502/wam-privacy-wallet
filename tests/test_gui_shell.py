"""Headless GUI smoke tests; no node, key material or wallet dependencies."""

import os
import unittest
import json
from pathlib import Path

from wam_privacy_wallet.application.privacy_readiness import (
    PrivacyResearchSnapshot, research_readiness,
)

from wam_privacy_wallet.application.node_status import NodeOverview, node_overview
from wam_privacy_wallet.node.attestation import ChainIdentity, WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.core_profile import VerifiedCoreProfile
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint

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


    def test_node_diagnostic_starts_without_a_node_or_snapshot(self) -> None:
        self.assertEqual(self.window.node_diagnostic_status.text(), "NO DIAGNOSTIC SNAPSHOT · NO RPC")
        self.assertIn("NOT A CONNECTION", self.window.node_diagnostic_notice.text())
        self.assertEqual(self.window.node_status.text(), "DISCONNECTED · NO RPC")

    def test_explicit_immutable_snapshot_is_visible_only_as_unverified(self) -> None:
        snapshot = NodeOverview("regtest", 42, "READ_ONLY_SNAPSHOT", "EXPERIMENTAL_NO_REAL_FUNDS")
        self.window.present_offline_node_snapshot(snapshot)
        self.window.navigation.setCurrentRow(4)
        self.assertEqual(self.window.current_page_title, "Node")
        self.assertIn("regtest height 42", self.window.node_diagnostic_status.text())
        self.assertIn("UNVERIFIED", self.window.node_diagnostic_status.text())
        self.assertIn("NOT A NODE CONNECTION", self.window.node_diagnostic_notice.text())
        self.assertEqual(self.window.node_status.text(), "DISCONNECTED · NO RPC")

    def test_diagnostic_reset_clears_preview_without_node_connections(self) -> None:
        snapshot = NodeOverview("regtest", 15, "READ_ONLY_SNAPSHOT", "EXPERIMENTAL_NO_REAL_FUNDS")
        self.window.present_offline_node_snapshot(snapshot)
        self.window.clear_offline_node_snapshot()
        self.assertEqual(self.window.node_diagnostic_status.text(), "NO DIAGNOSTIC SNAPSHOT · NO RPC")
        self.assertIn("NOT A CONNECTION", self.window.node_diagnostic_notice.text())
        self.assertEqual(self.window.node_status.text(), "DISCONNECTED · NO RPC")

    def test_untrusted_types_and_subclasses_are_rejected(self) -> None:
        class FakeOverview(NodeOverview):
            pass

        valid = FakeOverview("regtest", 1, "READ_ONLY_SNAPSHOT", "EXPERIMENTAL_NO_REAL_FUNDS")
        for candidate in (None, {}, [], True, 10, "regtest", object(), valid):
            with self.subTest(kind=type(candidate).__name__):
                with self.assertRaisesRegex(ValueError, "^APP_GUI_DIAGNOSTIC_REJECTED$"):
                    self.window.present_offline_node_snapshot(candidate)

    def test_forged_fields_are_rejected_even_in_exact_snapshot_type(self) -> None:
        good = ("regtest", 10, "READ_ONLY_SNAPSHOT", "EXPERIMENTAL_NO_REAL_FUNDS")
        malformed = (
            ("mainnet", *good[1:]),
            ("regtest", True, *good[2:]),
            ("regtest", -1, *good[2:]),
            ("regtest", 100_000_001, *good[2:]),
            ("regtest", "10", *good[2:]),
            (*good[:2], "CAN_SIGN", good[3]),
            (*good[:3], "READY_FOR_FUNDS"),
        )
        for item in malformed:
            with self.subTest(value=item):
                with self.assertRaisesRegex(ValueError, "^APP_GUI_DIAGNOSTIC_REJECTED$"):
                    self.window.present_offline_node_snapshot(NodeOverview(*item))

    def test_rejected_update_leaves_existing_snapshot_display_unchanged(self) -> None:
        self.window.present_offline_node_snapshot(
            NodeOverview("regtest", 7, "READ_ONLY_SNAPSHOT", "EXPERIMENTAL_NO_REAL_FUNDS")
        )
        before = self.window.node_diagnostic_status.text()
        with self.assertRaisesRegex(ValueError, "^APP_GUI_DIAGNOSTIC_REJECTED$"):
            self.window.present_offline_node_snapshot({"height": 88, "password": "DO_NOT_DISPLAY"})
        self.assertEqual(self.window.node_diagnostic_status.text(), before)
        self.assertNotIn("DO_NOT_DISPLAY", self.window.node_diagnostic_notice.text())

    def test_offline_projection_does_not_store_snapshot_or_enable_actions(self) -> None:
        snapshot = NodeOverview("regtest", 5, "READ_ONLY_SNAPSHOT", "EXPERIMENTAL_NO_REAL_FUNDS")
        self.window.present_offline_node_snapshot(snapshot)
        self.assertFalse(any(value is snapshot for value in vars(self.window).values()))
        self.assertEqual(self.window.findChildren(QPushButton), [])
        self.assertNotIn("29554", self.window.node_diagnostic_status.text())
        self.assertNotIn("127.0.0.1", self.window.node_diagnostic_status.text())

    def test_existing_application_projection_composes_with_synthetic_fixture(self) -> None:
        # No network transport, Core binary, scanner or signer is constructed.
        endpoint = LocalRegtestEndpoint("127.0.0.1", 29554)
        identity = ChainIdentity(endpoint, WAM_REGTEST_GENESIS, 6, "a" * 64)
        mock_profile = VerifiedCoreProfile(identity=identity, headers=7, pruned=False)
        projection = node_overview(mock_profile)
        self.window.present_offline_node_snapshot(projection)
        self.assertIn("regtest height 6", self.window.node_diagnostic_status.text())
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")
        self.assertEqual(self.window.node_status.text(), "DISCONNECTED · NO RPC")


    def test_privacy_page_starts_with_all_research_capabilities_disabled(self) -> None:
        self.assertEqual(self.window.privacy_readiness_status.text(), "RESEARCH INVENTORY · NOT LOADED")
        self.assertIn("NO ACTIVE INTEGRATION", self.window.privacy_readiness_notice.text())
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_canonical_wsp_and_security_evidence_is_displayed_as_review_only(self) -> None:
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / "compat/reuse_candidates.json").read_text(encoding="utf-8"))
        ledger = json.loads((root / "compat/g0_security_gate_ledger.json").read_text(encoding="utf-8"))
        snapshot = research_readiness(manifest, ledger)
        self.window.present_offline_privacy_readiness(snapshot)
        self.window.navigation.setCurrentRow(3)
        self.assertEqual(self.window.current_page_title, "Privacy")
        self.assertIn("0 ACTIVE WALLET CAPABILITIES", self.window.privacy_readiness_status.text())
        self.assertIn("UNATTESTED", self.window.privacy_readiness_notice.text())
        self.assertIn("SCANNER / SIGNER / SEND BLOCKED", self.window.privacy_readiness_notice.text())
        self.assertEqual(self.window.findChildren(QPushButton), [])
        self.assertEqual(self.window.node_status.text(), "DISCONNECTED · NO RPC")
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")

    def test_privacy_snapshot_forgery_is_rejected_and_reset_clears_display(self) -> None:
        good = PrivacyResearchSnapshot(
            "RESEARCH_ONLY", "PIN_RECORDED_UNATTESTED",
            "MODEL_ONLY", "MODEL_ONLY", "MODEL_ONLY", "NOT_INTEGRATED",
            "BLOCKED", "BLOCKED", "BLOCKED",
        )
        self.window.present_offline_privacy_readiness(good)
        before = self.window.privacy_readiness_status.text()
        for invalid in (
            None, {}, {"secret": "DO_NOT_DISPLAY"}, True,
            PrivacyResearchSnapshot(
                "APPROVED", "PIN_RECORDED_UNATTESTED",
                "MODEL_ONLY", "MODEL_ONLY", "MODEL_ONLY", "NOT_INTEGRATED",
                "BLOCKED", "BLOCKED", "BLOCKED",
            ),
            PrivacyResearchSnapshot(
                "RESEARCH_ONLY", "PIN_RECORDED_UNATTESTED",
                "MODEL_ONLY", "MODEL_ONLY", "MODEL_ONLY", "NOT_INTEGRATED",
                "BLOCKED", "READY", "BLOCKED",
            ),
        ):
            with self.subTest(kind=type(invalid).__name__):
                with self.assertRaisesRegex(ValueError, "^APP_GUI_PRIVACY_GATE_REJECTED$"):
                    self.window.present_offline_privacy_readiness(invalid)
                self.assertEqual(self.window.privacy_readiness_status.text(), before)
        self.assertNotIn("DO_NOT_DISPLAY", self.window.privacy_readiness_notice.text())
        self.window.clear_offline_privacy_readiness()
        self.assertEqual(self.window.privacy_readiness_status.text(), "RESEARCH INVENTORY · NOT LOADED")


if __name__ == "__main__":
    unittest.main()
