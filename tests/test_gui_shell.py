"""Headless GUI smoke tests; no node, key material or wallet dependencies."""

import os
import unittest
import json
from pathlib import Path

from wam_privacy_wallet.application.privacy_readiness import (
    PrivacyResearchSnapshot, research_readiness,
)
from wam_privacy_wallet.application.policy_evidence import (
    SyntheticPolicyReport, inspect_synthetic_policy_evidence,
)
from wam_privacy_wallet.application import receive_vector as rv

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


    def test_privacy_model_panel_starts_disabled_without_evidence(self) -> None:
        self.assertEqual(self.window.privacy_policy_status.text(), "NO SYNTHETIC POLICY EVIDENCE")
        self.assertIn("NOT AUTHORIZED", self.window.privacy_policy_notice.text())
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_synthetic_network_and_payjoin_models_display_only_as_untrusted(self) -> None:
        network = {
            "schema": 1, "scan_route": "local", "broadcast_route": "tor",
            "broadcast_encrypted": False, "async_payjoin": False,
            "payjoin_route": None, "direct_fallback_present": False, "result": "PASS",
        }
        payjoin = {
            "schema": 1, "receiver_inputs_added": 1, "output_substitution": False,
            "sender_fee_contribution_used": False, "absolute_fee_increased": True,
            "result": "PASS",
        }
        report = inspect_synthetic_policy_evidence(network, payjoin)
        self.window.present_offline_policy_report(report)
        self.window.navigation.setCurrentRow(3)
        self.assertIn("UNTRUSTED", self.window.privacy_policy_status.text())
        self.assertIn("NOT AUTHORIZED", self.window.privacy_policy_status.text())
        self.assertIn("NO RPC / SIGN / SEND", self.window.privacy_policy_notice.text())
        self.assertEqual(self.window.node_status.text(), "DISCONNECTED · NO RPC")
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_forged_synthetic_policy_report_and_subclass_denied_without_display(self) -> None:
        accepted = SyntheticPolicyReport(
            "PIN_RECORDED_UNATTESTED", "MODEL_PASS_UNTRUSTED",
            "MODEL_PASS_UNTRUSTED", "MODEL_ONLY_NO_AUTHORITY",
            "BLOCKED", "BLOCKED", "BLOCKED",
        )
        class Forged(SyntheticPolicyReport):
            pass
        invalid_values = (
            None, {"secret": "DO_NOT_DISPLAY"},
            Forged(*tuple(getattr(accepted, name) for name in
                ("provenance", "network", "payjoin", "authority", "scan", "sign", "send"))),
            SyntheticPolicyReport(
                "PIN_RECORDED_UNATTESTED", "MODEL_PASS_UNTRUSTED",
                "MODEL_PASS_UNTRUSTED", "CAN_SIGN", "BLOCKED", "BLOCKED", "BLOCKED"),
            SyntheticPolicyReport(
                "PIN_RECORDED_UNATTESTED", "MODEL_PASS_UNTRUSTED",
                "MODEL_PASS_UNTRUSTED", "MODEL_ONLY_NO_AUTHORITY", "BLOCKED", "READY", "BLOCKED"),
            SyntheticPolicyReport(
                "PIN_RECORDED_UNATTESTED", "MODEL_PASS_UNTRUSTED",
                "MODEL_PASS_UNTRUSTED", "MODEL_ONLY_NO_AUTHORITY", "BLOCKED", True, "BLOCKED"),
        )
        self.window.present_offline_policy_report(accepted)
        before = self.window.privacy_policy_status.text()
        for item in invalid_values:
            with self.subTest(kind=type(item).__name__):
                with self.assertRaisesRegex(ValueError, "^APP_GUI_SYNTHETIC_POLICY_DENIED$"):
                    self.window.present_offline_policy_report(item)
                self.assertEqual(self.window.privacy_policy_status.text(), before)
        self.assertNotIn("DO_NOT_DISPLAY", self.window.privacy_policy_notice.text())

    def test_policy_report_reset_never_affects_other_diagnostics(self) -> None:
        report = SyntheticPolicyReport(
            "PIN_RECORDED_UNATTESTED", "MODEL_PASS_UNTRUSTED",
            "MODEL_PASS_UNTRUSTED", "MODEL_ONLY_NO_AUTHORITY", "BLOCKED", "BLOCKED", "BLOCKED",
        )
        self.window.present_offline_policy_report(report)
        self.assertFalse(any(value is report for value in vars(self.window).values()))
        self.window.clear_offline_policy_report()
        self.assertEqual(self.window.privacy_policy_status.text(), "NO SYNTHETIC POLICY EVIDENCE")
        self.assertIn("NOT AUTHORIZED", self.window.privacy_policy_notice.text())
        self.assertEqual(self.window.privacy_readiness_status.text(), "RESEARCH INVENTORY · NOT LOADED")
        self.assertEqual(self.window.node_status.text(), "DISCONNECTED · NO RPC")


    def test_explicit_pinned_research_demo_renders_only_untrusted_model(self) -> None:
        self.window.run_fixed_offline_policy_demo()
        self.window.navigation.setCurrentRow(3)
        self.assertIn("UNTRUSTED", self.window.privacy_policy_status.text())
        self.assertIn("NOT AUTHORIZED", self.window.privacy_policy_status.text())
        self.assertIn("NO RPC / SIGN / SEND", self.window.privacy_policy_notice.text())
        self.assertEqual(self.window.node_status.text(), "DISCONNECTED · NO RPC")
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_rejected_demo_clears_previous_evidence_without_secret_leak(self) -> None:
        from unittest.mock import patch
        from wam_privacy_wallet.application.synthetic_policy_demo import SyntheticDemoError
        self.window.run_fixed_offline_policy_demo()
        with patch(
            "wam_privacy_wallet.application.synthetic_policy_demo.run_fixed_synthetic_privacy_demo",
            side_effect=SyntheticDemoError("PRIVATE_SECRET"),
        ):
            with self.assertRaisesRegex(
                ValueError, "^APP_GUI_SYNTHETIC_MODEL_DENIED$"
            ) as failed:
                self.window.run_fixed_offline_policy_demo()
            self.assertIsNone(failed.exception.__cause__)
        self.assertEqual(self.window.privacy_policy_status.text(), "NO SYNTHETIC POLICY EVIDENCE")
        self.assertNotIn("PRIVATE_SECRET", self.window.privacy_policy_notice.text())
        self.assertEqual(self.window.node_status.text(), "DISCONNECTED · NO RPC")



    def test_receive_page_starts_without_any_address_or_wallet_controls(self) -> None:
        self.window.navigation.setCurrentRow(1)
        self.assertEqual(self.window.current_page_title, "Receive")
        self.assertEqual(
            self.window.receive_vector_status.text(),
            "NO PUBLIC SAMPLE · NO ADDRESS GENERATED",
        )
        self.assertIn("NOT A RECEIVING ADDRESS", self.window.receive_vector_notice.text())
        self.assertEqual(self.window.findChildren(QPushButton), [])
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")

    def test_fixed_public_vector_preview_renders_fingerprint_only(self) -> None:
        preview = rv.inspect_pinned_public_vector()
        self.window.present_public_receive_vector(preview)
        self.window.navigation.setCurrentRow(1)
        self.assertIn(rv._FIXED_FINGERPRINT, self.window.receive_vector_status.text())
        self.assertIn("SYNTHETIC REGTEST", self.window.receive_vector_status.text())
        self.assertNotIn(rv._PUBLIC_ONLY_VECTOR, self.window.receive_vector_status.text())
        self.assertNotIn(rv._PUBLIC_ONLY_VECTOR, self.window.receive_vector_notice.text())
        self.assertIn("NOT A RECEIVING ADDRESS", self.window.receive_vector_notice.text())
        self.assertEqual(self.window.node_status.text(), "DISCONNECTED · NO RPC")
        self.assertEqual(self.window.findChildren(QPushButton), [])
        self.assertFalse(any(v is preview for v in vars(self.window).values()))

    def test_explicit_receive_demo_is_non_authorizing_and_resettable(self) -> None:
        self.window.run_fixed_public_receive_demo()
        self.assertIn("PUBLIC FINGERPRINT", self.window.receive_vector_status.text())
        self.assertIn("NO SCANNER / SIGNER", self.window.receive_vector_notice.text())
        self.assertEqual(self.window.node_status.text(), "DISCONNECTED · NO RPC")
        self.window.clear_public_receive_vector()
        self.assertEqual(
            self.window.receive_vector_status.text(),
            "NO PUBLIC SAMPLE · NO ADDRESS GENERATED",
        )
        self.assertEqual(self.window.privacy_policy_status.text(), "NO SYNTHETIC POLICY EVIDENCE")

    def test_forged_public_preview_cannot_enable_receive_or_leak_user_input(self) -> None:
        correct = rv.inspect_pinned_public_vector()
        class Forged(rv.ReceiveVectorPreview):
            pass
        self.window.present_public_receive_vector(correct)
        before = self.window.receive_vector_status.text()
        invalid = (
            None, True, {}, {"seed": "SHOULD_NOT_DISPLAY"},
            Forged(*tuple(getattr(correct, name) for name in
                ("profile", "network", "provenance", "sample", "fingerprint",
                 "receive", "scanner", "signer"))),
            rv.ReceiveVectorPreview("WSP-1", "mainnet",
                "PIN_RECORDED_UNATTESTED", "PUBLIC_SYNTHETIC_FIXTURE",
                correct.fingerprint, "BLOCKED", "BLOCKED", "BLOCKED"),
            rv.ReceiveVectorPreview("WSP-1", "regtest",
                "PIN_RECORDED_UNATTESTED", "PUBLIC_SYNTHETIC_FIXTURE",
                "untrusted-fingerprint", "BLOCKED", "BLOCKED", "BLOCKED"),
            rv.ReceiveVectorPreview("WSP-1", "regtest",
                "PIN_RECORDED_UNATTESTED", "PUBLIC_SYNTHETIC_FIXTURE",
                correct.fingerprint, "READY", "BLOCKED", "BLOCKED"),
        )
        for value in invalid:
            with self.subTest(kind=type(value).__name__):
                with self.assertRaisesRegex(
                    ValueError, "^APP_GUI_RECEIVE_VECTOR_DENIED$"
                ):
                    self.window.present_public_receive_vector(value)
                self.assertEqual(self.window.receive_vector_status.text(), before)
        self.assertNotIn("SHOULD_NOT_DISPLAY", self.window.receive_vector_notice.text())
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_corrupt_codec_blocks_explicit_demo_and_clears_stale_preview(self) -> None:
        from pathlib import Path
        import tempfile
        from unittest.mock import patch

        self.window.run_fixed_public_receive_demo()
        with tempfile.TemporaryDirectory(prefix="receive-codec-test-") as tmp:
            corrupt = Path(tmp) / "codec.py"
            corrupt.write_text("raise RuntimeError('secret')", encoding="utf-8")
            with patch.object(rv, "_CODEC_FILE", corrupt):
                with self.assertRaisesRegex(
                    ValueError, "^APP_GUI_RECEIVE_VECTOR_DENIED$"
                ) as failure:
                    self.window.run_fixed_public_receive_demo()
                self.assertIsNone(failure.exception.__cause__)
        self.assertEqual(
            self.window.receive_vector_status.text(),
            "NO PUBLIC SAMPLE · NO ADDRESS GENERATED",
        )
        self.assertNotIn("secret", self.window.receive_vector_notice.text())
        self.assertEqual(self.window.node_status.text(), "DISCONNECTED · NO RPC")


    def test_lifecycle_valid_then_invalid_clears_all_panels(self) -> None:
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        self.window.replace_offline_presentation(0, node=NodeOverview(
            "regtest", 42, "READ_ONLY_SNAPSHOT", "EXPERIMENTAL_NO_REAL_FUNDS"))
        self.assertIn("UNVERIFIED", self.window.node_diagnostic_status.text())
        with self.assertRaises(OfflineLifecycleError):
            self.window.replace_offline_presentation(1, node={"private": "DO_NOT_ECHO"})
        self.assertEqual(self.window.node_diagnostic_status.text(), "NO DIAGNOSTIC SNAPSHOT · NO RPC")
        self.assertEqual(self.window.offline_presentation_state.transition, "REJECTED")
        self.assertEqual(self.window.node_status.text(), "DISCONNECTED · NO RPC")

    def test_lifecycle_stale_revision_clears_receive_and_node(self) -> None:
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        self.window.replace_offline_presentation(0, node=NodeOverview(
            "regtest", 42, "READ_ONLY_SNAPSHOT", "EXPERIMENTAL_NO_REAL_FUNDS"),
            receive=rv.inspect_pinned_public_vector())
        self.assertIn("PUBLIC FINGERPRINT", self.window.receive_vector_status.text())
        with self.assertRaises(OfflineLifecycleError):
            self.window.replace_offline_presentation(0)
        self.assertEqual(self.window.receive_vector_status.text(),
                         "NO PUBLIC SAMPLE · NO ADDRESS GENERATED")
        self.assertEqual(self.window.node_diagnostic_status.text(),
                         "NO DIAGNOSTIC SNAPSHOT · NO RPC")

    def test_lifecycle_reset_invalidates_revision_and_all_panels(self) -> None:
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        self.window.replace_offline_presentation(0, receive=rv.inspect_pinned_public_vector())
        self.window.clear_offline_presentation()
        self.assertEqual(self.window.offline_presentation_state.transition, "CLEARED")
        self.assertEqual(self.window.receive_vector_status.text(),
                         "NO PUBLIC SAMPLE · NO ADDRESS GENERATED")
        with self.assertRaises(OfflineLifecycleError):
            self.window.replace_offline_presentation(1)

    def test_lifecycle_replacement_does_not_retain_omitted_evidence(self) -> None:
        self.window.replace_offline_presentation(0, receive=rv.inspect_pinned_public_vector())
        self.window.replace_offline_presentation(1)
        self.assertEqual(self.window.offline_presentation_state.receive, "ABSENT")
        self.assertEqual(self.window.receive_vector_status.text(),
                         "NO PUBLIC SAMPLE · NO ADDRESS GENERATED")
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")
        self.assertEqual(self.window.findChildren(QPushButton), [])


    def test_legacy_presenter_replaces_managed_snapshot_atomically(self) -> None:
        # Legacy direct calls now run through the same single-writer revision.
        from wam_privacy_wallet.application.node_status import NodeOverview
        from wam_privacy_wallet.application.policy_evidence import (
            SyntheticPolicyReport,
        )
        self.window.replace_offline_presentation(
            0, node=NodeOverview(
                "regtest", 10, "READ_ONLY_SNAPSHOT",
                "EXPERIMENTAL_NO_REAL_FUNDS",
            ), receive=rv.inspect_pinned_public_vector()
        )
        self.assertEqual(self.window.offline_presentation_state.revision, 1)
        self.window.present_offline_policy_report(SyntheticPolicyReport(
            "PIN_RECORDED_UNATTESTED", "MODEL_PASS_UNTRUSTED",
            "MODEL_PASS_UNTRUSTED", "MODEL_ONLY_NO_AUTHORITY",
            "BLOCKED", "BLOCKED", "BLOCKED",
        ))
        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.policy), (2, "MODEL_ONLY"))
        self.assertEqual((state.node, state.receive), ("ABSENT", "ABSENT"))
        self.assertEqual(self.window.node_diagnostic_status.text(),
                         "NO DIAGNOSTIC SNAPSHOT · NO RPC")
        self.assertEqual(self.window.receive_vector_status.text(),
                         "NO PUBLIC SAMPLE · NO ADDRESS GENERATED")

    def test_legacy_clear_invalidates_all_panels_and_prior_revision(self) -> None:
        from wam_privacy_wallet.application.presentation_lifecycle import (
            OfflineLifecycleError,
        )
        self.window.replace_offline_presentation(
            0, receive=rv.inspect_pinned_public_vector()
        )
        self.window.clear_public_receive_vector()
        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.transition), (2, "CLEARED"))
        self.assertEqual((state.node, state.receive), ("ABSENT", "ABSENT"))
        with self.assertRaises(OfflineLifecycleError):
            self.window.replace_offline_presentation(1)
        self.assertEqual(self.window.offline_presentation_state.transition,
                         "REJECTED")

    def test_legacy_invalid_input_does_not_mutate_accepted_state(self) -> None:
        self.window.present_public_receive_vector(
            rv.inspect_pinned_public_vector()
        )
        before = self.window.offline_presentation_state
        self.assertEqual(before.receive, "PUBLIC_FIXTURE")
        with self.assertRaisesRegex(
            ValueError, "^APP_GUI_RECEIVE_VECTOR_DENIED$"
        ):
            self.window.present_public_receive_vector(
                {"secret": "MUST_NOT_LOG"}
            )
        self.assertEqual(self.window.offline_presentation_state, before)
        self.assertIn("PUBLIC FINGERPRINT",
                      self.window.receive_vector_status.text())
        self.assertNotIn("MUST_NOT_LOG",
                         self.window.receive_vector_notice.text())

    def test_legacy_demo_routes_through_controller_single_writer(self) -> None:
        self.window.run_fixed_public_receive_demo()
        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.receive), (1, "PUBLIC_FIXTURE"))
        self.assertEqual(state.authority, "BLOCKED")
        self.window.run_fixed_offline_policy_demo()
        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.policy), (2, "MODEL_ONLY"))
        self.assertEqual(state.receive, "ABSENT")
        self.assertEqual(self.window.receive_vector_status.text(),
                         "NO PUBLIC SAMPLE · NO ADDRESS GENERATED")
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")

    def test_lifecycle_clear_failure_invalidates_revision_and_other_panels(self) -> None:
        # A Qt setter may fail while clearing OLD content, before new content
        # is rendered. The controller must not retain an accepted revision.
        from unittest.mock import patch
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError

        self.window.replace_offline_presentation(
            0, receive=rv.inspect_pinned_public_vector()
        )
        self.assertIn("PUBLIC FINGERPRINT", self.window.receive_vector_status.text())
        original = MainWindow.clear_offline_node_snapshot
        calls = []

        def fail_once(window):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("SECRET_QT_CLEAR_DETAIL")
            return original(window)

        with patch.object(MainWindow, "clear_offline_node_snapshot",
                          autospec=True, side_effect=fail_once):
            with self.assertRaisesRegex(
                OfflineLifecycleError, "^APP_OFFLINE_RENDER_DENIED$"
            ) as failure:
                self.window.replace_offline_presentation(
                    1, node=NodeOverview(
                        "regtest", 7, "READ_ONLY_SNAPSHOT",
                        "EXPERIMENTAL_NO_REAL_FUNDS",
                    )
                )
            self.assertIsNone(failure.exception.__cause__)

        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.transition), (3, "CLEARED"))
        self.assertEqual((state.node, state.receive), ("ABSENT", "ABSENT"))
        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(self.window.node_diagnostic_status.text(),
                         "NO DIAGNOSTIC SNAPSHOT · NO RPC")
        self.assertEqual(self.window.receive_vector_status.text(),
                         "NO PUBLIC SAMPLE · NO ADDRESS GENERATED")
        with self.assertRaises(OfflineLifecycleError):
            self.window.replace_offline_presentation(1)
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")

    def test_reset_clear_failure_attempts_all_panels_and_stays_blocked(self) -> None:
        # An error in one widget cannot prevent other panel resets; the
        # user-visible exception contains only the stable error code.
        from unittest.mock import patch
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError

        self.window.replace_offline_presentation(
            0, receive=rv.inspect_pinned_public_vector()
        )
        with patch.object(MainWindow, "clear_offline_node_snapshot",
                          side_effect=RuntimeError("PRIVATE_QT_DETAIL")):
            with self.assertRaisesRegex(
                OfflineLifecycleError, "^APP_OFFLINE_RENDER_DENIED$"
            ) as failure:
                self.window.clear_offline_presentation()
            self.assertIsNone(failure.exception.__cause__)

        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.transition), (2, "CLEARED"))
        self.assertEqual((state.node, state.receive), ("ABSENT", "ABSENT"))
        self.assertEqual(self.window.receive_vector_status.text(),
                         "NO PUBLIC SAMPLE · NO ADDRESS GENERATED")
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_reentrant_clear_during_render_cannot_survive_swallowed_error(self) -> None:
        from unittest.mock import patch
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        original = MainWindow.present_offline_node_snapshot
        observed = []

        def reenter(window, snapshot):
            try:
                window.clear_offline_presentation()
            except OfflineLifecycleError as exc:
                observed.append(str(exc))
            else:
                observed.append("UNEXPECTEDLY_ACCEPTED")
            return original(window, snapshot)

        with patch.object(MainWindow, "present_offline_node_snapshot",
                          autospec=True, side_effect=reenter):
            with self.assertRaisesRegex(
                OfflineLifecycleError, "^APP_OFFLINE_RENDER_DENIED$"
            ) as exc:
                self.window.replace_offline_presentation(
                    0, node=NodeOverview("regtest", 4, "READ_ONLY_SNAPSHOT",
                                          "EXPERIMENTAL_NO_REAL_FUNDS")
                )
            self.assertIsNone(exc.exception.__cause__)
        self.assertEqual(observed, ["APP_OFFLINE_REENTRANT_DENIED"])
        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.transition, state.node),
                         (2, "CLEARED", "ABSENT"))
        self.assertEqual(self.window.node_diagnostic_status.text(),
                         "NO DIAGNOSTIC SNAPSHOT · NO RPC")
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")

    def test_reentrant_replace_during_clear_poisoned_even_when_callback_catches(self) -> None:
        from unittest.mock import patch
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        original = MainWindow.clear_offline_node_snapshot
        observed = []

        def reenter(window):
            if not observed:
                try:
                    window.replace_offline_presentation(
                        window.offline_presentation_state.revision,
                        node=NodeOverview("regtest", 99, "READ_ONLY_SNAPSHOT",
                                          "EXPERIMENTAL_NO_REAL_FUNDS")
                    )
                except OfflineLifecycleError as exc:
                    observed.append(str(exc))
                else:
                    observed.append("UNEXPECTEDLY_ACCEPTED")
            return original(window)

        with patch.object(MainWindow, "clear_offline_node_snapshot",
                          autospec=True, side_effect=reenter):
            with self.assertRaisesRegex(
                OfflineLifecycleError, "^APP_OFFLINE_RENDER_DENIED$"
            ):
                self.window.replace_offline_presentation(
                    0, node=NodeOverview("regtest", 1, "READ_ONLY_SNAPSHOT",
                                          "EXPERIMENTAL_NO_REAL_FUNDS")
                )
        self.assertEqual(observed, ["APP_OFFLINE_REENTRANT_DENIED"])
        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.transition, state.node),
                         (2, "CLEARED", "ABSENT"))
        self.assertEqual(self.window.node_diagnostic_status.text(),
                         "NO DIAGNOSTIC SNAPSHOT · NO RPC")

    def test_reentrant_replace_during_explicit_clear_stays_blocked_then_recovers(self) -> None:
        from unittest.mock import patch
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        self.window.present_public_receive_vector(rv.inspect_pinned_public_vector())
        original = MainWindow.clear_offline_node_snapshot
        observed = []

        def reenter(window):
            if not observed:
                try:
                    window.replace_offline_presentation(
                        window.offline_presentation_state.revision
                    )
                except OfflineLifecycleError as exc:
                    observed.append(str(exc))
                else:
                    observed.append("UNEXPECTEDLY_ACCEPTED")
            return original(window)

        with patch.object(MainWindow, "clear_offline_node_snapshot",
                          autospec=True, side_effect=reenter):
            with self.assertRaisesRegex(
                OfflineLifecycleError, "^APP_OFFLINE_RENDER_DENIED$"
            ):
                self.window.clear_offline_presentation()
        self.assertEqual(observed, ["APP_OFFLINE_REENTRANT_DENIED"])
        cleared = self.window.offline_presentation_state
        self.assertEqual((cleared.revision, cleared.transition, cleared.receive),
                         (2, "CLEARED", "ABSENT"))
        self.assertEqual(self.window.receive_vector_status.text(),
                         "NO PUBLIC SAMPLE · NO ADDRESS GENERATED")
        # Internal reentry poison must not persist into a later valid update.
        self.window.replace_offline_presentation(
            2, node=NodeOverview("regtest", 3, "READ_ONLY_SNAPSHOT",
                                  "EXPERIMENTAL_NO_REAL_FUNDS")
        )
        self.assertEqual(self.window.offline_presentation_state.revision, 3)
        self.assertEqual(self.window.offline_presentation_state.node, "UNVERIFIED")
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")

    def test_lifecycle_render_failure_clears_and_invalidates(self) -> None:
        # A renderer can fail *after* a validated state was committed.
        # That must never leave an accepted revision or stale panel visible.
        from unittest.mock import patch
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        self.window.replace_offline_presentation(
            0, receive=rv.inspect_pinned_public_vector()
        )
        self.assertIn("PUBLIC FINGERPRINT", self.window.receive_vector_status.text())
        with patch.object(MainWindow, "present_offline_node_snapshot",
                          side_effect=RuntimeError("PRIVATE_RENDER_DETAIL")):
            with self.assertRaisesRegex(
                OfflineLifecycleError, "^APP_OFFLINE_RENDER_DENIED$"
            ) as failure:
                self.window.replace_offline_presentation(
                    1, node=NodeOverview(
                        "regtest", 42, "READ_ONLY_SNAPSHOT",
                        "EXPERIMENTAL_NO_REAL_FUNDS",
                    ),
                )
            self.assertIsNone(failure.exception.__cause__)
        state = self.window.offline_presentation_state
        self.assertEqual((state.transition, state.revision), ("CLEARED", 3))
        self.assertEqual((state.node, state.receive), ("ABSENT", "ABSENT"))
        self.assertEqual(self.window.node_diagnostic_status.text(),
                         "NO DIAGNOSTIC SNAPSHOT · NO RPC")
        self.assertEqual(self.window.receive_vector_status.text(),
                         "NO PUBLIC SAMPLE · NO ADDRESS GENERATED")
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")
        self.assertNotIn("PRIVATE_RENDER_DETAIL", self.window.node_diagnostic_notice.text())
        self.assertEqual(self.window.findChildren(QPushButton), [])


if __name__ == "__main__":
    unittest.main()
