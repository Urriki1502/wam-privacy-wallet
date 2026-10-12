"""Headless GUI smoke tests; no node, key material or wallet dependencies."""

import os
import unittest
from unittest.mock import patch
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
from wam_privacy_wallet.application.scanner_session_workflow import ScannerReadOnlyObservation
from wam_privacy_wallet.application.wsp_scan_coordinator import WspScanSessionSummary
from wam_privacy_wallet.node.attestation import ChainIdentity, WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.core_profile import VerifiedCoreProfile
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEvent  # noqa: E402
from PySide6.QtWidgets import QApplication, QPushButton  # noqa: E402

from wam_privacy_wallet.gui import MainWindow  # noqa: E402


class GuiShellSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.window = MainWindow()

    def tearDown(self) -> None:
        # Full-discovery keeps GUI and socket tests in one process. On macOS,
        # leaving Qt widgets to Python GC after GUI tests can delete shared
        # QObjects during a later non-GUI test (native exit 139). Dispose on
        # the creating GUI thread via DeferredDelete, not direct C++ deletion.
        self.window.close()
        self.window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        QCoreApplication.processEvents()

    def test_new_privacy_panels_start_empty_and_scroll_without_actions(self):
        from PySide6.QtWidgets import QScrollArea
        self.assertIsInstance(self.window.page_stack.widget(3),QScrollArea)
        self.assertEqual((self.window.offline_presentation_state.coin_policy,self.window.offline_presentation_state.disclosure,self.window.offline_presentation_state.assurance),("ABSENT",)*3)
        self.assertEqual(self.window.findChildren(QPushButton),[])

    def test_actual_normalized_coin_policy_reaches_readonly_gui(self):
        from wam_privacy_wallet.research_models.wallet_privacy.model import Coin,Intent
        self.window.review_coin_policy_inputs((Coin("01"*32,0,51000,"PRIVATE_CLUSTER"),),(Intent("PRIVATE_RECIPIENT",50000),),1000,scope="synthetic-regtest",consent=True)
        self.assertIn("inputs 1",self.window.coin_policy_review_status.text())
        self.assertIn("UNTRUSTED",self.window.coin_policy_review_status.text())
        self.assertIn("db3d2dca",self.window.coin_policy_review_notice.text())
        self.assertNotIn("PRIVATE",self.window.coin_policy_review_status.text())
        self.assertEqual(self.window.session_status.text(),"NO WALLET LOADED")

    def test_coin_policy_denied_consent_or_scope_clears_before_algorithm(self):
        from wam_privacy_wallet.application.coin_selection_review import CoinSelectionReview
        for changes in ({"consent":False},{"scope":"mainnet"}):
            self.window.present_coin_policy_review(CoinSelectionReview(1,1,False,()))
            with patch("wam_privacy_wallet.application.coin_selection_review._verify_source") as source:
                with self.assertRaisesRegex(ValueError,"^APP_GUI_COIN_POLICY_DENIED$"):
                    self.window.review_coin_policy_inputs((),(),1000,**(dict(scope="synthetic-regtest",consent=True)|changes))
                source.assert_not_called()
            self.assertEqual(self.window.offline_presentation_state.coin_policy,"ABSENT")

    def test_forged_coin_signing_or_warning_claim_clears_whole_gui(self):
        from wam_privacy_wallet.application.coin_selection_review import CoinSelectionReview
        value=CoinSelectionReview(1,1,False,());object.__setattr__(value,"signing_allowed",True)
        for receipt in (value,CoinSelectionReview(1,1,False,("CLUSTER_MERGE",))):
            with self.assertRaisesRegex(ValueError,"^APP_GUI_COIN_POLICY_DENIED$"):self.window.present_coin_policy_review(receipt)
            self.assertEqual(self.window.offline_presentation_state.coin_policy,"ABSENT")

    def test_public_disclosure_dto_is_only_untrusted_display_evidence(self):
        # Schema/display only; actual Rust worker-to-Qt cases run in native CI.
        from wam_privacy_wallet.application.selective_disclosure_review import SelectiveDisclosureReview
        self.window.present_public_disclosure_review(SelectiveDisclosureReview("audit",14))
        self.assertIn("AUDIT",self.window.disclosure_review_status.text())
        self.assertIn("EXTERNAL REVIEW PENDING",self.window.disclosure_review_status.text())
        self.assertIn("NO PRIVATE CONTENT",self.window.disclosure_review_notice.text())
        self.assertEqual(self.window.findChildren(QPushButton),[])

    def test_disclosure_denied_consent_clears_without_native_worker(self):
        from wam_privacy_wallet.application.selective_disclosure_review import SelectiveDisclosureReview
        self.window.present_public_disclosure_review(SelectiveDisclosureReview("incoming",14))
        with patch("subprocess.run") as child:
            with self.assertRaisesRegex(ValueError,"^APP_GUI_DISCLOSURE_DENIED$"):
                self.window.review_public_disclosure_fixture(role="incoming",scope="synthetic-regtest",consent=False)
            child.assert_not_called()
        self.assertEqual(self.window.offline_presentation_state.disclosure,"ABSENT")

    def test_disclosure_forged_external_review_or_spend_authority_is_denied(self):
        from dataclasses import replace
        from wam_privacy_wallet.application.selective_disclosure_review import SelectiveDisclosureReview
        for field in ("external_review_complete","runtime_authenticated","spend_authorized","sign_allowed","broadcast_allowed"):
            with self.assertRaisesRegex(ValueError,"^APP_GUI_DISCLOSURE_DENIED$"):
                self.window.present_public_disclosure_review(replace(SelectiveDisclosureReview("incoming",14),**{field:True}))
            self.assertEqual(self.window.offline_presentation_state.disclosure,"ABSENT")

    def test_assurance_dto_display_is_unsigned_without_authentication_claim(self):
        # A supplied DTO is not proof of helper execution or publisher identity.
        from wam_privacy_wallet.application.security_assurance_review import SecurityAssuranceReview,_PUBLIC_PROVENANCE_DIGEST
        self.window.present_public_assurance_review(SecurityAssuranceReview(_PUBLIC_PROVENANCE_DIGEST))
        self.assertIn("UNSIGNED / UNTRUSTED",self.window.assurance_review_status.text())
        self.assertIn("c9b1ce87",self.window.assurance_review_notice.text())
        self.assertIn("NO PUBLISHER / RUNTIME / RELEASE",self.window.assurance_review_notice.text())

    def test_assurance_denied_consent_clears_without_child_or_source_read(self):
        from wam_privacy_wallet.application.security_assurance_review import SecurityAssuranceReview,_PUBLIC_PROVENANCE_DIGEST
        self.window.present_public_assurance_review(SecurityAssuranceReview(_PUBLIC_PROVENANCE_DIGEST))
        with patch("subprocess.run") as child:
            with self.assertRaisesRegex(ValueError,"^APP_GUI_ASSURANCE_DENIED$"):
                self.window.review_public_assurance_fixture(scope="synthetic-regtest",consent=False)
            child.assert_not_called()
        self.assertEqual(self.window.offline_presentation_state.assurance,"ABSENT")

    def test_assurance_forged_digest_or_release_claim_clears_all_evidence(self):
        from dataclasses import replace
        from wam_privacy_wallet.application.security_assurance_review import SecurityAssuranceReview,_PUBLIC_PROVENANCE_DIGEST
        for value in (SecurityAssuranceReview("1"*64),replace(SecurityAssuranceReview(_PUBLIC_PROVENANCE_DIGEST),release_allowed=True)):
            with self.assertRaisesRegex(ValueError,"^APP_GUI_ASSURANCE_DENIED$"):self.window.present_public_assurance_review(value)
            self.assertEqual(self.window.offline_presentation_state.assurance,"ABSENT")

    def test_combined_privacy_receipts_replace_and_clear_with_single_writer(self):
        from wam_privacy_wallet.application.coin_selection_review import CoinSelectionReview
        from wam_privacy_wallet.application.selective_disclosure_review import SelectiveDisclosureReview
        from wam_privacy_wallet.application.security_assurance_review import SecurityAssuranceReview,_PUBLIC_PROVENANCE_DIGEST
        self.window.replace_offline_presentation(0,coin_policy_review=CoinSelectionReview(1,1,False,()),disclosure_review=SelectiveDisclosureReview("incoming",14),assurance_review=SecurityAssuranceReview(_PUBLIC_PROVENANCE_DIGEST))
        self.assertEqual(self.window.offline_presentation_state.authority,"BLOCKED")
        self.window.replace_offline_presentation(self.window.offline_presentation_state.revision)
        self.assertEqual((self.window.offline_presentation_state.coin_policy,self.window.offline_presentation_state.disclosure,self.window.offline_presentation_state.assurance),("ABSENT",)*3)
        self.assertEqual(self.window.assurance_review_status.text(),"NO UNSIGNED PROVENANCE REVIEW")

    def test_new_privacy_renderer_failures_invalidate_revision_and_redact(self):
        from wam_privacy_wallet.application.coin_selection_review import CoinSelectionReview
        from wam_privacy_wallet.application.selective_disclosure_review import SelectiveDisclosureReview
        from wam_privacy_wallet.application.security_assurance_review import SecurityAssuranceReview,_PUBLIC_PROVENANCE_DIGEST
        for widget,method,receipt in ((self.window.coin_policy_review_status,self.window.present_coin_policy_review,CoinSelectionReview(1,1,False,())),(self.window.disclosure_review_status,self.window.present_public_disclosure_review,SelectiveDisclosureReview("incoming",14)),(self.window.assurance_review_status,self.window.present_public_assurance_review,SecurityAssuranceReview(_PUBLIC_PROVENANCE_DIGEST))):
            old=self.window.offline_presentation_state.revision
            with patch.object(widget,"setText",side_effect=RuntimeError("PRIVATE")):
                with self.assertRaisesRegex(ValueError,"^APP_OFFLINE_RENDER_DENIED$"):method(receipt)
            self.assertGreater(self.window.offline_presentation_state.revision,old)
            self.assertEqual((self.window.offline_presentation_state.coin_policy,self.window.offline_presentation_state.disclosure,self.window.offline_presentation_state.assurance),("ABSENT",)*3)

    def test_psbt_panel_defaults_empty_without_actions(self):
        self.assertEqual(self.window.psbt_review_status.text(), "NO UNSIGNED PSBT REVIEW")
        self.assertEqual(self.window.offline_presentation_state.psbt, "ABSENT")
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_psbt_scalar_dto_displays_untrusted_without_retaining_raw(self):
        # Display/schema test only. Actual parser-to-Qt proof lives in native CI.
        from wam_privacy_wallet.application.psbt_v2_review import PsbtV2Review
        self.window.present_unsigned_psbt_review(PsbtV2Review(2, 3))
        self.assertIn("inputs 2", self.window.psbt_review_status.text())
        self.assertIn("UNTRUSTED", self.window.psbt_review_status.text())
        self.assertIn("ac55f134", self.window.psbt_review_notice.text())
        self.assertIn("SIGNING / SENDING BLOCKED", self.window.psbt_review_notice.text())
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")
        self.assertFalse(hasattr(self.window.offline_presentation_state, "raw"))

    def test_psbt_denied_consent_clears_prior_evidence_before_child(self):
        from pathlib import Path
        from wam_privacy_wallet.application.psbt_v2_review import PsbtV2Review
        self.window.present_unsigned_psbt_review(PsbtV2Review(1, 1))
        with patch("subprocess.run") as child:
            with self.assertRaisesRegex(ValueError, "^APP_GUI_PSBT_REVIEW_DENIED$"):
                self.window.review_unsigned_psbt_fixture(b"psbt\xff", source_root=Path.cwd(), scope="synthetic-regtest", consent=False)
            child.assert_not_called()
        self.assertEqual(self.window.psbt_review_status.text(), "NO UNSIGNED PSBT REVIEW")
        self.assertEqual(self.window.offline_presentation_state.psbt, "ABSENT")

    def test_psbt_forged_authority_clears_whole_gui(self):
        from dataclasses import replace
        from wam_privacy_wallet.application.psbt_v2_review import PsbtV2Review
        self.window.present_offline_node_snapshot(NodeOverview("regtest", 1, "READ_ONLY_SNAPSHOT", "EXPERIMENTAL_NO_REAL_FUNDS"))
        with self.assertRaisesRegex(ValueError, "^APP_GUI_PSBT_REVIEW_DENIED$"):
            self.window.present_unsigned_psbt_review(replace(PsbtV2Review(1, 1), sign_allowed=True))
        self.assertEqual(self.window.offline_presentation_state.node, "ABSENT")
        self.assertEqual(self.window.psbt_review_status.text(), "NO UNSIGNED PSBT REVIEW")

    def test_psbt_next_replacement_and_direct_clear_remove_receipt(self):
        from wam_privacy_wallet.application.psbt_v2_review import PsbtV2Review
        self.window.present_unsigned_psbt_review(PsbtV2Review(1, 1))
        self.window.replace_offline_presentation(self.window.offline_presentation_state.revision)
        self.assertEqual(self.window.psbt_review_status.text(), "NO UNSIGNED PSBT REVIEW")
        self.window.present_unsigned_psbt_review(PsbtV2Review(1, 1))
        self.window.clear_unsigned_psbt_review()
        self.assertEqual(self.window.offline_presentation_state.psbt, "ABSENT")

    def test_psbt_render_failure_invalidates_and_redacts(self):
        from wam_privacy_wallet.application.psbt_v2_review import PsbtV2Review
        old = self.window.offline_presentation_state.revision
        with patch.object(self.window.psbt_review_status, "setText", side_effect=RuntimeError("PRIVATE")):
            with self.assertRaisesRegex(ValueError, "^APP_OFFLINE_RENDER_DENIED$"):
                self.window.present_unsigned_psbt_review(PsbtV2Review(1, 1))
        self.assertGreater(self.window.offline_presentation_state.revision, old)
        self.assertEqual(self.window.offline_presentation_state.psbt, "ABSENT")
        self.assertEqual(self.window.offline_presentation_state.authority, "BLOCKED")

    def test_real_wsp_scanner_result_renders_only_as_untrusted_receipt(self):
        receipt = WspScanSessionSummary(1, 2, 0, 0)
        self.window.present_wsp_scan_session_summary(receipt)
        self.assertIn("WSP-1 SCAN EXECUTED", self.window.wsp_session_status.text())
        self.assertIn("tx 2", self.window.wsp_session_status.text())
        self.assertIn("UNTRUSTED CORE", self.window.wsp_session_status.text())
        self.assertIn("NO VALIDATED CORE", self.window.wsp_session_notice.text())
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_real_wsp_receipt_cleared_by_next_offline_update(self):
        self.window.present_wsp_scan_session_summary(
            WspScanSessionSummary(1, 1, 0, 0)
        )
        self.window.replace_offline_presentation(
            self.window.offline_presentation_state.revision
        )
        self.assertEqual(
            self.window.wsp_session_status.text(),
            "NO WSP-1 APPLICATION SCAN RECEIPT",
        )
        self.assertEqual(self.window.offline_presentation_state.scanner_session,
                         "ABSENT")

    def test_forged_real_wsp_receipt_denied_and_clears_existing(self):
        self.window.present_wsp_scan_session_summary(
            WspScanSessionSummary(1, 1, 0, 0)
        )
        forged = WspScanSessionSummary(1, 1, 0, 0)
        object.__setattr__(forged, "signer_enabled", True)
        with self.assertRaisesRegex(ValueError, "^APP_GUI_WSP_RECEIPT_DENIED$"):
            self.window.present_wsp_scan_session_summary(forged)
        self.assertEqual(
            self.window.wsp_session_status.text(),
            "NO WSP-1 APPLICATION SCAN RECEIPT",
        )
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")

    def test_real_wsp_receipt_bool_and_oversize_counts_fail_closed(self):
        for field, value in (
            ("blocks_processed", True),
            ("blocks_processed", 17),
            ("transactions_processed", 160001),
            ("rollback_blocks", -1),
            ("mempool_transactions_processed", 10001),
            ("status", "WALLET_OPERATIONAL"),
        ):
            receipt = WspScanSessionSummary(1, 1, 0, 0)
            object.__setattr__(receipt, field, value)
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, "^APP_GUI_WSP_RECEIPT_DENIED$"
            ):
                self.window.present_wsp_scan_session_summary(receipt)

    def test_real_wsp_receipt_direct_clear_and_reentrant_guard(self):
        self.window.present_wsp_scan_session_summary(
            WspScanSessionSummary(1, 0, 0, 0)
        )
        self.window.clear_wsp_scan_session_summary()
        self.assertEqual(
            self.window.wsp_session_status.text(),
            "NO WSP-1 APPLICATION SCAN RECEIPT",
        )
        self.assertFalse(self.window._managed_transition_active)

    def test_local_scanner_rpc_observation_is_untrusted_gui_only(self) -> None:
        preview = ScannerReadOnlyObservation(3, 2, 4, 0)
        self.window.replace_offline_presentation(0, scanner_observation=preview)
        self.assertEqual(
            self.window.offline_presentation_state.scanner_session,
            "LOCAL_RPC_OBSERVED_UNTRUSTED",
        )
        self.assertIn("blocks read 2", self.window.scanner_read_only_status.text())
        self.assertIn("NO WALLET SCAN", self.window.scanner_read_only_status.text())
        self.assertIn("NO VALIDATED CORE", self.window.scanner_read_only_notice.text())
        self.assertEqual(self.window.findChildren(QPushButton), [])
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")

    def test_forged_scanner_enable_flag_clears_gui_lifecycle(self) -> None:
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        safe = ScannerReadOnlyObservation(3, 2, 4, 0)
        self.window.replace_offline_presentation(0, scanner_observation=safe)
        forged = ScannerReadOnlyObservation(3, 2, 4, 0)
        object.__setattr__(forged, "scanner_enabled", True)
        with self.assertRaisesRegex(
            OfflineLifecycleError, "^APP_OFFLINE_LIFECYCLE_DENIED$",
        ):
            self.window.replace_offline_presentation(
                self.window.offline_presentation_state.revision,
                scanner_observation=forged,
            )
        self.assertEqual(
            self.window.scanner_read_only_status.text(),
            "NO LOCAL SCANNER OBSERVATION",
        )
        self.assertEqual(self.window.offline_presentation_state.scanner_session, "ABSENT")

    def test_lifecycle_replacement_never_carries_scanner_preview_forward(self) -> None:
        preview = ScannerReadOnlyObservation(3, 2, 4, 2)
        self.window.replace_offline_presentation(0, scanner_observation=preview)
        self.window.replace_offline_presentation(
            self.window.offline_presentation_state.revision
        )
        self.assertEqual(self.window.offline_presentation_state.scanner_session, "ABSENT")
        self.assertEqual(
            self.window.scanner_read_only_status.text(),
            "NO LOCAL SCANNER OBSERVATION",
        )

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

    def _review_policy_inputs(self, **changes):
        from test_network_plan_review import plan
        from test_payjoin_proposal_review import fixtures
        endpoints = changes.pop("endpoints", plan())
        original, proposal = fixtures()
        proposal = changes.pop("proposal", proposal)
        self.window.review_offline_policy_inputs(
            endpoints, original, proposal,
            **(dict(payment_output_index=0, scope="synthetic-regtest", consent=True) | changes),
        )

    def test_input_policy_review_actual_models_and_readonly_gui(self):
        self._review_policy_inputs()
        state = self.window.offline_presentation_state
        self.assertEqual((state.policy, state.authority), ("MODEL_ONLY", "BLOCKED"))
        self.assertIn("UNTRUSTED", self.window.privacy_policy_status.text())
        self.assertEqual(self.window.findChildren(QPushButton), [])
        self.assertNotIn("synthetic-payment", self.window.privacy_policy_notice.text())
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")

    def test_input_policy_denied_consent_clears_previous_report(self):
        self._review_policy_inputs()
        revision = self.window.offline_presentation_state.revision
        with self.assertRaisesRegex(ValueError, "^APP_GUI_POLICY_INPUT_REVIEW_DENIED$"):
            self._review_policy_inputs(consent=False)
        state = self.window.offline_presentation_state
        self.assertGreater(state.revision, revision)
        self.assertEqual((state.policy, state.authority), ("ABSENT", "BLOCKED"))
        self.assertEqual(self.window.privacy_policy_status.text(), "NO SYNTHETIC POLICY EVIDENCE")

    def test_input_policy_bad_network_or_proposal_cannot_keep_pass(self):
        from test_network_plan_review import plan
        from test_payjoin_proposal_review import fixtures
        for bad in ("network", "payjoin"):
            self._review_policy_inputs()
            changes = {}
            if bad == "network":
                endpoints = plan()
                endpoints[1]["route"] = "direct"
                changes["endpoints"] = endpoints
            else:
                _, proposal = fixtures()
                proposal["outputs"][0]["destination"] = "attacker"
                changes["proposal"] = proposal
            with self.assertRaisesRegex(ValueError, "^APP_GUI_POLICY_INPUT_REVIEW_DENIED$"):
                self._review_policy_inputs(**changes)
            self.assertEqual(self.window.offline_presentation_state.policy, "ABSENT")

    def test_input_policy_replaces_receive_scanner_and_prior_evidence(self):
        self.window.run_fixed_public_receive_demo()
        self.window.present_wsp_scan_session_summary(WspScanSessionSummary(1, 1, 0, 0))
        self._review_policy_inputs()
        state = self.window.offline_presentation_state
        self.assertEqual((state.receive, state.scanner_session), ("ABSENT", "ABSENT"))
        self.assertEqual(self.window.receive_vector_status.text(), "NO PUBLIC SAMPLE · NO ADDRESS GENERATED")
        self.assertNotIn("WSP-1 SCAN EXECUTED", self.window.wsp_session_status.text())

    def test_input_policy_renderer_failure_invalidates_and_redacts(self):
        from unittest.mock import patch
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        original = MainWindow.present_offline_policy_report
        def fail_render(window, report):
            if window._managed_render_depth:
                raise RuntimeError("PRIVATE_QT_DETAIL")
            return original(window, report)
        with patch.object(MainWindow, "present_offline_policy_report", autospec=True, side_effect=fail_render):
            with self.assertRaisesRegex(OfflineLifecycleError, "^APP_OFFLINE_RENDER_DENIED$"):
                self._review_policy_inputs()
        self.assertEqual(self.window.offline_presentation_state.policy, "ABSENT")
        self.assertEqual(self.window.privacy_policy_status.text(), "NO SYNTHETIC POLICY EVIDENCE")

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

    def _synthetic_recovery_review(self, *, old_version=3, new_version=3,
                                  old_height=5, new_height=5,
                                  old_hash=None, new_hash=None):
        from wam_privacy_wallet.application.recovery_transition import (
            evaluate_offline_recovery_transition,
        )
        A, B = "a" * 64, "b" * 64
        old_hash = A if old_hash is None else old_hash
        new_hash = A if new_hash is None else new_hash

        def fixture(version, height, blockhash):
            return {
                "schema": "wam-wallet-storage-review/v1",
                "profile": "WSP-1", "network": "regtest",
                "genesis": WAM_REGTEST_GENESIS,
                "store_schema_version": version,
                "checkpoint_height": height,
                "checkpoint_hash": blockhash,
                "reported_height": height, "reported_tip": blockhash,
                "writer_lock": "UNATTESTED",
                "db_integrity": "UNATTESTED",
                "wallet_identity": "UNATTESTED",
            }

        return evaluate_offline_recovery_transition(
            old=fixture(old_version, old_height, old_hash),
            candidate=fixture(new_version, new_height, new_hash),
            old_revision=5, new_revision=6,
        )

    def test_recovery_page_has_no_backup_restore_or_signing_actions(self) -> None:
        self.window.navigation.setCurrentRow(5)
        self.assertEqual(self.window.current_page_title, "Recovery")
        self.assertEqual(self.window.recovery_review_status.text(),
                         "NO OFFLINE RECOVERY EVIDENCE")
        self.assertIn("NO WALLET RESTORED", self.window.recovery_review_notice.text())
        self.assertIn("BLOCKED", self.window.recovery_review_notice.text())
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_recovery_matching_snapshot_renders_untrusted_only(self) -> None:
        preview = self._synthetic_recovery_review()
        self.window.present_offline_recovery_review(preview)
        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.recovery),
                         (1, "REVIEW_ONLY_NOT_VERIFIED"))
        self.assertIn("UNTRUSTED CHECKPOINT", self.window.recovery_review_status.text())
        self.assertNotIn("a" * 64, self.window.recovery_review_notice.text())
        self.assertEqual(state.authority, "BLOCKED")
        self.assertEqual(state.wallet, "NO_WALLET_LOADED")
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")

    def test_recovery_rescan_and_migration_use_fixed_vocabularies(self) -> None:
        from wam_privacy_wallet.application.recovery_transition import (
            OfflineRecoveryTransition,
        )
        scenarios = (
            (self._synthetic_recovery_review(new_hash="b" * 64),
             "RESCAN REQUIRED · NOT PERFORMED"),
            (self._synthetic_recovery_review(old_version=2),
             "MIGRATION + RESCAN REQUIRED · NOT PERFORMED"),
        )
        for preview, expected in scenarios:
            self.window.present_offline_recovery_review(preview)
            self.assertEqual(self.window.recovery_review_status.text(), expected)
            self.assertNotIn("a" * 64, self.window.recovery_review_status.text())
            self.assertEqual(self.window.offline_presentation_state.recovery,
                             preview.decision)
            self.assertEqual(self.window.offline_presentation_state.authority,
                             "BLOCKED")

    def test_recovery_direct_presenter_invalidates_other_managed_panels(self) -> None:
        self.window.present_public_receive_vector(rv.inspect_pinned_public_vector())
        self.assertIn("PUBLIC FINGERPRINT", self.window.receive_vector_status.text())
        self.window.present_offline_recovery_review(self._synthetic_recovery_review())
        state = self.window.offline_presentation_state
        self.assertEqual(state.revision, 2)
        self.assertEqual(state.receive, "ABSENT")
        self.assertEqual(self.window.receive_vector_status.text(),
                         "NO PUBLIC SAMPLE · NO ADDRESS GENERATED")
        self.window.present_offline_node_snapshot(NodeOverview(
            "regtest", 3, "READ_ONLY_SNAPSHOT", "EXPERIMENTAL_NO_REAL_FUNDS"
        ))
        self.assertEqual(self.window.offline_presentation_state.recovery, "ABSENT")
        self.assertEqual(self.window.recovery_review_status.text(),
                         "NO OFFLINE RECOVERY EVIDENCE")
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_recovery_forged_authority_or_reason_is_denied(self) -> None:
        from dataclasses import replace
        source = self._synthetic_recovery_review()
        self.window.present_offline_recovery_review(source)
        prior = self.window.offline_presentation_state
        cases = [replace(source, decision="RESCAN_REQUIRED")]
        tampered = replace(source)
        object.__setattr__(tampered, "wallet_enabled", True)
        cases.append(tampered)
        for bad in cases:
            with self.subTest(bad=bad.reason), self.assertRaisesRegex(
                ValueError, "^APP_GUI_RECOVERY_REVIEW_DENIED$"
            ):
                self.window.present_offline_recovery_review(bad)
        self.assertEqual(self.window.offline_presentation_state, prior)
        self.assertIn("UNTRUSTED", self.window.recovery_review_status.text())
        self.assertFalse(any((
            self.window.findChildren(QPushButton),
        )))

    def test_recovery_clear_and_stale_revision_rejects_prior_evidence(self) -> None:
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        self.window.present_offline_recovery_review(self._synthetic_recovery_review())
        self.window.clear_offline_recovery_review()
        s = self.window.offline_presentation_state
        self.assertEqual((s.revision, s.transition, s.recovery),
                         (2, "CLEARED", "ABSENT"))
        self.assertEqual(self.window.recovery_review_status.text(),
                         "NO OFFLINE RECOVERY EVIDENCE")
        with self.assertRaises(OfflineLifecycleError):
            self.window.replace_offline_presentation(
                1, recovery=self._synthetic_recovery_review()
            )
        self.assertEqual(self.window.offline_presentation_state.transition,
                         "REJECTED")
        self.assertEqual(self.window.recovery_review_status.text(),
                         "NO OFFLINE RECOVERY EVIDENCE")

    def test_recovery_render_fault_invalidates_managed_revision(self) -> None:
        from unittest.mock import patch
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        preview = self._synthetic_recovery_review()
        with patch.object(MainWindow, "present_offline_recovery_review",
                          side_effect=RuntimeError("HIDDEN_QT_DETAIL")):
            with self.assertRaisesRegex(
                OfflineLifecycleError, "^APP_OFFLINE_RENDER_DENIED$"
            ) as raised:
                self.window.replace_offline_presentation(
                    0, recovery=preview
                )
            self.assertIsNone(raised.exception.__cause__)
        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.transition, state.recovery),
                         (2, "CLEARED", "ABSENT"))
        self.assertEqual(self.window.recovery_review_status.text(),
                         "NO OFFLINE RECOVERY EVIDENCE")
        self.assertNotIn("HIDDEN_QT_DETAIL",
                         self.window.recovery_review_notice.text())

    def _synthetic_resume_preview(self, *, scenario="normal"):
        from wam_privacy_wallet.application.offline_resume_review import (
            review_offline_resume,
        )
        A, B = "a" * 64, "b" * 64

        def metadata(version=3, checkpoint=3, digest=A):
            return {
                "schema": "wam-wallet-storage-review/v1",
                "profile": "WSP-1", "network": "regtest",
                "genesis": WAM_REGTEST_GENESIS,
                "store_schema_version": version,
                "checkpoint_height": checkpoint,
                "checkpoint_hash": digest,
                "reported_height": checkpoint,
                "reported_tip": digest,
                "writer_lock": "UNATTESTED", "db_integrity": "UNATTESTED",
                "wallet_identity": "UNATTESTED",
            }

        old = metadata()
        after = metadata()
        if scenario == "rollback":
            old = metadata(checkpoint=4, digest=B)
        elif scenario == "migration":
            old = metadata(version=2)
        return review_offline_resume(
            before=old, after=after, old_revision=4, new_revision=5,
            interrupted_height=5, interruption="CRASH",
        )

    def test_resume_panel_starts_blocked_with_no_user_actions(self) -> None:
        self.window.navigation.setCurrentRow(5)
        self.assertEqual(self.window.current_page_title, "Recovery")
        self.assertIn("RESUME DISABLED", self.window.resume_review_status.text())
        self.assertIn("NO AUTOMATIC RESUME", self.window.resume_review_notice.text())
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_resume_normal_restart_never_promotes_wallet_or_scanner(self) -> None:
        preview = self._synthetic_resume_preview()
        self.window.present_offline_resume_review(preview)
        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.resume),
                         (1, "REVALIDATE_BEFORE_RESCAN"))
        self.assertEqual(state.authority, "BLOCKED")
        self.assertEqual(state.wallet, "NO_WALLET_LOADED")
        self.assertIn("RESUME NOT AUTHORIZED", self.window.resume_review_status.text())
        self.assertNotIn("a" * 64, self.window.resume_review_status.text())
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")

    def test_resume_rollback_and_migration_have_fixed_safe_messages(self) -> None:
        for scenario, label in (
            ("rollback", "REWIND / RESCAN REVIEW · NOT STARTED"),
            ("migration", "MIGRATION + RESCAN REVIEW · NOT STARTED"),
        ):
            with self.subTest(scenario=scenario):
                self.window.present_offline_resume_review(
                    self._synthetic_resume_preview(scenario=scenario)
                )
                self.assertEqual(self.window.resume_review_status.text(), label)
                self.assertNotIn("b" * 64, self.window.resume_review_notice.text())
                self.assertEqual(self.window.offline_presentation_state.authority,
                                 "BLOCKED")

    def test_resume_and_recovery_share_single_writer_atomic_swap(self) -> None:
        self.window.replace_offline_presentation(
            0, recovery=self._synthetic_recovery_review(),
            resume=self._synthetic_resume_preview(),
        )
        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.recovery, state.resume),
                         (1, "REVIEW_ONLY_NOT_VERIFIED", "REVALIDATE_BEFORE_RESCAN"))
        self.window.present_offline_node_snapshot(NodeOverview(
            "regtest", 2, "READ_ONLY_SNAPSHOT", "EXPERIMENTAL_NO_REAL_FUNDS"
        ))
        cleared = self.window.offline_presentation_state
        self.assertEqual((cleared.revision, cleared.recovery, cleared.resume),
                         (2, "ABSENT", "ABSENT"))
        self.assertIn("RESUME DISABLED", self.window.resume_review_status.text())
        self.assertIn("NO OFFLINE RECOVERY", self.window.recovery_review_status.text())

    def test_resume_forged_claims_rejected_without_changing_display(self) -> None:
        from dataclasses import replace
        good = self._synthetic_resume_preview()
        self.window.present_offline_resume_review(good)
        original = self.window.offline_presentation_state
        bad_action = replace(good, action="REWIND_RESCAN_REVIEW")
        bad_authority = replace(good)
        object.__setattr__(bad_authority, "resume_authorized", True)
        for bad in (bad_action, bad_authority, {"secret": "DO_NOT_LEAK"}):
            with self.subTest(bad=type(bad).__name__), self.assertRaisesRegex(
                ValueError, "^APP_GUI_RESUME_REVIEW_DENIED$"
            ):
                self.window.present_offline_resume_review(bad)
            self.assertEqual(self.window.offline_presentation_state, original)
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_resume_clear_invalidates_old_revision_and_evidence(self) -> None:
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        self.window.present_offline_resume_review(self._synthetic_resume_preview())
        self.window.clear_offline_resume_review()
        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.transition, state.resume),
                         (2, "CLEARED", "ABSENT"))
        self.assertIn("RESUME DISABLED", self.window.resume_review_status.text())
        with self.assertRaises(OfflineLifecycleError):
            self.window.replace_offline_presentation(1,
                resume=self._synthetic_resume_preview())
        self.assertEqual(self.window.offline_presentation_state.transition, "REJECTED")

    def test_resume_renderer_fault_resets_and_redacts_without_privilege(self) -> None:
        from unittest.mock import patch
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        with patch.object(MainWindow, "present_offline_resume_review",
                          side_effect=RuntimeError("SECRET_QT_RESUME_FAILURE")):
            with self.assertRaisesRegex(
                OfflineLifecycleError, "^APP_OFFLINE_RENDER_DENIED$"
            ) as failure:
                self.window.replace_offline_presentation(
                    0, resume=self._synthetic_resume_preview()
                )
            self.assertIsNone(failure.exception.__cause__)
        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.resume, state.transition),
                         (2, "ABSENT", "CLEARED"))
        self.assertIn("RESUME DISABLED", self.window.resume_review_status.text())
        self.assertNotIn("SECRET_QT_RESUME_FAILURE",
                         self.window.resume_review_notice.text())

    def _synthetic_segment_report(self, *, replay=False, empty=False):
        from wam_privacy_wallet.application.offline_rescan_segments import (
            inspect_offline_rescan_segments,
        )
        resume = self._synthetic_resume_preview()
        segment = {
            "start_height": 3, "end_height": 5,
            "parent_hash": "a" * 64, "end_hash": "b" * 64,
            "transaction_count": 2, "attempt": 1,
        }
        batch = () if empty else (segment, dict(segment)) if replay else (segment,)
        return inspect_offline_rescan_segments(
            resume=resume, expected_revision=resume.revision,
            start_height=3, segments=batch,
        )

    def test_rescan_segments_gui_starts_disabled_without_buttons(self) -> None:
        self.window.navigation.setCurrentRow(5)
        self.assertIn("NO RESCAN SEGMENT", self.window.rescan_segments_status.text())
        self.assertIn("NO DURABLE CHECKPOINT", self.window.rescan_segments_notice.text())
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_contiguous_segment_review_does_not_claim_checkpoint(self) -> None:
        report = self._synthetic_segment_report()
        self.window.present_offline_rescan_segments(report)
        self.assertEqual(self.window.offline_presentation_state.rescan,
                         "CONTIGUOUS_UNVERIFIED")
        self.assertIn("NOT COMMITTED", self.window.rescan_segments_status.text())
        self.assertEqual(self.window.session_status.text(), "NO WALLET LOADED")
        self.assertNotIn("b" * 64, self.window.rescan_segments_notice.text())

    def test_exact_segment_replay_displays_not_double_counted(self) -> None:
        report = self._synthetic_segment_report(replay=True)
        self.window.present_offline_rescan_segments(report)
        self.assertIn("NOT DOUBLE COUNTED", self.window.rescan_segments_status.text())
        self.assertEqual(report.observed_block_count, 2)
        self.assertEqual(report.replay_count, 1)
        self.assertEqual(self.window.offline_presentation_state.authority, "BLOCKED")

    def test_rescan_segment_forged_authority_or_counts_are_denied(self) -> None:
        from dataclasses import replace
        good = self._synthetic_segment_report()
        self.window.present_offline_rescan_segments(good)
        snapshot = self.window.offline_presentation_state
        forged = replace(good)
        object.__setattr__(forged, "scanner_enabled", True)
        for candidate in (
            forged, replace(good, observed_block_count=0),
            replace(good, disposition="REPLAY_NOT_APPLIED"),
            {"private_key": "SHOULD_NOT_LEAK"},
        ):
            with self.subTest(t=type(candidate).__name__), self.assertRaisesRegex(
                ValueError, "^APP_GUI_RESCAN_SEGMENTS_DENIED$"
            ):
                self.window.present_offline_rescan_segments(candidate)
            self.assertEqual(self.window.offline_presentation_state, snapshot)
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_segment_review_same_writer_and_direct_clear(self) -> None:
        resume = self._synthetic_resume_preview()
        segment = self._synthetic_segment_report()
        self.window.replace_offline_presentation(0, resume=resume, rescan=segment)
        self.assertEqual((self.window.offline_presentation_state.resume,
                          self.window.offline_presentation_state.rescan),
                         ("REVALIDATE_BEFORE_RESCAN", "CONTIGUOUS_UNVERIFIED"))
        self.window.clear_offline_rescan_segments()
        self.assertEqual((self.window.offline_presentation_state.revision,
                          self.window.offline_presentation_state.rescan), (2, "ABSENT"))
        self.assertIn("NO RESCAN SEGMENT", self.window.rescan_segments_status.text())
        self.assertIn("RESUME DISABLED", self.window.resume_review_status.text())

    def test_rescan_segment_renderer_failure_resets_and_redacts(self) -> None:
        from unittest.mock import patch
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        with patch.object(MainWindow, "present_offline_rescan_segments",
                          side_effect=RuntimeError("SECRET_RESCAN_RENDER")):
            with self.assertRaisesRegex(
                OfflineLifecycleError, "^APP_OFFLINE_RENDER_DENIED$"
            ) as error:
                self.window.replace_offline_presentation(
                    0, rescan=self._synthetic_segment_report()
                )
            self.assertIsNone(error.exception.__cause__)
        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.transition, state.rescan),
                         (2, "CLEARED", "ABSENT"))
        self.assertIn("NO RESCAN SEGMENT", self.window.rescan_segments_status.text())
        self.assertNotIn("SECRET_RESCAN_RENDER",
                         self.window.rescan_segments_notice.text())

    def _synthetic_reorg_receipts(self, mode="normal", replay=False):
        from wam_privacy_wallet.application.recovery_transition import (
            OfflineRecoveryTransition,
        )
        from wam_privacy_wallet.application.offline_rescan_segments import (
            OfflineRescanSegments,
        )
        from wam_privacy_wallet.application.offline_reorg_reconciliation import (
            reconcile_offline_reorg,
        )
        if mode == "normal":
            transition = OfflineRecoveryTransition(
                "NO_TRUSTED_RECOVERY_EVIDENCE",
                "REVIEW_ONLY_NOT_VERIFIED", 4, 5, 3,
            )
            resume = self._synthetic_resume_preview()
            segment = self._synthetic_segment_report(replay=replay)
        elif mode == "rollback":
            transition = OfflineRecoveryTransition(
                "CHECKPOINT_ROLLBACK", "RESCAN_REQUIRED", 4, 5, 3,
            )
            resume = self._synthetic_resume_preview(scenario="rollback")
            segment = OfflineRescanSegments(
                "CONTIGUOUS_UNVERIFIED", "REWIND_RESCAN_REVIEW",
                5, 3, 5, 1, 0, 2, 2,
            )
        elif mode == "migration":
            transition = OfflineRecoveryTransition(
                "MIGRATION_RESCAN_REQUIRED", "MIGRATION_RESCAN_REQUIRED",
                4, 5, 3,
            )
            resume = self._synthetic_resume_preview(scenario="migration")
            segment = OfflineRescanSegments(
                "CONTIGUOUS_UNVERIFIED", "MIGRATION_RESCAN_REVIEW",
                5, 0, 2, 1, 0, 2, 1,
            )
        else:
            raise AssertionError("unknown test case")
        outcome = reconcile_offline_reorg(
            transition=transition, resume=resume, segments=segment,
            expected_revision=5,
        )
        return transition, resume, segment, outcome

    def test_reorg_panel_defaults_to_no_evidence_and_no_actions(self):
        self.window.navigation.setCurrentRow(5)
        self.assertIn("NO REORG", self.window.reorg_review_status.text())
        self.assertIn("NO TRUSTED CURSOR", self.window.reorg_review_notice.text())
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_reorg_contiguous_model_remains_untrusted_in_gui(self):
        _, _, _, outcome = self._synthetic_reorg_receipts()
        self.window.present_offline_reorg_reconciliation(outcome)
        self.assertIn("NOT AUTHENTICATED", self.window.reorg_review_status.text())
        self.assertEqual(self.window.offline_presentation_state.reorg,
                         "CONTIGUOUS_BUT_UNVERIFIED")
        self.assertEqual(self.window.offline_presentation_state.wallet,
                         "NO_WALLET_LOADED")
        self.assertNotIn("a" * 64, self.window.reorg_review_notice.text())
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_reorg_replayed_segment_never_looks_committed(self):
        _, _, _, outcome = self._synthetic_reorg_receipts(replay=True)
        self.window.present_offline_reorg_reconciliation(outcome)
        self.assertEqual(outcome.verdict, "REPLAY_NOT_DOUBLE_COUNTED")
        self.assertIn("NOT COMMITTED", self.window.reorg_review_status.text())
        self.assertFalse(outcome.checkpoint_durable)

    def test_reorg_rollback_and_migration_keep_safe_fixed_language(self):
        for mode, token in (("rollback", "ROLLBACK REVIEW"),
                            ("migration", "MIGRATION REVIEW")):
            with self.subTest(mode=mode):
                _, _, _, outcome = self._synthetic_reorg_receipts(mode)
                self.window.present_offline_reorg_reconciliation(outcome)
                self.assertIn(token, self.window.reorg_review_status.text())
                self.assertIn("NO SAFE CURSOR", self.window.reorg_review_status.text())
                self.assertEqual(self.window.offline_presentation_state.authority,
                                 "BLOCKED")

    def test_reorg_forged_counts_or_authority_are_rejected(self):
        from dataclasses import replace
        _, _, _, good = self._synthetic_reorg_receipts()
        self.window.present_offline_reorg_reconciliation(good)
        state = self.window.offline_presentation_state
        fake = replace(good)
        object.__setattr__(fake, "scanner_enabled", True)
        for candidate in (
            fake,
            replace(good, unique_segments=0),
            replace(good, verdict="MIGRATION_RESCAN_REVIEW"),
            {"private_key": "DO_NOT_LEAK"},
        ):
            # A different valid verdict is an untrusted receipt, so the
            # invalid verdict fixture must be coupled to contradictory counts.
            if type(candidate) is type(good) and candidate.verdict == "MIGRATION_RESCAN_REVIEW":
                candidate = replace(candidate, unique_segments=0)
            with self.subTest(value=type(candidate).__name__), self.assertRaisesRegex(
                ValueError, "^APP_GUI_REORG_REVIEW_DENIED$"
            ):
                self.window.present_offline_reorg_reconciliation(candidate)
            self.assertEqual(self.window.offline_presentation_state, state)
        self.assertEqual(self.window.findChildren(QPushButton), [])

    def test_reorg_atomic_recovery_resume_rescan_and_clear(self):
        from dataclasses import replace
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        _, restart, seg, outcome = self._synthetic_reorg_receipts()
        self.window.replace_offline_presentation(
            0, resume=restart, rescan=seg, reorg=outcome,
        )
        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.resume, state.rescan, state.reorg),
                         (1, "REVALIDATE_BEFORE_RESCAN",
                          "CONTIGUOUS_UNVERIFIED", "CONTIGUOUS_BUT_UNVERIFIED"))
        with self.assertRaises(OfflineLifecycleError):
            self.window.replace_offline_presentation(
                1, resume=restart, rescan=seg,
                reorg=replace(outcome, unique_segments=2),
            )
        self.assertEqual(self.window.offline_presentation_state.transition,
                         "REJECTED")
        self.assertIn("NO REORG", self.window.reorg_review_status.text())
        self.assertIn("NO RESCAN SEGMENT", self.window.rescan_segments_status.text())

    def test_reorg_renderer_fault_redacts_and_invalidates_revision(self):
        from unittest.mock import patch
        from wam_privacy_wallet.application.presentation_lifecycle import OfflineLifecycleError
        _, _, _, outcome = self._synthetic_reorg_receipts()
        with patch.object(MainWindow, "present_offline_reorg_reconciliation",
                          side_effect=RuntimeError("PRIVATE_REORG_GUI_EXCEPTION")):
            with self.assertRaisesRegex(
                OfflineLifecycleError, "^APP_OFFLINE_RENDER_DENIED$"
            ) as error:
                self.window.replace_offline_presentation(0, reorg=outcome)
            self.assertIsNone(error.exception.__cause__)
        state = self.window.offline_presentation_state
        self.assertEqual((state.revision, state.transition, state.reorg),
                         (2, "CLEARED", "ABSENT"))
        self.assertIn("NO REORG", self.window.reorg_review_status.text())
        self.assertNotIn("PRIVATE_REORG_GUI_EXCEPTION",
                         self.window.reorg_review_notice.text())

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
