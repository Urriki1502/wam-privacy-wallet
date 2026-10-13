"""Actual dependency-free lifecycle and local policy tests; no fake wallet."""
import unittest
from dataclasses import replace
from unittest.mock import patch

from wam_privacy_wallet.application.regtest_lifecycle import (
    BLOCKERS, ReadinessInspection, RegtestLifecycle, RegtestLifecycleError,
    WorkTicket, inspect_local_readiness,
)


class RegtestLifecycleTests(unittest.TestCase):
    def selected(self):
        controller = RegtestLifecycle()
        controller.select_mode("regtest")
        return controller

    def test_startup_has_no_mode_or_wallet(self):
        state = RegtestLifecycle().state
        self.assertEqual((state.phase, state.mode, state.revision), ("MODE_REQUIRED", "UNSELECTED", 0))
        self.assertFalse(state.wallet_operational)

    def test_actual_local_policy_inspection_is_blocked(self):
        receipt = inspect_local_readiness(lambda: False)
        self.assertEqual(receipt.blockers, BLOCKERS)
        self.assertEqual(receipt.status, "BLOCKED_EXTERNAL_APPROVAL")
        self.assertFalse(receipt.core_authenticated)

    def test_mainnet_and_ambiguous_modes_denied(self):
        for mode in ("mainnet", "REGTEST", "", None, 1, True):
            with self.assertRaises(RegtestLifecycleError):
                RegtestLifecycle().select_mode(mode)

    def test_string_subclass_mode_denied_without_callback(self):
        class Mode(str):
            def __eq__(self, other):
                raise AssertionError("callback executed")
        with self.assertRaises(RegtestLifecycleError):
            RegtestLifecycle().select_mode(Mode("regtest"))

    def test_inspection_requires_selected_mode(self):
        with self.assertRaises(RegtestLifecycleError):
            RegtestLifecycle().begin_readiness(consent=True)

    def test_consent_must_be_true_identity(self):
        for consent in (False, 1, "yes", None):
            with self.assertRaises(RegtestLifecycleError):
                self.selected().begin_readiness(consent=consent)

    def test_successful_work_reports_blocked_not_wallet_success(self):
        controller = self.selected()
        ticket = controller.begin_readiness(consent=True)
        self.assertTrue(controller.finish_readiness(ticket, inspect_local_readiness(lambda: False)))
        self.assertEqual(controller.state.phase, "BLOCKED")
        self.assertFalse(controller.state.wallet_operational)

    def test_duplicate_work_and_mode_change_during_work_denied(self):
        controller = self.selected()
        controller.begin_readiness(consent=True)
        with self.assertRaises(RegtestLifecycleError):
            controller.begin_readiness(consent=True)
        with self.assertRaises(RegtestLifecycleError):
            controller.select_mode("regtest")

    def test_matching_forged_ticket_is_ignored(self):
        controller = self.selected()
        ticket = controller.begin_readiness(consent=True)
        self.assertFalse(controller.finish_readiness(WorkTicket(ticket.revision, ticket.operation), ReadinessInspection()))
        self.assertEqual(controller.state.phase, "CHECKING")

    def test_cancelled_completion_cannot_restore_evidence(self):
        controller = self.selected()
        ticket = controller.begin_readiness(consent=True)
        controller.cancel()
        self.assertFalse(controller.finish_readiness(ticket, ReadinessInspection()))
        self.assertEqual(controller.state.phase, "CANCELLED")

    def test_previous_session_cannot_overwrite_new_work(self):
        controller = self.selected()
        old = controller.begin_readiness(consent=True)
        controller.cancel()
        current = controller.begin_readiness(consent=True)
        self.assertFalse(controller.finish_readiness(old, ReadinessInspection()))
        self.assertTrue(controller.finish_readiness(current, ReadinessInspection()))

    def test_closed_session_never_resurrects(self):
        controller = self.selected()
        ticket = controller.begin_readiness(consent=True)
        state = controller.close()
        self.assertFalse(controller.fail(ticket))
        self.assertFalse(controller.finish_readiness(ticket, ReadinessInspection()))
        self.assertEqual(controller.close(), state)
        self.assertEqual(controller.cancel(), state)
        with self.assertRaises(RegtestLifecycleError):
            controller.select_mode("regtest")

    def test_forged_authority_result_invalidates_work(self):
        for name in ("core_authenticated", "wallet_operational", "signing_allowed", "broadcast_allowed", "mainnet_allowed"):
            controller = self.selected()
            ticket = controller.begin_readiness(consent=True)
            with self.assertRaises(RegtestLifecycleError):
                controller.finish_readiness(ticket, replace(ReadinessInspection(), **{name: True}))
            self.assertEqual(controller.state.phase, "FAILED")
            self.assertFalse(controller.state.wallet_operational)

    def test_bad_schema_or_removed_blocker_is_denied(self):
        for value in (None, {}, replace(ReadinessInspection(), blockers=(9,)), replace(ReadinessInspection(), status="PASS"), replace(ReadinessInspection(), blockers=(True, 82, 86, 153, 148, 151))):
            controller = self.selected()
            ticket = controller.begin_readiness(consent=True)
            with self.assertRaises(RegtestLifecycleError):
                controller.finish_readiness(ticket, value)

    def test_failure_is_fixed_and_retryable(self):
        controller = self.selected()
        ticket = controller.begin_readiness(consent=True)
        self.assertTrue(controller.fail(ticket))
        self.assertEqual(controller.state.failure, "APP_REGTEST_WORK_DENIED")
        self.assertFalse(controller.fail(ticket))
        current = controller.begin_readiness(consent=True)
        self.assertTrue(controller.finish_readiness(current, ReadinessInspection()))

    def test_operational_gate_denies_before_backend_io(self):
        with patch("socket.socket") as network, patch("subprocess.Popen") as process:
            controller = self.selected()
            with self.assertRaisesRegex(RegtestLifecycleError, "^APP_REGTEST_OPERATIONAL_GATES_BLOCKED$"):
                controller.require_operational_wallet()
            network.assert_not_called()
            process.assert_not_called()

    def test_cancelled_readiness_does_not_evaluate_policy(self):
        with patch("wam_privacy_wallet.application.regtest_lifecycle.TwoNodeReadiness") as policy:
            with self.assertRaisesRegex(RegtestLifecycleError, "^APP_REGTEST_CANCELLED$"):
                inspect_local_readiness(lambda: True)
            policy.assert_not_called()

    def test_invalid_cancel_result_fails_closed(self):
        for value in (None, 0, ""):
            with self.assertRaises(RegtestLifecycleError):
                inspect_local_readiness(lambda: value)

    def test_local_readiness_does_not_read_files_or_connect(self):
        with patch("builtins.open") as files, patch("socket.socket") as network, patch("subprocess.run") as process:
            self.assertEqual(inspect_local_readiness(lambda: False).status, "BLOCKED_EXTERNAL_APPROVAL")
            files.assert_not_called()
            network.assert_not_called()
            process.assert_not_called()

    def test_revision_increases_through_real_lifecycle(self):
        controller = RegtestLifecycle()
        self.assertEqual(controller.select_mode("regtest").revision, 1)
        ticket = controller.begin_readiness(consent=True)
        self.assertEqual(ticket.revision, 2)
        controller.finish_readiness(ticket, ReadinessInspection())
        self.assertEqual(controller.state.revision, 3)
        self.assertEqual(controller.close().revision, 4)
