"""Synthetic fail-closed GUI CI gate regressions; no Qt, node or keys."""
from __future__ import annotations

import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

from tools.gui_ci_contract_gate import check_and_run


_NAMES = (
    "test_new_privacy_panels_start_empty_and_scroll_without_actions",
    "test_actual_normalized_coin_policy_reaches_readonly_gui",
    "test_coin_policy_denied_consent_or_scope_clears_before_algorithm",
    "test_forged_coin_signing_or_warning_claim_clears_whole_gui",
    "test_public_disclosure_dto_is_only_untrusted_display_evidence",
    "test_disclosure_denied_consent_clears_without_native_worker",
    "test_disclosure_forged_external_review_or_spend_authority_is_denied",
    "test_assurance_dto_display_is_unsigned_without_authentication_claim",
    "test_assurance_denied_consent_clears_without_child_or_source_read",
    "test_assurance_forged_digest_or_release_claim_clears_all_evidence",
    "test_combined_privacy_receipts_replace_and_clear_with_single_writer",
    "test_new_privacy_renderer_failures_invalidate_revision_and_redact",

    "test_psbt_panel_defaults_empty_without_actions",
    "test_psbt_scalar_dto_displays_untrusted_without_retaining_raw",
    "test_psbt_denied_consent_clears_prior_evidence_before_child",
    "test_psbt_forged_authority_clears_whole_gui",
    "test_psbt_next_replacement_and_direct_clear_remove_receipt",
    "test_psbt_render_failure_invalidates_and_redacts",

    "test_input_policy_review_actual_models_and_readonly_gui",
    "test_input_policy_denied_consent_clears_previous_report",
    "test_input_policy_bad_network_or_proposal_cannot_keep_pass",
    "test_input_policy_replaces_receive_scanner_and_prior_evidence",
    "test_input_policy_renderer_failure_invalidates_and_redacts",

    "test_real_wsp_scanner_result_renders_only_as_untrusted_receipt",
    "test_real_wsp_receipt_cleared_by_next_offline_update",
    "test_forged_real_wsp_receipt_denied_and_clears_existing",
    "test_real_wsp_receipt_bool_and_oversize_counts_fail_closed",
    "test_real_wsp_receipt_direct_clear_and_reentrant_guard",
    "test_local_scanner_rpc_observation_is_untrusted_gui_only",
    "test_forged_scanner_enable_flag_clears_gui_lifecycle",
    "test_lifecycle_replacement_never_carries_scanner_preview_forward",
    "test_pages_and_navigation_are_consistent",
    "test_offline_safety_notice_and_no_funds_state",
    "test_no_payment_actions_are_exposed",
    "test_window_is_portable_qt_widget",
    "test_lifecycle_valid_then_invalid_clears_all_panels",
    "test_lifecycle_stale_revision_clears_receive_and_node",
    "test_lifecycle_reset_invalidates_revision_and_all_panels",
    "test_lifecycle_replacement_does_not_retain_omitted_evidence",
    "test_lifecycle_render_failure_clears_and_invalidates",
    "test_reentrant_clear_during_render_cannot_survive_swallowed_error",
    "test_reentrant_replace_during_clear_poisoned_even_when_callback_catches",
    "test_reentrant_replace_during_explicit_clear_stays_blocked_then_recovers",
    "test_lifecycle_clear_failure_invalidates_revision_and_other_panels",
    "test_reset_clear_failure_attempts_all_panels_and_stays_blocked",
    "test_recovery_page_has_no_backup_restore_or_signing_actions",
    "test_recovery_forged_authority_or_reason_is_denied",
    "test_recovery_clear_and_stale_revision_rejects_prior_evidence",
    "test_recovery_render_fault_invalidates_managed_revision",
    "test_resume_panel_starts_blocked_with_no_user_actions",
    "test_resume_forged_claims_rejected_without_changing_display",
    "test_resume_clear_invalidates_old_revision_and_evidence",
    "test_resume_renderer_fault_resets_and_redacts_without_privilege",
    "test_rescan_segments_gui_starts_disabled_without_buttons",
    "test_rescan_segment_forged_authority_or_counts_are_denied",
    "test_segment_review_same_writer_and_direct_clear",
    "test_rescan_segment_renderer_failure_resets_and_redacts",
    "test_reorg_panel_defaults_to_no_evidence_and_no_actions",
    "test_reorg_forged_counts_or_authority_are_rejected",
    "test_reorg_atomic_recovery_resume_rescan_and_clear",
    "test_reorg_renderer_fault_redacts_and_invalidates_revision",
    "test_legacy_presenter_replaces_managed_snapshot_atomically",
    "test_legacy_clear_invalidates_all_panels_and_prior_revision",
    "test_legacy_invalid_input_does_not_mutate_accepted_state",
    "test_legacy_demo_routes_through_controller_single_writer",
)


class GuiGateSyntheticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gui-gate-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.tests = Path(self.temp.name)
        self.addCleanup(self._clean_imports)
        self._clean_imports()

    def _clean_imports(self):
        sys.modules.pop("test_gui_shell", None)
        sys.modules.pop("test_other", None)
        while str(getattr(self, "tests", "")) in sys.path:
            sys.path.remove(str(self.tests))

    def _write(self, filename, content):
        (self.tests / filename).write_text(content, encoding="utf-8")

    def _gui(self, *, names=_NAMES, skipped=(), class_skip=False, broken=False):
        code = "import unittest\n"
        if broken:
            code += "raise ImportError('synthetic import error')\n"
        if class_skip:
            code += "@unittest.skip('synthetic')\n"
        code += "class GuiShellSmokeTests(unittest.TestCase):\n"
        for name in names:
            if name in skipped:
                code += "    @unittest.skip('synthetic')\n"
            code += f"    def {name}(self): pass\n"
        self._write("test_gui_shell.py", code)

    def _run(self, minimum=4, *, critical_non_gui_ids=()):
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            return check_and_run(self.tests, full_minimum=minimum,
                                 critical_non_gui_ids=frozenset(critical_non_gui_ids))

    def test_missing_gui_file_denied(self):
        self.assertEqual(self._run(0), 1)

    def test_empty_gui_file_denied(self):
        self._write("test_gui_shell.py", "# empty\n")
        self.assertEqual(self._run(0), 1)

    def test_partial_gui_cases_denied(self):
        self._gui(names=_NAMES[:8])
        self.assertEqual(self._run(0), 1)

    def test_replaced_gui_case_same_count_denied(self):
        self._gui(names=(*_NAMES[:8], "test_replacement"))
        self.assertEqual(self._run(0), 1)

    def test_gui_import_error_denied(self):
        self._gui(broken=True)
        self.assertEqual(self._run(0), 1)

    def test_skipped_gui_class_denied(self):
        self._gui(class_skip=True)
        self.assertEqual(self._run(), 1)

    def test_single_skipped_gui_case_denied(self):
        self._gui(skipped=(_NAMES[0],))
        self.assertEqual(self._run(), 1)

    def test_fifteen_pinned_gui_cases_pass(self):
        self._gui()
        self.assertEqual(self._run(), 0)

    def test_additional_gui_case_allowed(self):
        self._gui(names=(*_NAMES, "test_extra"))
        self.assertEqual(self._run(10), 0)

    def test_full_discovery_count_floor_denies_loss(self):
        self._gui()
        # A drop below the current pinned GUI identity count must fail.
        self.assertEqual(self._run(len(_NAMES) + 1), 1)

    def test_extra_full_suite_counts(self):
        self._gui()
        self._write("test_other.py", "import unittest\nclass Other(unittest.TestCase):\n    def test_ok(self): pass\n")
        self.assertEqual(self._run(5), 0)

    def test_failing_non_gui_suite_denied(self):
        self._gui()
        self._write("test_other.py", "import unittest\nclass Other(unittest.TestCase):\n    def test_fail(self): self.fail('synthetic')\n")
        self.assertEqual(self._run(5), 1)

    def test_duplicate_gui_id_denied(self):
        self._gui()
        with (self.tests / "test_gui_shell.py").open("a", encoding="utf-8") as out:
            out.write("\ndef load_tests(loader, tests, pattern):\n"
                      "    tests.addTest(GuiShellSmokeTests('test_pages_and_navigation_are_consistent'))\n"
                      "    return tests\n")
        self.assertEqual(self._run(), 1)

    def test_duplicate_non_gui_id_denied(self):
        self._gui()
        self._write("test_other.py", "import unittest\n"
                    "class Other(unittest.TestCase):\n"
                    "    def test_ok(self): pass\n"
                    "def load_tests(loader, tests, pattern):\n"
                    "    tests.addTest(Other('test_ok'))\n"
                    "    return tests\n")
        self.assertEqual(self._run(5), 1)

    def test_skipped_non_gui_case_denied(self):
        self._gui()
        self._write("test_other.py", "import unittest\n"
                    "class Other(unittest.TestCase):\n"
                    "    @unittest.skip('synthetic skip')\n"
                    "    def test_skipped(self): pass\n")
        self.assertEqual(self._run(5), 1)

    def test_expected_failure_non_gui_case_denied(self):
        """An xfail must not turn a failing security assertion into CI success."""
        self._gui()
        self._write("test_other.py", "import unittest\n"
                    "class Other(unittest.TestCase):\n"
                    "    @unittest.expectedFailure\n"
                    "    def test_critical(self): self.fail('synthetic')\n")
        self.assertEqual(self._run(5, critical_non_gui_ids=(
            "test_other.Other.test_critical",)), 1)

    def test_critical_non_gui_case_present_passes(self):
        self._gui()
        self._write("test_other.py", "import unittest\n"
                    "class Other(unittest.TestCase):\n"
                    "    def test_critical(self): pass\n")
        self.assertEqual(self._run(5, critical_non_gui_ids=(
            "test_other.Other.test_critical",)), 0)

    def test_critical_non_gui_case_replaced_same_count_denied(self):
        """A compensating fake cannot replace a pinned non-GUI test ID."""
        self._gui()
        self._write("test_other.py", "import unittest\n"
                    "class Other(unittest.TestCase):\n"
                    "    def test_fake(self): pass\n")
        self.assertEqual(self._run(5, critical_non_gui_ids=(
            "test_other.Other.test_critical",)), 1)

    def test_load_tests_hook_drops_critical_non_gui_case_denied(self):
        """A load_tests hook can hide a real case without changing total count."""
        self._gui()
        self._write("test_other.py", "import unittest\n"
                    "class Other(unittest.TestCase):\n"
                    "    def test_critical(self): pass\n"
                    "    def test_fake(self): pass\n"
                    "def load_tests(loader, tests, pattern):\n"
                    "    return unittest.TestSuite([Other('test_fake')])\n")
        self.assertEqual(self._run(5, critical_non_gui_ids=(
            "test_other.Other.test_critical",)), 1)

    def test_non_gui_import_error_denied(self):
        self._gui()
        self._write("test_other.py", "raise ImportError('synthetic')\n")
        self.assertEqual(self._run(8), 1)


if __name__ == "__main__":
    unittest.main()
