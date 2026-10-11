"""Fail-closed offline GUI discovery gate. No Core binary, node, or network."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
GUI_PATTERN = "test_gui_shell.py"
GUI_TEST_IDS = frozenset({
    "test_gui_shell.GuiShellSmokeTests.test_pages_and_navigation_are_consistent",
    "test_gui_shell.GuiShellSmokeTests.test_offline_safety_notice_and_no_funds_state",
    "test_gui_shell.GuiShellSmokeTests.test_no_payment_actions_are_exposed",
    "test_gui_shell.GuiShellSmokeTests.test_window_is_portable_qt_widget",
    "test_gui_shell.GuiShellSmokeTests.test_lifecycle_valid_then_invalid_clears_all_panels",
    "test_gui_shell.GuiShellSmokeTests.test_lifecycle_stale_revision_clears_receive_and_node",
    "test_gui_shell.GuiShellSmokeTests.test_lifecycle_reset_invalidates_revision_and_all_panels",
    "test_gui_shell.GuiShellSmokeTests.test_lifecycle_replacement_does_not_retain_omitted_evidence",
    "test_gui_shell.GuiShellSmokeTests.test_lifecycle_render_failure_clears_and_invalidates",
    "test_gui_shell.GuiShellSmokeTests.test_legacy_presenter_replaces_managed_snapshot_atomically",
    "test_gui_shell.GuiShellSmokeTests.test_legacy_clear_invalidates_all_panels_and_prior_revision",
    "test_gui_shell.GuiShellSmokeTests.test_legacy_invalid_input_does_not_mutate_accepted_state",
    "test_gui_shell.GuiShellSmokeTests.test_legacy_demo_routes_through_controller_single_writer",
})
# Security-critical original non-GUI identities; additive to original suite floors.
CRITICAL_NON_GUI_IDS = frozenset({
    "test_real_regtest_harness.HarnessTests.test_digest_mismatch_cannot_spawn",
    "test_regtest_artifact_preflight.RegtestBinaryArtifactPreflightTests.test_matching_synthetic_file_never_counts_as_real_node",
    "test_two_node_schema.ParallelTwoNodeSchemaTests.test_schema_version_is_exact_one_and_no_execution_authority",
    "test_security_gate_ledger.SecurityGateLedgerTests.test_cannot_auto_promote_global_authority",
    "test_rpc_qualification_prep.RpcQualificationPreparationTests.test_fake_approval_release_or_core_execution_denied",
    "test_ci_contract_gate.MandatoryOfflineContractGateTests.test_minimum_case_floors_pinned_for_all_mandatory_suites",
    "test_scanner_response_shape.ScannerResponseShapeTests.test_no_files_sockets_subprocess_or_wsp_imports",
    "test_scanner_response_shape.ScannerResponseShapeTests.test_wrong_hash_or_previous_hash_or_height_rejected",
    "test_scanner_window_contract.OfflineScanWindowTests.test_changing_reported_tip_denied",
    "test_scanner_window_contract.OfflineScanWindowTests.test_immutable_summary_and_no_io_or_wsp_imports",
    "test_offline_recovery_disposition.OfflineRecoveryDispositionTests.test_no_caller_can_claim_verified_writer_identity_or_integrity",
    "test_offline_recovery_disposition.OfflineRecoveryDispositionTests.test_readonly_policy_never_uses_file_socket_or_subprocess",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_all_three_synthetic_evidence_types_never_make_a_wallet",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_in_place_scan_authority_forgery_denied",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_in_place_storage_writer_claim_denied",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_no_network_file_subprocess_or_operational_engine",
})
# Full floor: original 284 + App 19 + Core 3 + Reply 14 + Window 18 + Recovery 18 + cross-module 18.
FULL_MIN_CASES = 374


def _cases(suite: unittest.TestSuite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _cases(item)
        else:
            yield item


def _discovery(test_dir: Path, pattern: str):
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(test_dir), pattern=pattern)
    cases = list(_cases(suite))
    ids = [case.id() for case in cases]
    return loader, suite, ids


def check_and_run(
    test_dir: Path, *, full_minimum: int = FULL_MIN_CASES,
    critical_non_gui_ids: frozenset[str] = CRITICAL_NON_GUI_IDS,
) -> int:
    """Pin GUI identities and full count; reject skips, failures and import errors."""
    if not (test_dir / GUI_PATTERN).is_file():
        print("CI_GUI_SUITE_MISSING", file=sys.stderr)
        return 1
    gui_loader, _, gui_ids = _discovery(test_dir, GUI_PATTERN)
    if (gui_loader.errors or len(gui_ids) < len(GUI_TEST_IDS)
            or len(gui_ids) != len(set(gui_ids))
            or not GUI_TEST_IDS.issubset(gui_ids)):
        print("CI_GUI_REQUIRED_CASES_MISSING_OR_DUPLICATE", file=sys.stderr)
        return 1
    full_loader, full_suite, full_ids = _discovery(test_dir, "test*.py")
    if (full_loader.errors or len(full_ids) < full_minimum
            or len(full_ids) != len(set(full_ids))
            or not set(gui_ids).issubset(full_ids)
            or not critical_non_gui_ids.issubset(full_ids)):
        print("CI_GUI_FULL_DISCOVERY_INCOMPLETE", file=sys.stderr)
        return 1
    print(f"CI_GUI_DISCOVERY: GUI={len(gui_ids)}, FULL={len(full_ids)}, MIN={full_minimum}", flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(full_suite)
    if not result.wasSuccessful() or result.testsRun != len(full_ids):
        print("CI_GUI_FULL_SUITE_FAILED", file=sys.stderr)
        return 1
    if result.skipped:
        print("CI_GUI_FULL_DISCOVERY_SKIPPED_CASE", file=sys.stderr)
        return 1
    if result.expectedFailures:
        print("CI_GUI_FULL_DISCOVERY_EXPECTED_FAILURE", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    return check_and_run(ROOT / "tests")


if __name__ == "__main__":
    raise SystemExit(main())
