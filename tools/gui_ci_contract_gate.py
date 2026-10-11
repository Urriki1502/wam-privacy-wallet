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
})
# Security-critical original non-GUI identities; additive to original suite floors.
CRITICAL_NON_GUI_IDS = frozenset({
    "test_real_regtest_harness.HarnessTests.test_digest_mismatch_cannot_spawn",
    "test_real_regtest_harness.HarnessTests.test_verified_binary_still_cannot_spawn_before_binding_review",
    "test_real_regtest_harness.HarnessTests.test_launch_gate_precedes_workspace_creation_and_socket_bind",
    "test_core_artifact_staging.CoreArtifactStagingTests.test_verified_synthetic_snapshot_never_authorizes_core_execution",
    "test_core_artifact_staging.CoreArtifactStagingTests.test_postcopy_metadata_race_rejected",
    "test_core_artifact_staging.CoreArtifactStagingTests.test_same_size_staged_byte_mutation_during_review_is_detected",
    "test_core_artifact_staging.CoreArtifactStagingTests.test_windows_reparse_file_metadata_is_denied_even_if_regular",
    "test_core_candidate_bridge.CoreCandidateBridgeTests.test_wrong_native_platform_is_denied_before_disk_read",
    "test_core_candidate_bridge.CoreCandidateBridgeTests.test_staged_candidate_requires_identical_host_and_bytes",
    "test_core_candidate_bridge.CoreCandidateBridgeTests.test_staged_mutation_on_context_exit_is_denied_with_redacted_code",
    "test_core_signed_release.CoreSignedReleaseTests.test_valid_signature_contract_is_still_archive_only_and_no_core_launch",
    "test_core_signed_release.CoreSignedReleaseTests.test_gpg_listed_primary_key_must_match_fixed_fingerprint",
    "test_core_signed_release.CoreSignedReleaseTests.test_unsigned_checksums_are_never_acceptance_evidence",
    "test_core_signed_release.CoreSignedReleaseTests.test_post_signature_archive_digest_mismatch_denied",
    "test_core_signed_release.CoreSignedReleaseTests.test_gpg_invocation_never_uses_shell_or_user_gnupghome",
    "test_core_archive_inventory.CoreArchiveInventoryTests.test_linux_tar_contains_readonly_node_hash_and_counts",
    "test_core_archive_inventory.CoreArchiveInventoryTests.test_reject_tar_symlink_and_hardlink",
    "test_core_archive_inventory.CoreArchiveInventoryTests.test_reject_zip_unix_symlink",
    "test_core_archive_inventory.CoreArchiveInventoryTests.test_zip_compression_ratio_denies_bomb",
    "test_core_archive_inventory.CoreArchiveInventoryTests.test_bogus_archive_digest_denied_before_container_inspection",
    "test_core_archive_inventory.CoreArchiveInventoryTests.test_no_extraction_file_creation_process_or_sockets",
    "test_regtest_artifact_preflight.RegtestBinaryArtifactPreflightTests.test_matching_synthetic_file_never_counts_as_real_node",
    "test_two_node_schema.ParallelTwoNodeSchemaTests.test_schema_version_is_exact_one_and_no_execution_authority",
    "test_security_gate_ledger.SecurityGateLedgerTests.test_cannot_auto_promote_global_authority",
    "test_rpc_qualification_prep.RpcQualificationPreparationTests.test_fake_approval_release_or_core_execution_denied",
    "test_ci_contract_gate.MandatoryOfflineContractGateTests.test_minimum_case_floors_pinned_for_all_mandatory_suites",
})
# Existing 267-case GUI baseline + 12 public-vector tests + 5 Receive GUI tests.
FULL_MIN_CASES = 364


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
