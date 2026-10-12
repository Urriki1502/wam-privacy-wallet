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
    "test_gui_shell.GuiShellSmokeTests.test_reentrant_clear_during_render_cannot_survive_swallowed_error",
    "test_gui_shell.GuiShellSmokeTests.test_reentrant_replace_during_clear_poisoned_even_when_callback_catches",
    "test_gui_shell.GuiShellSmokeTests.test_reentrant_replace_during_explicit_clear_stays_blocked_then_recovers",
    "test_gui_shell.GuiShellSmokeTests.test_lifecycle_clear_failure_invalidates_revision_and_other_panels",
    "test_gui_shell.GuiShellSmokeTests.test_reset_clear_failure_attempts_all_panels_and_stays_blocked",
    "test_gui_shell.GuiShellSmokeTests.test_recovery_page_has_no_backup_restore_or_signing_actions",
    "test_gui_shell.GuiShellSmokeTests.test_recovery_forged_authority_or_reason_is_denied",
    "test_gui_shell.GuiShellSmokeTests.test_recovery_clear_and_stale_revision_rejects_prior_evidence",
    "test_gui_shell.GuiShellSmokeTests.test_recovery_render_fault_invalidates_managed_revision",
    "test_gui_shell.GuiShellSmokeTests.test_resume_panel_starts_blocked_with_no_user_actions",
    "test_gui_shell.GuiShellSmokeTests.test_resume_forged_claims_rejected_without_changing_display",
    "test_gui_shell.GuiShellSmokeTests.test_resume_clear_invalidates_old_revision_and_evidence",
    "test_gui_shell.GuiShellSmokeTests.test_resume_renderer_fault_resets_and_redacts_without_privilege",
    "test_gui_shell.GuiShellSmokeTests.test_rescan_segments_gui_starts_disabled_without_buttons",
    "test_gui_shell.GuiShellSmokeTests.test_rescan_segment_forged_authority_or_counts_are_denied",
    "test_gui_shell.GuiShellSmokeTests.test_segment_review_same_writer_and_direct_clear",
    "test_gui_shell.GuiShellSmokeTests.test_rescan_segment_renderer_failure_resets_and_redacts",
    "test_gui_shell.GuiShellSmokeTests.test_reorg_panel_defaults_to_no_evidence_and_no_actions",
    "test_gui_shell.GuiShellSmokeTests.test_reorg_forged_counts_or_authority_are_rejected",
    "test_gui_shell.GuiShellSmokeTests.test_reorg_atomic_recovery_resume_rescan_and_clear",
    "test_gui_shell.GuiShellSmokeTests.test_reorg_renderer_fault_redacts_and_invalidates_revision",
    "test_gui_shell.GuiShellSmokeTests.test_legacy_presenter_replaces_managed_snapshot_atomically",
    "test_gui_shell.GuiShellSmokeTests.test_legacy_clear_invalidates_all_panels_and_prior_revision",
    "test_gui_shell.GuiShellSmokeTests.test_legacy_invalid_input_does_not_mutate_accepted_state",
    "test_gui_shell.GuiShellSmokeTests.test_legacy_demo_routes_through_controller_single_writer",
})
# Security-critical original non-GUI identities; additive to original suite floors.
CRITICAL_NON_GUI_IDS = frozenset({
    "test_binary_path_race_preflight.BinaryPathRacePreflightTests.test_custom_fspath_cannot_execute_hooks",
    "test_binary_path_race_preflight.BinaryPathRacePreflightTests.test_hardlinked_binary_denied_even_with_correct_digest",
    "test_binary_path_race_preflight.BinaryPathRacePreflightTests.test_relative_path_denied_before_filesystem_access",
    "test_binary_path_race_preflight.BinaryPathRacePreflightTests.test_same_bytes_path_replaced_during_resolve_is_rejected",
    "test_binary_path_race_preflight.BinaryPathRacePreflightTests.test_path_deleted_during_resolve_cannot_qualify",
    "test_two_node_ancestry_cli.BoundedAncestryCliTests.test_p2p_opt_in_reuses_two_prompted_credentials_only",
    "test_two_node_ancestry_cli.BoundedAncestryCliTests.test_p2p_forged_authority_extra_keys_and_counts_denied",
    "test_two_node_ancestry_cli.BoundedAncestryCliTests.test_p2p_port_collisions_fail_before_secrets_or_rpc",
    "test_two_node_ancestry_cli.BoundedAncestryCliTests.test_optional_header_review_reuses_one_tty_prompt_pair",
    "test_two_node_ancestry_cli.BoundedAncestryCliTests.test_header_forged_authority_and_missing_flags_denied",
    "test_two_node_ancestry_cli.BoundedAncestryCliTests.test_header_height_window_epoch_mismatch_is_denied",
    "test_two_node_ancestry_cli.BoundedAncestryCliTests.test_secret_bearing_extra_ancestry_fields_are_refused",
    "test_two_node_ancestry_cli.BoundedAncestryCliTests.test_header_extra_fields_or_fake_pass_count_denied",
    "test_two_node_readiness.TwoNodeReadinessTests.test_all_claimed_evidence_still_cannot_grant_authority",
    "test_two_node_readiness.TwoNodeReadinessTests.test_readiness_never_launches_core",
    "test_binary_path_race_preflight.BinaryPathRacePreflightTests.test_path_replacement_during_open_is_rejected",
    "test_binary_path_race_preflight.BinaryPathRacePreflightTests.test_launcher_remains_interlocked_even_with_correct_digest",
    "test_two_node_p2p_readonly.TwoNodeP2PRealTcpTests.test_both_genuine_localhost_sockets_receive_p2p_methods",
    "test_two_node_p2p_readonly.TwoNodeP2PRealTcpTests.test_remote_peer_address_denied",
    "test_two_node_p2p_readonly.TwoNodeP2PRealTcpTests.test_no_core_subprocess_network_reconfiguration_or_wallet_file",
    "test_regtest_scanner_wire.RegtestScannerReadBridgeTests.test_parent_hash_change_with_stable_tip_is_denied",
    "test_regtest_scanner_wire.RegtestScannerReadBridgeTests.test_mismatched_external_parent_denied_before_block_read",
    "test_probe_existing_regtest.ExistingRegtestCliTests.test_block_height_only_fetches_parent_directly_over_node_rpc",
    "test_probe_two_node_regtest.TwoNodeRegtestWireTests.test_same_tip_different_parent_rejected_across_nodes",
    "test_probe_two_node_regtest.TwoNodeRegtestWireTests.test_same_tip_parent_reorg_mid_block_denied",
    "test_core_source_pin.CorePinTests.test_bip94_wrong_regtest_even_with_rewritten_blob_pin_is_denied",
    "test_core_source_pin.CorePinTests.test_bip94_manifest_forgery_denied",
    "test_core_signed_linux_memfd.SignedLinuxCoreMemfdTests.test_real_kernel_memfd_has_no_execute_bits_and_signed_byte_hash",
    "test_core_signed_linux_memfd.SignedLinuxCoreMemfdTests.test_signature_error_fails_before_inventory_or_memfd",
    "test_core_linux_sealed_snapshot.LinuxKernelSealedRegtestTests.test_kernel_denies_write_after_seals",
    "test_core_linux_sealed_snapshot.LinuxKernelSealedRegtestTests.test_no_operational_or_publisher_authority_even_when_sealed",
    "test_core_official_metadata.OfficialMetadataHttpsTests.test_no_http_redirects_or_untrusted_origin_fallback",
    "test_core_official_metadata.OfficialReleaseCliTests.test_fake_gpg_success_claim_cannot_enable_core_execution",
    "test_probe_two_node_regtest.TwoNodeRegtestWireTests.test_both_endpoints_actually_receive_separate_http_rpc",
    "test_probe_two_node_regtest.TwoNodeRegtestWireTests.test_no_core_process_launch_during_real_socket_observation",
    "test_probe_existing_regtest.ExistingRegtestCliTests.test_actual_loopback_mempool_wire_has_no_mock_transport_hook",
    "test_probe_existing_regtest.ExistingRegtestCliTests.test_process_launch_forbidden_even_on_successful_wire_read",
    "test_verify_core_release_offline.OfficialReleaseReviewCliTests.test_cli_success_is_non_authorizing_json_and_no_core_spawn",
    "test_verify_core_release_offline.OfficialReleaseReviewCliTests.test_forced_execution_claim_is_always_rejected",
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
    "test_offline_recovery_transition.OfflineRecoveryTransitionTests.test_legacy_version_two_to_three_does_not_prove_rescan",
    "test_offline_recovery_transition.OfflineRecoveryTransitionTests.test_downgrade_to_legacy_is_fail_closed",
    "test_offline_recovery_transition.OfflineRecoveryTransitionTests.test_no_file_socket_subprocess_or_wsp_imports",
    "test_offline_resume_review.OfflineResumeReviewTests.test_matching_crash_never_auto_resumes",
    "test_offline_resume_review.OfflineResumeReviewTests.test_legacy_to_v3_never_proves_migration",
    "test_offline_resume_review.OfflineResumeReviewTests.test_no_file_socket_process_or_wsp_imports",
    "test_offline_rescan_segments.OfflineRescanSegmentsTests.test_exact_immediate_replay_does_not_double_count",
    "test_offline_rescan_segments.OfflineRescanSegmentsTests.test_hash_identity_cannot_cycle_back_to_earlier_anchor",
    "test_offline_rescan_segments.OfflineRescanSegmentsTests.test_output_immutable_no_sensitive_values_or_io",
    "test_offline_reorg_reconciliation.OfflineReorgReconciliationTests.test_checkpoint_mismatch_across_receipts_denied",
    "test_offline_reorg_reconciliation.OfflineReorgReconciliationTests.test_metamorphic_immediate_replay_never_increases_unique_work",
    "test_offline_reorg_reconciliation.OfflineReorgReconciliationTests.test_no_file_socket_subprocess_or_operational_wsp_imports",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_all_three_synthetic_evidence_types_never_make_a_wallet",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_in_place_scan_authority_forgery_denied",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_in_place_storage_writer_claim_denied",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_no_network_file_subprocess_or_operational_engine",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_cleared_state_cannot_retain_recovery_preview",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_conflicting_storage_and_presentation_recovery_denied",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_rejected_or_cleared_presentation_cannot_retain_resume",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_resume_only_research_panel_cannot_authorize_scanning",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_rescan_segment_only_research_state_cannot_grant_scanner",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_clear_state_with_stale_rescan_preview_is_denied",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_reorg_reconciliation_only_remains_untrusted",
    "test_regtest_scanner_wire.RegtestScannerReadBridgeTests.test_real_loopback_http_fetches_block_without_mock_callback",
    "test_regtest_scanner_wire.RegtestScannerReadBridgeTests.test_reorg_during_block_rpc_denied_after_read",
    "test_regtest_scanner_wire.RegtestScannerReadBridgeTests.test_live_transport_does_not_launch_core_or_load_wsp",
    "test_offline_integration_status.OfflineIntegrationStatusTests.test_mismatched_reorg_segment_or_recovery_fails_atomic_replacement",
    "test_regtest_cookie_descriptor.RegtestCookieDescriptorTests.test_exact_terminal_crlf_is_accepted_but_internal_crlf_denied",
    "test_regtest_cookie_descriptor.RegtestCookieDescriptorTests.test_swap_between_lstat_and_fd_open_is_rejected",
    "test_read_rpc.LocalReadOnlyRpcTests.test_header_invalid_hash_or_verbosity_fails_without_network",
    "test_two_node_header_links.TwoNodeHeaderLinkWireTests.test_independent_real_tcp_header_rpc_double_pass",
    "test_two_node_header_links.TwoNodeHeaderLinkWireTests.test_misreported_header_parent_rejected_even_if_both_nodes_agree",
    "test_two_node_header_links.TwoNodeHeaderLinkWireTests.test_output_redacted_non_authorizing_and_no_executable",
    "test_two_node_ancestry_cli.BoundedAncestryCliTests.test_forged_true_authority_is_redacted_and_denied",
    "test_two_node_ancestry_cli.BoundedAncestryCliTests.test_missing_or_malformed_review_receipt_is_refused",
    "test_two_node_ancestry_cli.BoundedAncestryCliTests.test_noninteractive_stdio_is_denied_no_secret_prompts",
    "test_two_node_ancestry_cli.BoundedAncestryCliTests.test_rpc_denial_does_not_leak_password_or_remote_error",
    "test_two_node_ancestry_cli.BoundedAncestryCliTests.test_live_cli_boundary_never_launches_core",
    "test_two_node_bounded_ancestry.TwoNodeBoundedAncestryWireTests.test_actual_two_distinct_tcp_hosts_audit_three_heights_twice",
    "test_two_node_bounded_ancestry.TwoNodeBoundedAncestryWireTests.test_same_reported_tip_but_different_interior_height_denied",
    "test_two_node_bounded_ancestry.TwoNodeBoundedAncestryWireTests.test_silent_interior_mutation_between_two_passes_is_denied",
    "test_two_node_bounded_ancestry.TwoNodeBoundedAncestryWireTests.test_never_calls_wam_core_subprocess_on_real_localhost_http",
    "test_two_node_live_transition.TwoNodeLiveTransitionWireTests.test_higher_tip_with_rewritten_old_height_is_reorg",
    "test_two_node_live_transition.TwoNodeLiveTransitionWireTests.test_two_real_independent_localhost_sockets_report_unchanged",
    "test_two_node_live_transition.TwoNodeLiveTransitionWireTests.test_no_core_subprocess_on_successful_live_http_observation",
    "test_two_node_private_workspace.PrivateTwoNodeWorkspaceTests.test_caller_valueerror_propagates_and_workspace_is_deleted",
    "test_two_node_private_workspace.PrivateTwoNodeWorkspaceTests.test_real_temp_workspace_has_two_distinct_dirs_and_configs",
    "test_two_node_private_workspace.PrivateTwoNodeWorkspaceTests.test_windows_unreviewed_acl_denied_without_disk",
    "test_regtest_cookie_descriptor.RegtestCookieDescriptorTests.test_swap_after_same_fd_read_is_rejected",
    "test_regtest_cookie_descriptor.RegtestCookieDescriptorTests.test_windows_reparse_attribute_denied_even_when_regular_metadata",
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
})
# Full floor: original 284 + App 19 + Core 3 + Reply 14 + Window 18 + Recovery 18 + cross-module 20.
FULL_MIN_CASES = 833


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
