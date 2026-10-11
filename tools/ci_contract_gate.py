"""Fail-closed, dependency-free runner for mandatory wallet offline CI suites.

Each suite executes in a fresh Python interpreter, as in the original CI.
This is not a wallet-security or release qualification by itself.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
# Baseline test-count floors measured on all four PR #26 CI platforms.
# These protect against accidental shrinking of a named test module.
MINIMUM_CASES = {
    "test_scaffold.py": 5,
    "test_core_profile.py": 9,
    "test_core_source_pin.py": 10,
    "test_node_contract.py": 7,
    "test_read_rpc.py": 11,
    "test_real_regtest_harness.py": 13,
    "test_regtest_attestation.py": 10,
    "test_regtest_gateway.py": 10,
    "test_reuse_manifest.py": 6,
    "test_app_diagnostic_boundary.py": 5,
    "test_security_gate_ledger.py": 6,
    "test_regtest_artifact_preflight.py": 10,
    "test_two_node_topology.py": 12,
    "test_two_node_policy.py": 19,
    "test_two_node_schema.py": 18,
    "test_provenance_intake.py": 13,
    "test_rpc_qualification_prep.py": 13,
    "test_reorg_qualification_prep.py": 13,
    "test_ci_contract_gate.py": 14,
    "test_gui_ci_contract_gate.py": 20,
    "test_app_privacy_readiness.py": 8,
    "test_app_policy_evidence.py": 12,
    "test_app_synthetic_policy_demo.py": 8,
    "test_app_receive_public_vector.py": 12,
    "test_app_presentation_lifecycle.py": 10,
    "test_scanner_response_shape.py": 14,
    "test_scanner_window_contract.py": 19,
    "test_offline_recovery_disposition.py": 18,
    "test_offline_recovery_transition.py": 16,
    "test_offline_resume_review.py": 19,
    "test_offline_rescan_segments.py": 23,
    "test_offline_reorg_reconciliation.py": 24,
    "test_offline_integration_status.py": 31,
    "test_regtest_scanner_wire.py": 15,
    "test_core_artifact_staging.py": 20,
    "test_core_candidate_bridge.py": 14,
    "test_core_signed_release.py": 20,
    "test_core_archive_inventory.py": 23,
    "test_verify_core_release_offline.py": 12,
}
MANDATORY_SUITES = tuple(MINIMUM_CASES)


class ContractGateError(Exception):
    """A mandatory test target was not found, was empty or did not pass."""


def run_single(pattern: str, test_dir: Path) -> int:
    """Run exactly one required suite; reject missing and empty discovery."""
    if pattern not in MANDATORY_SUITES:
        raise ContractGateError("CI_UNKNOWN_REQUIRED_SUITE")
    if not (test_dir / pattern).is_file():
        raise ContractGateError(f"CI_REQUIRED_SUITE_MISSING: {pattern}")
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(test_dir), pattern=pattern)
    count = suite.countTestCases()
    if count == 0:
        raise ContractGateError(f"CI_REQUIRED_SUITE_EMPTY: {pattern}")
    minimum = MINIMUM_CASES[pattern]
    if count < minimum:
        raise ContractGateError(
            f"CI_REQUIRED_SUITE_BELOW_BASELINE: {pattern}: {count} < {minimum}"
        )
    print(f"CI_DISCOVERED_TESTS: {pattern}: {count} (minimum {minimum})", flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or loader.errors:
        raise ContractGateError(f"CI_REQUIRED_SUITE_FAILED: {pattern}")
    # unittest reports a failing @expectedFailure case as successful.
    # A mandatory offline contract must never pass on an expected failure.
    if result.expectedFailures:
        raise ContractGateError(f"CI_REQUIRED_SUITE_EXPECTED_FAILURE: {pattern}")
    if result.testsRun <= len(result.skipped):
        raise ContractGateError(f"CI_REQUIRED_SUITE_ALL_SKIPPED: {pattern}")
    return count


def run_all() -> int:
    failures: list[str] = []
    total = 0
    for pattern in MANDATORY_SUITES:
        print(f"::group::Mandatory offline suite: {pattern}", flush=True)
        result = subprocess.run(
            [sys.executable, "-m", "tools.ci_contract_gate", "--single", pattern],
            cwd=ROOT,
            check=False,
        )
        print("::endgroup::", flush=True)
        if result.returncode:
            failures.append(pattern)
        else:
            total += 1
    if failures:
        print("CI_FAILED_REQUIRED_SUITES: " + ", ".join(failures), file=sys.stderr)
        return 1
    print(f"CI_ALL_REQUIRED_SUITES_PASSED: {total}/{len(MANDATORY_SUITES)}", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mandatory fail-closed CI suites")
    parser.add_argument("--single", choices=MANDATORY_SUITES)
    args = parser.parse_args(argv)
    if args.single is None:
        return run_all()
    try:
        run_single(args.single, ROOT / "tests")
    except ContractGateError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
