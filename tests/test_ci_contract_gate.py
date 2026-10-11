"""Adversarial tests for the fail-closed CI runner itself (no real wallet)."""
from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.ci_contract_gate import (
    ContractGateError, MANDATORY_SUITES, MINIMUM_CASES, run_all, run_single,
)


class MandatoryOfflineContractGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wallet-ci-gate-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.pattern = "test_scaffold.py"

    def _with_suite(self, suite):
        class FakeLoader:
            errors = ()
            def discover(self, **_kwargs):
                return suite
        return patch("tools.ci_contract_gate.unittest.TestLoader", return_value=FakeLoader())
    
    def _fixture_floor(self):
        # Synthetic single-test suites model unrelated failure cases.
        return patch.dict(MINIMUM_CASES, {self.pattern: 1})

    def test_manifest_preserves_original_eight_and_self_test(self):
        self.assertEqual(len(MANDATORY_SUITES), 42)
        self.assertEqual(len(set(MANDATORY_SUITES)), len(MANDATORY_SUITES))
        self.assertIn("test_ci_contract_gate.py", MANDATORY_SUITES)
        self.assertIn("test_regtest_gateway.py", MANDATORY_SUITES)

    def test_missing_required_file_fails_closed(self):
        with self.assertRaisesRegex(ContractGateError, "^CI_REQUIRED_SUITE_MISSING"):
            run_single(self.pattern, self.folder)

    def test_existing_file_with_zero_tests_fails_closed(self):
        (self.folder / self.pattern).write_text("# empty suite\n", encoding="utf-8")
        with self._with_suite(unittest.TestSuite()):
            with self.assertRaisesRegex(ContractGateError, "^CI_REQUIRED_SUITE_EMPTY"):
                run_single(self.pattern, self.folder)

    def test_unknown_test_pattern_is_rejected(self):
        with self.assertRaisesRegex(ContractGateError, "^CI_UNKNOWN_REQUIRED_SUITE$"):
            run_single("test_random.py", self.folder)

    def test_failing_suite_fails_job(self):
        (self.folder / self.pattern).write_text("# synthetic suite\n", encoding="utf-8")
        def fail():
            raise AssertionError("synthetic failure")
        suite = unittest.TestSuite([unittest.FunctionTestCase(fail)])
        with self._with_suite(suite), self._fixture_floor(), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(ContractGateError, "^CI_REQUIRED_SUITE_FAILED"):
                run_single(self.pattern, self.folder)

    def test_passing_suite_is_counted(self):
        (self.folder / self.pattern).write_text("# synthetic suite\n", encoding="utf-8")
        suite = unittest.TestSuite([unittest.FunctionTestCase(lambda: None)])
        with self._with_suite(suite), self._fixture_floor(), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(run_single(self.pattern, self.folder), 1)

    def test_entirely_skipped_suite_fails_closed(self):
        (self.folder / self.pattern).write_text("# synthetic suite\n", encoding="utf-8")
        @unittest.skip("synthetic skip")
        class Skipped(unittest.TestCase):
            def test_skipped(self):
                pass
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Skipped)
        with self._with_suite(suite), self._fixture_floor(), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(ContractGateError, "^CI_REQUIRED_SUITE_ALL_SKIPPED"):
                run_single(self.pattern, self.folder)

    def test_expected_failure_is_not_accepted_as_success(self):
        """A failed security assertion marked xfail must fail the CI contract."""
        (self.folder / self.pattern).write_text("# synthetic suite\n", encoding="utf-8")
        class SyntheticExpectedFailure(unittest.TestCase):
            @unittest.expectedFailure
            def test_security_contract(self):
                self.fail("synthetic expected failure")
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(SyntheticExpectedFailure)
        with (self._with_suite(suite), self._fixture_floor(),
              contextlib.redirect_stderr(io.StringIO())):
            with self.assertRaisesRegex(
                ContractGateError, "^CI_REQUIRED_SUITE_EXPECTED_FAILURE:"
            ):
                run_single(self.pattern, self.folder)

    def test_unexpected_success_remains_denied(self):
        """An xfail that unexpectedly passes is already a failure in unittest."""
        (self.folder / self.pattern).write_text("# synthetic suite\n", encoding="utf-8")
        class SyntheticUnexpectedSuccess(unittest.TestCase):
            @unittest.expectedFailure
            def test_critical(self):
                self.assertTrue(True)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(SyntheticUnexpectedSuccess)
        with (self._with_suite(suite), self._fixture_floor(),
              contextlib.redirect_stderr(io.StringIO())):
            with self.assertRaisesRegex(ContractGateError, "^CI_REQUIRED_SUITE_FAILED:"):
                run_single(self.pattern, self.folder)

    def test_failing_subtest_remains_denied(self):
        """A subTest failure must not be hidden by a passing sibling."""
        (self.folder / self.pattern).write_text("# synthetic suite\n", encoding="utf-8")
        class SyntheticSubtest(unittest.TestCase):
            def test_multiple(self):
                with self.subTest(case="pass"):
                    self.assertTrue(True)
                with self.subTest(case="fail"):
                    self.assertTrue(False)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(SyntheticSubtest)
        with (self._with_suite(suite), self._fixture_floor(),
              contextlib.redirect_stderr(io.StringIO())):
            with self.assertRaisesRegex(ContractGateError, "^CI_REQUIRED_SUITE_FAILED:"):
                run_single(self.pattern, self.folder)

    def test_mixed_pass_and_expected_failure_is_denied(self):
        """A passing sibling cannot mask a failed expectedFailure case."""
        (self.folder / self.pattern).write_text("# synthetic suite\n", encoding="utf-8")
        class SyntheticMixed(unittest.TestCase):
            def test_pass(self):
                self.assertTrue(True)

            @unittest.expectedFailure
            def test_failed_but_expected(self):
                self.fail("synthetic failure")
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(SyntheticMixed)
        with (self._with_suite(suite), self._fixture_floor(),
              contextlib.redirect_stderr(io.StringIO())):
            with self.assertRaisesRegex(
                ContractGateError, "^CI_REQUIRED_SUITE_EXPECTED_FAILURE:"
            ):
                run_single(self.pattern, self.folder)

    def test_minimum_case_floors_pinned_for_all_mandatory_suites(self):
        expected = {
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
            "test_regtest_scanner_wire.py": 19,
            "test_core_artifact_staging.py": 20,
            "test_core_candidate_bridge.py": 14,
            "test_core_signed_release.py": 20,
            "test_core_archive_inventory.py": 23,
            "test_verify_core_release_offline.py": 12,
            "test_probe_existing_regtest.py": 13,
            "test_probe_two_node_regtest.py": 21,
            "test_core_official_metadata.py": 18,
        }
        self.assertEqual(MINIMUM_CASES, expected)
        self.assertEqual(MANDATORY_SUITES, tuple(expected))

    def test_nonempty_suite_below_original_count_fails_closed(self):
        (self.folder / self.pattern).write_text("# synthetic test\n", encoding="utf-8")
        suite = unittest.TestSuite([unittest.FunctionTestCase(lambda: None)])
        with self._with_suite(suite):
            with self.assertRaisesRegex(
                ContractGateError, "^CI_REQUIRED_SUITE_BELOW_BASELINE:"
            ):
                run_single(self.pattern, self.folder)

    def test_other_suites_still_run_after_one_failure(self):
        class Result:
            def __init__(self, code):
                self.returncode = code
        called = []
        def fake_subprocess(argv, **_kwargs):
            called.append(argv[-1])
            return Result(1 if argv[-1] == self.pattern else 0)
        with patch("tools.ci_contract_gate.subprocess.run", side_effect=fake_subprocess):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(run_all(), 1)
        self.assertEqual(tuple(called), MANDATORY_SUITES)


if __name__ == "__main__":
    unittest.main()
