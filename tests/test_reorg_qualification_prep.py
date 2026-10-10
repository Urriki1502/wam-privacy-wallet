"""G1-05 offline readiness cases, NEVER real-chain assertions."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
import socket
import subprocess
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node.reorg_qualification_prep import (
    REORG_CASES, ReorgQualificationPrepError, prepare_reorg_qualification,
)


def fixture():
    return {
        "schema": "g1-05-reorg-qualification-prep/v1",
        "case_expectations": dict(REORG_CASES),
        "real_rpc_qualified": False,
        "real_two_node_executed": False,
        "upstream_lock_reviewed": False,
        "scanner_security_reviewed": False,
        "release_allowed": False,
    }


class ReorgQualificationPreparationTests(unittest.TestCase):
    def test_canonical_inventory_is_complete_and_blocked(self):
        p = prepare_reorg_qualification(fixture())
        self.assertEqual(len(p.cases), 10)
        self.assertEqual(tuple(x.case_id for x in p.cases), tuple(k for k, _ in REORG_CASES))
        self.assertTrue(all(x.status == "BLOCKED_NO_REAL_REORG_EVIDENCE" for x in p.cases))

    def test_release_and_scanner_authority_not_granted(self):
        p = prepare_reorg_qualification(fixture())
        self.assertEqual(p.status, "BLOCKED_G1_04_AND_UPSTREAM_REVIEW")
        for field in ("real_rpc_qualified", "real_two_node_executed",
                      "upstream_lock_reviewed", "scanner_security_reviewed",
                      "signing_enabled", "broadcast_enabled", "release_allowed"):
            self.assertIs(getattr(p, field), False)

    def test_missing_fields_and_extra_keys_rejected(self):
        for value in (None, [], True, "", {}, dict(fixture(), new_field=True)):
            with self.subTest(value=repr(value)), self.assertRaisesRegex(
                ReorgQualificationPrepError, "^G1_REORG_PREP_SCHEMA_REJECTED$"
            ):
                prepare_reorg_qualification(value)
        for key in fixture():
            p = fixture()
            del p[key]
            with self.subTest(key=key), self.assertRaises(ReorgQualificationPrepError):
                prepare_reorg_qualification(p)

    def test_invalid_schema_version_rejected(self):
        for version in (None, True, 1, "g1-05-reorg-qualification-prep/v2"):
            p = fixture()
            p["schema"] = version
            with self.subTest(version=version), self.assertRaises(ReorgQualificationPrepError):
                prepare_reorg_qualification(p)

    def test_absent_scenario_never_silent_pass(self):
        for case, _ in REORG_CASES:
            p = fixture()
            del p["case_expectations"][case]
            with self.subTest(case=case), self.assertRaisesRegex(
                ReorgQualificationPrepError, "^G1_REORG_PREP_CASES_REJECTED$"
            ):
                prepare_reorg_qualification(p)

    def test_wrong_result_and_unlisted_method_denied(self):
        for case, _ in REORG_CASES:
            p = fixture()
            p["case_expectations"][case] = "PASS"
            with self.subTest(case=case), self.assertRaises(ReorgQualificationPrepError):
                prepare_reorg_qualification(p)
        p = fixture()
        p["case_expectations"]["REMOTE_SCANNER_FALLBACK"] = "ALLOW"
        with self.assertRaises(ReorgQualificationPrepError):
            prepare_reorg_qualification(p)

    def test_invalid_case_collections_rejected(self):
        for cases in ([], None, (), True, {1: "DENY"}, "all passed"):
            p = fixture()
            p["case_expectations"] = cases
            with self.subTest(cases=repr(cases)), self.assertRaises(ReorgQualificationPrepError):
                prepare_reorg_qualification(p)

    def test_fake_core_lease_or_release_approval_denied(self):
        for key in ("real_rpc_qualified", "real_two_node_executed",
                    "upstream_lock_reviewed", "scanner_security_reviewed",
                    "release_allowed"):
            for value in (True, 0, "false", None):
                p = fixture()
                p[key] = value
                with self.subTest(key=key, value=value), self.assertRaisesRegex(
                    ReorgQualificationPrepError, "^G1_REORG_PREP_AUTHORITY_REJECTED$"
                ):
                    prepare_reorg_qualification(p)

    def test_plan_and_cases_are_frozen_without_keys(self):
        p = prepare_reorg_qualification(fixture())
        with self.assertRaises(FrozenInstanceError):
            p.release_allowed = True
        with self.assertRaises(FrozenInstanceError):
            p.cases[0].status = "PASS"
        names = {f.name for f in fields(p)}
        self.assertFalse(names.intersection({"rpc", "wallet", "secret", "signer",
                                             "credentials", "broadcast_method"}))

    def test_pure_planning_never_executes_scans_or_network(self):
        with patch("builtins.open", side_effect=AssertionError("NO FILE")), \
             patch.object(socket, "socket", side_effect=AssertionError("NO SOCKET")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("NO EXEC")):
            p = prepare_reorg_qualification(fixture())
        self.assertEqual(p.status, "BLOCKED_G1_04_AND_UPSTREAM_REVIEW")


if __name__ == "__main__":
    unittest.main()
