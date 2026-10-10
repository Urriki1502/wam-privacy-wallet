"""G1-04 offline readiness: a case inventory cannot impersonate live RPC."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
import socket
import subprocess
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node.rpc_qualification_prep import (
    RPC_CASES, RpcQualificationPrepError, prepare_rpc_qualification,
)


def fixture():
    return {
        "schema": "g1-04-rpc-qualification-prep/v1",
        "case_expectations": dict(RPC_CASES),
        "publisher_identity_verified": False,
        "isolated_runner_verified": False,
        "live_core_executed": False,
        "release_allowed": False,
    }


class RpcQualificationPreparationTests(unittest.TestCase):
    def test_full_inventory_stays_blocked(self):
        plan = prepare_rpc_qualification(fixture())
        self.assertEqual(len(plan.cases), 10)
        self.assertEqual(tuple(c.case_id for c in plan.cases),
                         tuple(k for k, _ in RPC_CASES))
        self.assertTrue(all(c.status == "BLOCKED_NO_REAL_CORE_EVIDENCE"
                            for c in plan.cases))

    def test_qualification_and_wallet_permissions_never_granted(self):
        plan = prepare_rpc_qualification(fixture())
        self.assertEqual(plan.status, "BLOCKED_VERIFIED_BINARY_AND_ISOLATED_RUNNER")
        for field in ("publisher_identity_verified", "isolated_runner_verified",
                      "live_core_executed", "scanner_enabled", "signer_enabled",
                      "release_allowed"):
            self.assertIs(getattr(plan, field), False)

    def test_absent_extra_or_non_mapping_fields_rejected(self):
        for bad in (None, {}, [], True, "rpc", dict(fixture(), extra=True)):
            with self.subTest(bad=repr(bad)), self.assertRaisesRegex(
                RpcQualificationPrepError, "^G1_RPC_PREP_SCHEMA_REJECTED$"
            ):
                prepare_rpc_qualification(bad)
        for key in fixture():
            p = fixture()
            del p[key]
            with self.subTest(missing=key), self.assertRaises(RpcQualificationPrepError):
                prepare_rpc_qualification(p)

    def test_schema_drift_rejected(self):
        for schema in ("g1-04-rpc-qualification-prep/v2", None, True, "", 1):
            p = fixture()
            p["schema"] = schema
            with self.subTest(schema=schema), self.assertRaises(RpcQualificationPrepError):
                prepare_rpc_qualification(p)

    def test_missing_required_rpc_case_denied(self):
        for key, _ in RPC_CASES:
            p = fixture()
            del p["case_expectations"][key]
            with self.subTest(key=key), self.assertRaisesRegex(
                RpcQualificationPrepError, "^G1_RPC_PREP_CASES_REJECTED$"
            ):
                prepare_rpc_qualification(p)

    def test_changed_or_extra_rpc_case_denied(self):
        for key, _ in RPC_CASES:
            p = fixture()
            p["case_expectations"][key] = "PASS"
            with self.subTest(key=key), self.assertRaises(RpcQualificationPrepError):
                prepare_rpc_qualification(p)
        p = fixture()
        p["case_expectations"]["SENDRAWTRANSACTION"] = "ALLOW"
        with self.assertRaises(RpcQualificationPrepError):
            prepare_rpc_qualification(p)

    def test_non_dict_cases_and_malformed_values_denied(self):
        for cases in (None, [], (), "", True, {1: "DENY"}):
            p = fixture()
            p["case_expectations"] = cases
            with self.subTest(cases=repr(cases)), self.assertRaises(RpcQualificationPrepError):
                prepare_rpc_qualification(p)

    def test_fake_approval_release_or_core_execution_denied(self):
        for key in ("publisher_identity_verified", "isolated_runner_verified",
                    "live_core_executed", "release_allowed"):
            for value in (True, 0, "false", None):
                p = fixture()
                p[key] = value
                with self.subTest(key=key, value=value), self.assertRaisesRegex(
                    RpcQualificationPrepError, "^G1_RPC_PREP_AUTHORITY_REJECTED$"
                ):
                    prepare_rpc_qualification(p)

    def test_frozen_records_expose_no_secret_or_client(self):
        plan = prepare_rpc_qualification(fixture())
        with self.assertRaises(FrozenInstanceError):
            plan.release_allowed = True
        with self.assertRaises(FrozenInstanceError):
            plan.cases[0].status = "PASS"
        members = {x.name for x in fields(plan)}
        self.assertFalse(members.intersection({"rpc_client", "password", "cookie",
                                                "wallet", "binary_path", "broadcast"}))

    def test_readiness_uses_no_files_sockets_or_subprocess(self):
        with patch("builtins.open", side_effect=AssertionError("NO FILE")), \
             patch.object(socket, "socket", side_effect=AssertionError("NO SOCKET")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("NO PROCESS")):
            plan = prepare_rpc_qualification(fixture())
        self.assertEqual(plan.status, "BLOCKED_VERIFIED_BINARY_AND_ISOLATED_RUNNER")


if __name__ == "__main__":
    unittest.main()
