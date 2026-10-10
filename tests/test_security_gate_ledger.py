"""Adversarial gate-ledger schema tests, offline and non-authorizing."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from tools.check_security_gate_ledger import SecurityGateLedgerError, validate_security_gates

FILE = Path(__file__).resolve().parents[1] / "compat" / "g0_security_gate_ledger.json"


class SecurityGateLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = json.loads(FILE.read_text(encoding="utf-8"))

    def deny(self, data):
        with self.assertRaises(SecurityGateLedgerError):
            validate_security_gates(data)

    def test_baseline_stays_explicitly_nonoperational(self):
        validate_security_gates(self.baseline)
        self.assertIs(self.baseline["release_allowed"], False)
        self.assertIs(self.baseline["mainnet_allowed"], False)
        self.assertIs(self.baseline["operational_wallet_enabled"], False)

    def test_cannot_auto_promote_global_authority(self):
        for key in ("release_allowed", "mainnet_allowed", "operational_wallet_enabled"):
            with self.subTest(key=key):
                x = copy.deepcopy(self.baseline)
                x[key] = True
                self.deny(x)
        x = copy.deepcopy(self.baseline)
        x["scope"] = "PRODUCTION"
        self.deny(x)

    def test_cannot_mark_required_review_as_pass(self):
        for i, gate in enumerate(self.baseline["gates"]):
            for illegal in ("PASS", "APPROVED", "NOT_APPLICABLE", "SKIPPED"):
                with self.subTest(gate=gate["id"], status=illegal):
                    x = copy.deepcopy(self.baseline)
                    x["gates"][i]["status"] = illegal
                    self.deny(x)

    def test_p0_and_hard_blockers_cannot_be_downgraded(self):
        for i, gate in enumerate(self.baseline["gates"]):
            with self.subTest(gate=gate["id"]):
                x = copy.deepcopy(self.baseline)
                x["gates"][i]["priority"] = "P2"
                self.deny(x)
                if gate["status"] == "BLOCKED":
                    x = copy.deepcopy(self.baseline)
                    x["gates"][i]["status"] = "REVIEW_REQUIRED"
                    self.deny(x)

    def test_removed_duplicate_or_forged_items_denied(self):
        x = copy.deepcopy(self.baseline)
        x["gates"].pop()
        self.deny(x)
        x = copy.deepcopy(self.baseline)
        x["gates"][0]["id"] = x["gates"][1]["id"]
        self.deny(x)
        x = copy.deepcopy(self.baseline)
        x["gates"][0]["evidence"] = "https://evil.example/approved"
        self.deny(x)

    def test_unsupported_structures_denied(self):
        for x in ({}, [], None, "approved", 1, True):
            with self.subTest(kind=type(x).__name__):
                self.deny(x)
        x = copy.deepcopy(self.baseline)
        x["evidence_approved"] = True
        self.deny(x)
        x = copy.deepcopy(self.baseline)
        x["gates"][0]["unreviewed"] = True
        self.deny(x)


if __name__ == "__main__":
    unittest.main()
