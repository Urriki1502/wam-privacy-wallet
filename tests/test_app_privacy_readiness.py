"""Offline capability-readiness contract tests; no real scanner/signer or transport."""
from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path
import unittest

from wam_privacy_wallet.application.privacy_readiness import (
    PrivacyReadinessError, PrivacyResearchSnapshot, research_readiness,
)
from tools.check_reuse_manifest import validate_manifest
from tools.check_security_gate_ledger import validate_security_gates

ROOT = Path(__file__).resolve().parents[1]
_UNSET = object()  # Distinguish an omitted fixture from an explicit invalid None.


class OfflinePrivacyReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(
            (ROOT / "compat/reuse_candidates.json").read_text(encoding="utf-8")
        )
        cls.ledger = json.loads(
            (ROOT / "compat/g0_security_gate_ledger.json").read_text(encoding="utf-8")
        )

    def deny(self, manifest=_UNSET, ledger=_UNSET):
        if manifest is _UNSET:
            manifest = self.manifest
        if ledger is _UNSET:
            ledger = self.ledger
        with self.assertRaisesRegex(PrivacyReadinessError, "^APP_PRIVACY_EVIDENCE_DENIED$"):
            research_readiness(manifest, ledger)

    def test_canonical_research_inventory_composes_to_disabled_readiness(self):
        validate_manifest(self.manifest)
        validate_security_gates(self.ledger)
        snapshot = research_readiness(self.manifest, self.ledger)
        self.assertEqual(
            snapshot, PrivacyResearchSnapshot(
                "RESEARCH_ONLY", "PIN_RECORDED_UNATTESTED",
                "MODEL_ONLY", "MODEL_ONLY", "MODEL_ONLY", "NOT_INTEGRATED",
                "BLOCKED", "BLOCKED", "BLOCKED",
            ),
        )
        self.assertEqual(len(dataclasses.fields(snapshot)), 9)
        self.assertFalse(hasattr(snapshot, "__dict__"))

    def test_manifest_cannot_promote_integration_authority(self):
        for key, value in (
            ("integration_allowed", True),
            ("state", "APPROVED"),
            ("node_network", "mainnet"),
            ("upstream_repositories_not_modified", False),
        ):
            with self.subTest(key=key):
                corrupted = copy.deepcopy(self.manifest)
                corrupted[key] = value
                self.deny(manifest=corrupted)

    def test_exact_pinned_wsp_and_silent_wallet_sources_are_required(self):
        for index in (0, 7):  # WSP API and Silent Wallet node candidates
            for field, value in (
                ("commit_sha", "0" * 40),
                ("blob_sha", "BAD"),
                ("blob_sha", "0" * 40),  # well-formed but wrong Git blob SHA
                ("source_path", "src/../secrets.py"),
                ("repository", "untrusted/repo"),
                ("status", "APPROVED"),
            ):
                with self.subTest(candidate=index, field=field, value=value):
                    corrupted = copy.deepcopy(self.manifest)
                    corrupted["candidates"][index][field] = value
                    self.deny(manifest=corrupted)

    def test_manifest_missing_duplicate_or_unexpected_candidate_is_denied(self):
        for bad in ({}, [], None, True, {"schema": "fake"}):
            with self.subTest(kind=type(bad).__name__):
                self.deny(manifest=bad)
        duplicated = copy.deepcopy(self.manifest)
        duplicated["candidates"][1]["id"] = duplicated["candidates"][0]["id"]
        self.deny(manifest=duplicated)
        removed = copy.deepcopy(self.manifest)
        removed["candidates"].pop()
        self.deny(manifest=removed)
        extra_field = copy.deepcopy(self.manifest)
        extra_field["candidates"][0]["authority"] = True
        self.deny(manifest=extra_field)

    def test_ledger_cannot_promote_operational_wallet_or_mainnet(self):
        for field in ("release_allowed", "mainnet_allowed", "operational_wallet_enabled"):
            with self.subTest(field=field):
                corrupted = copy.deepcopy(self.ledger)
                corrupted[field] = True
                self.deny(ledger=corrupted)
        corrupted = copy.deepcopy(self.ledger)
        corrupted["scope"] = "APPROVED"
        self.deny(ledger=corrupted)

    def test_required_security_gate_promotion_is_rejected(self):
        for index, gate in enumerate(self.ledger["gates"]):
            for promotion in ("PASS", "APPROVED", "REVIEW_REQUIRED" if gate["status"] == "BLOCKED" else "APPROVED"):
                with self.subTest(gate=gate["id"], promotion=promotion):
                    corrupted = copy.deepcopy(self.ledger)
                    corrupted["gates"][index]["status"] = promotion
                    self.deny(ledger=corrupted)

    def test_ledger_missing_duplicate_or_untrusted_structures_are_denied(self):
        for bad in ({}, [], None, 1, {"schema": "fake"}):
            with self.subTest(kind=type(bad).__name__):
                self.deny(ledger=bad)
        missing = copy.deepcopy(self.ledger)
        missing["gates"].pop()
        self.deny(ledger=missing)
        duplicate = copy.deepcopy(self.ledger)
        duplicate["gates"][0]["id"] = duplicate["gates"][1]["id"]
        self.deny(ledger=duplicate)
        priority = copy.deepcopy(self.ledger)
        priority["gates"][0]["priority"] = "P2"
        self.deny(ledger=priority)

    def test_result_is_immutable_and_contains_no_execution_capabilities(self):
        record = research_readiness(self.manifest, self.ledger)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.sign = "READY"
        for attr in ("rpc", "endpoint", "wallet", "signer", "scanner", "keyring",
                     "seed", "wallet_db", "broadcast", "approve", "client"):
            with self.subTest(attr=attr):
                self.assertFalse(hasattr(record, attr))
        for secret in ("127.0.0.1", "29554", "password", "seed", "private"):
            self.assertNotIn(secret, repr(record).lower())


if __name__ == "__main__":
    unittest.main()
