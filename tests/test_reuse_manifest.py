"""Offline positive/negative tests for the non-authorizing reuse manifest."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from tools.check_reuse_manifest import ReuseManifestError, validate_manifest

MANIFEST = Path(__file__).resolve().parents[1] / "compat" / "reuse_candidates.json"


class ReuseManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.valid = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_pinned_review_inventory_is_accepted_but_never_authorized(self):
        validate_manifest(self.valid)
        self.assertIs(self.valid["integration_allowed"], False)
        self.assertTrue(all(row["status"] != "APPROVED" for row in self.valid["candidates"]))

    def test_unpinned_commit_and_blob_are_denied(self):
        for field, invalid in (("commit_sha", "main"), ("blob_sha", "xyz"),
                               ("commit_sha", "A" * 40), ("blob_sha", "1" * 39)):
            with self.subTest(field=field, invalid=invalid):
                changed = copy.deepcopy(self.valid)
                changed["candidates"][0][field] = invalid
                with self.assertRaises(ReuseManifestError):
                    validate_manifest(changed)

    def test_active_integration_or_approved_claim_denied(self):
        for top, value in (("integration_allowed", True), ("state", "APPROVED"),
                           ("node_network", "mainnet"),
                           ("upstream_repositories_not_modified", False)):
            with self.subTest(field=top):
                changed = copy.deepcopy(self.valid)
                changed[top] = value
                with self.assertRaises(ReuseManifestError):
                    validate_manifest(changed)
        changed = copy.deepcopy(self.valid)
        changed["candidates"][0]["status"] = "APPROVED"
        with self.assertRaises(ReuseManifestError):
            validate_manifest(changed)

    def test_untrusted_repo_and_path_denied(self):
        for repo, path in (("hostile.example/org/pkg", "src/a.py"),
                           ("Urriki1502/wam-silent-wallet", "src/../keys.py"),
                           ("Urriki1502/wam-silent-wallet", "/tmp/private.py")):
            with self.subTest(repo=repo, path=path):
                changed = copy.deepcopy(self.valid)
                changed["candidates"][0]["repository"] = repo
                changed["candidates"][0]["source_path"] = path
                with self.assertRaises(ReuseManifestError):
                    validate_manifest(changed)

    def test_duplicate_or_missing_role_denied(self):
        for index in (0, 1):
            changed = copy.deepcopy(self.valid)
            changed["candidates"][index]["id"] = changed["candidates"][2]["id"]
            with self.assertRaises(ReuseManifestError):
                validate_manifest(changed)
        changed = copy.deepcopy(self.valid)
        changed["candidates"].pop()
        with self.assertRaises(ReuseManifestError):
            validate_manifest(changed)

    def test_rejects_unexpected_fields_or_invalid_json_shapes(self):
        for bad in (None, [], "false", {}, {"schema": "unexpected"}):
            with self.subTest(value=type(bad).__name__):
                with self.assertRaises(ReuseManifestError):
                    validate_manifest(bad)
        changed = copy.deepcopy(self.valid)
        changed["candidates"][0]["new_unreviewed_key"] = True
        with self.assertRaises(ReuseManifestError):
            validate_manifest(changed)


if __name__ == "__main__":
    unittest.main()
