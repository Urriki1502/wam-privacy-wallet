"""Dependency-free foundation contract; not a wallet or security test."""

import pathlib
import tomllib
import unittest

import wam_privacy_wallet

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ScaffoldContractTests(unittest.TestCase):
    def test_package_is_explicitly_nonproduction(self):
        self.assertEqual(wam_privacy_wallet.__status__, "gui-shell-only")
        self.assertEqual(wam_privacy_wallet.__version__, "0.0.0")

    def test_required_scaffold_files_exist(self):
        required = (
            "README.md",
            ".gitignore",
            "pyproject.toml",
            "docs/ARCHITECTURE.md",
            "docs/DEVELOPMENT_PLAN.md",
            ".github/workflows/scaffold-ci.yml",
        )
        for relative in required:
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file())

    def test_no_license_selected(self):
        self.assertFalse((ROOT / "LICENSE").exists())
        self.assertFalse((ROOT / "LICENSE.md").exists())

    def test_no_runtime_dependency_imported(self):
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(metadata["project"]["name"], "wam-privacy-wallet")
        self.assertEqual(metadata["project"]["dependencies"], [])

    def test_docs_keep_shielded_outside_v1(self):
        architecture = (ROOT / "docs/ARCHITECTURE.md").read_text(encoding="utf-8").lower()
        self.assertIn("not included in v1", architecture.replace("**", ""))
        self.assertIn("user-owned", architecture)


if __name__ == "__main__":
    unittest.main()
