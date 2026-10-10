"""WSP-1 provenance qualification tests. No secrets, wallet DB or network RPC."""

import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from wam_privacy_wallet.integrations import wsp1


class FakeDistribution:
    def __init__(self, *, version=wsp1.WSP1_VERSION, url=None, commit=None, raw=None):
        self.version = version
        if raw is None:
            raw = json.dumps(
                {
                    "url": url if url is not None else wsp1.WSP1_REPOSITORY + ".git",
                    "vcs_info": {"vcs": "git", "commit_id": commit or wsp1.WSP1_COMMIT},
                }
            )
        self.raw = raw

    def read_text(self, name):
        assert name == "direct_url.json"
        return self.raw


class WSP1ContractTests(unittest.TestCase):
    def test_exact_commit_and_version_are_immutable_constants(self):
        self.assertEqual(len(wsp1.WSP1_COMMIT), 40)
        self.assertEqual(wsp1.WSP1_VERSION, "1.0.0.dev0")
        self.assertEqual(wsp1.WSP1_PROFILE, "WSP-1")

    def test_installation_is_exact_pinned_git_source(self):
        result = wsp1.probe_pinned_wsp1()
        self.assertEqual(result.commit, wsp1.WSP1_COMMIT)
        self.assertEqual(result.regtest_genesis, wsp1.WSP1_REGTEST_GENESIS)
        self.assertFalse(result.mainnet_enabled)

    def test_git_provenance_errors_fail_before_import(self):
        cases = (
            (FakeDistribution(version="1.0.1"), "WSP1_VERSION_MISMATCH"),
            (FakeDistribution(url="https://evil.invalid/a"), "WSP1_SOURCE_MISMATCH"),
            (FakeDistribution(commit="0" * 40), "WSP1_COMMIT_MISMATCH"),
            (FakeDistribution(raw="not json"), "WSP1_INVALID_PROVENANCE"),
            (FakeDistribution(raw="null"), "WSP1_PROVENANCE_MISSING"),
            (FakeDistribution(raw='{"url": 4, "vcs_info": {}}'), "WSP1_INVALID_PROVENANCE"),
        )
        for fake, expected in cases:
            with self.subTest(expected=expected), patch.object(
                wsp1.metadata, "distribution", return_value=fake
            ), patch.object(wsp1.importlib, "import_module") as importing:
                with self.assertRaisesRegex(wsp1.WSP1ContractError, f"^{expected}$"):
                    wsp1.probe_pinned_wsp1()
                importing.assert_not_called()

    def test_missing_git_provenance_rejected(self):
        with patch.object(
            wsp1.metadata, "distribution", return_value=SimpleNamespace(
                version=wsp1.WSP1_VERSION, read_text=lambda _: None
            )
        ):
            with self.assertRaisesRegex(wsp1.WSP1ContractError, "WSP1_PROVENANCE_MISSING"):
                wsp1.probe_pinned_wsp1()

    def test_mainnet_must_stay_disabled(self):
        with patch.object(
            wsp1.metadata, "distribution", return_value=FakeDistribution()
        ), patch.object(wsp1.importlib, "import_module") as importing:
            importing.side_effect = [
                SimpleNamespace(__version__=wsp1.WSP1_VERSION),
                SimpleNamespace(
                    API_VERSION=wsp1.WSP1_API_VERSION,
                    PROFILE=wsp1.WSP1_PROFILE,
                    CORE_VERSION=wsp1.WSP1_CORE_VERSION,
                    CORE_COMMIT=wsp1.WSP1_CORE_COMMIT,
                    REGTEST_GENESIS=wsp1.WSP1_REGTEST_GENESIS,
                    MAINNET_ENABLED=True,
                ),
            ]
            with self.assertRaisesRegex(wsp1.WSP1ContractError, "WSP1_MAINNET_UNAPPROVED"):
                wsp1.probe_pinned_wsp1()

    def test_unrecognized_public_api_rejected(self):
        with patch.object(
            wsp1.metadata, "distribution", return_value=FakeDistribution()
        ), patch.object(wsp1.importlib, "import_module") as importing:
            importing.side_effect = [
                SimpleNamespace(__version__=wsp1.WSP1_VERSION),
                SimpleNamespace(
                    API_VERSION=1, PROFILE="WSP-1",
                    CORE_VERSION=wsp1.WSP1_CORE_VERSION,
                    CORE_COMMIT=wsp1.WSP1_CORE_COMMIT,
                    REGTEST_GENESIS=wsp1.WSP1_REGTEST_GENESIS,
                    MAINNET_ENABLED=False,
                ),
            ]
            with self.assertRaisesRegex(wsp1.WSP1ContractError, "WSP1_PUBLIC_API_MISMATCH"):
                wsp1.probe_pinned_wsp1()


if __name__ == "__main__":
    unittest.main()
