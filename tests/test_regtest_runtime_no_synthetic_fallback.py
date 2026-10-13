"""Regression guard: real regtest scanning must never import mock providers.

This is an offline structural test only. It does NOT execute WAM Core and
does not establish provenance, two-node E2E or mainnet readiness.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1] / "src" / "wam_privacy_wallet"
SCANNING_PATHS = (
    "application/live_regtest_scanner.py",
    "application/qualified_scan_session.py",
    "application/wsp_scan_coordinator.py",
    "integrations/wsp1_scanner_only_rpc.py",
    "node/core_readiness_rpc.py",
)
FORBIDDEN_IMPORT_PARTS = (
    "unittest.mock",
    "pytest",
    "tools.",
    "tests.",
    ".synthetic_policy_demo",
    ".synthetic_peer",
    ".mock_peer",
    ".test_fixture",
)
FORBIDDEN_CALLS = frozenset((
    "Mock", "MagicMock", "AsyncMock", "MockRPC", "FakeRPC",
    "SyntheticRPC", "SyntheticPeer", "FakeWamCore",
))


def _qual_name(expr: ast.expr) -> str:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        return _qual_name(expr.value) + "." + expr.attr
    return ""


def _violations(source: str) -> tuple[str, ...]:
    tree = ast.parse(source)
    problems: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names = ((node.module or ""),)
        else:
            names = ()
        for name in names:
            if any(
                name == part or name.startswith(part) or part in name
                for part in FORBIDDEN_IMPORT_PARTS
            ):
                problems.append("fixture-import")
        if isinstance(node, ast.Call):
            callee = _qual_name(node.func)
            if callee.split(".")[-1] in FORBIDDEN_CALLS:
                problems.append("fake-provider")
    return tuple(problems)


def _calls(source: str) -> frozenset[str]:
    return frozenset(
        _qual_name(node.func)
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
    )


class RegtestRuntimeNoSyntheticFallbackTests(unittest.TestCase):
    def test_reviewed_runtime_paths_exist_and_parse(self):
        for relative in SCANNING_PATHS:
            with self.subTest(path=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                self.assertTrue(source)
                ast.parse(source)

    def test_reviewed_runtime_has_no_test_fixture_imports(self):
        for relative in SCANNING_PATHS:
            with self.subTest(path=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                self.assertEqual(_violations(source), ())

    def test_live_entrypoint_uses_concrete_rpc_and_scanner_runtime(self):
        calls = _calls((ROOT / SCANNING_PATHS[0]).read_text(encoding="utf-8"))
        self.assertTrue({
            "LocalRegtestIdentityGateway",
            "Wsp1ScannerOnlyRpc",
            "SourceQualifiedScanRuntime",
        }.issubset(calls))
        self.assertTrue(any(call.endswith(".scan") for call in calls))

    def test_scanner_rpc_constructs_real_loopback_transport(self):
        calls = _calls(
            (ROOT / "integrations/wsp1_scanner_only_rpc.py").read_text(encoding="utf-8")
        )
        self.assertIn("_ScannerOnlyWire", calls)
        self.assertIn("LocalRegtestIdentityGateway", calls)

    def test_coordinator_invokes_pinned_scanner_method(self):
        calls = _calls(
            (ROOT / "application/wsp_scan_coordinator.py").read_text(encoding="utf-8")
        )
        self.assertIn("scanner.sync", calls)

    def test_mock_import_mutation_is_detected(self):
        self.assertEqual(_violations("from unittest.mock import Mock\n"), ("fixture-import",))
        self.assertEqual(_violations("from tools.synthetic_peer import Peer\n"), ("fixture-import",))

    def test_synthetic_runtime_constructor_mutation_is_detected(self):
        self.assertEqual(_violations("peer = SyntheticPeer()\n"), ("fake-provider",))
        self.assertEqual(_violations("peer = provider.FakeRPC()\n"), ("fake-provider",))

    def test_plain_rpc_call_is_not_misclassified_as_mock(self):
        self.assertEqual(
            _violations("from wam_privacy_wallet.node.read_rpc import LocalReadOnlyRpc\n"
                        "rpc = LocalReadOnlyRpc(endpoint, auth)\n"), ()
        )


if __name__ == "__main__":
    unittest.main()
