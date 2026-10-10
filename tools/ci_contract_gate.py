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
MANDATORY_SUITES = (
    "test_scaffold.py",
    "test_core_profile.py",
    "test_core_source_pin.py",
    "test_node_contract.py",
    "test_read_rpc.py",
    "test_real_regtest_harness.py",
    "test_regtest_attestation.py",
    "test_regtest_gateway.py",
    "test_ci_contract_gate.py",
)


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
    print(f"CI_DISCOVERED_TESTS: {pattern}: {count}", flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or loader.errors:
        raise ContractGateError(f"CI_REQUIRED_SUITE_FAILED: {pattern}")
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
