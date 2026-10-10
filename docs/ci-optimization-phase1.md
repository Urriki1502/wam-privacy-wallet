# Wallet CI Consolidation — Phase 1 (review-only)

This change proposes replacing nine independent PR/push workflows with one
consolidated workflow and **five jobs** per ordinary PR or push (four platform
jobs and one read-only source-pin verification). It does **not** disable tests.

## Baseline and coverage mapping

| Former workflow | Test target or check preserved |
| --- | --- |
| scaffold-ci | `test_scaffold.py` on Linux/macOS/Windows x64 |
| core-profile-ci | `test_core_profile.py` on Win x86/x64, macOS x64, Linux x64 |
| core-source-pin-ci | `test_core_source_pin.py` on four architectures; then `tools/check_core_source_pin.py --check-head` |
| gui-shell-ci | GUI dependency install, pip check, full unittest discovery on Linux/macOS/Windows x64 |
| node-contract-ci | `test_node_contract.py` on Linux/macOS/Windows x64 |
| read-only-rpc-ci | `test_read_rpc.py` on four architectures |
| real-regtest-harness-ci | `test_real_regtest_harness.py` on four architectures |
| regtest-attestation-ci | `test_regtest_attestation.py` on four architectures |
| regtest-gateway-ci | `test_regtest_gateway.py` on four architectures |

The new cross-platform matrix runs **all eight targeted offline suites on all
four architectures**, retaining and expanding the prior checks. The full GUI
test suite remains on the three original x64 platforms. On each platform,
offline tests run before installation of optional GUI dependencies, matching
the earlier dependency-light verification model. The pinned-Core remote
inspection remains **read-only**, and occurs only after local validation.

## CI cost controls

- Shared setup replaces repeated runner provisioning and Python installation.
- Pull-request concurrency cancels superseded runs of the same PR only.
- `push: main` retains post-merge validation; `workflow_dispatch` is retained.
- No path filters or test skips: a PR always runs the full wallet qualification.
- `permissions: contents: read`, with no persistent checkout credentials.
- Existing Python 3.12 architecture assertions remain active.

## Pre-merge review gates

1. Confirm all five jobs run and pass on the draft PR.
2. Verify Windows x86 and x64, macOS x64 and Linux x64 report the true Python architecture.
3. Compare the test collection/results against the previous nine workflows;
   ensure the full GUI suite, offline negative tests, and upstream GET-only check pass.
4. Verify that existing branch protections and required status checks have
   been mapped to the new job names before merge. The ruleset read alone
   cannot establish every repository policy.
5. Record actual Actions billed minutes, including OS multipliers, before
   claiming cost savings; job-count reduction does not guarantee proportional
   billing reduction.
6. Keep this PR draft until the owner approves. No WAM Core code and no WSP-1
   PR #3 changes are included.

**Non-production status is unchanged.** CI PASS is not a claim that the
wallet is ready for funds or real-world use.
