# Fail-closed mandatory offline test discovery

This is a CI **integrity gate**, not a wallet release, security audit or real-node qualification.

## Problem
`python -m unittest discover -p <pattern>` can exit successfully with **zero tests** when a named test module has been removed, renamed, emptied or entirely skipped. A passing GitHub Actions job can therefore be misleading.

## Solution
`python -m tools.ci_contract_gate` runs the eight existing offline suites plus its own regression test suite in **isolated Python subprocesses**. It rejects:
- an unlisted test pattern,
- a missing expected test file,
- a suite with zero discovered tests,
- a nonempty suite that falls below its verified baseline minimum,
- actual test failures/import failures, and
- a suite whose tests all skip.

The runner reports discovered cases and their minimum counts. The original eight
suite minimums are **5, 9, 10, 7, 11, 10, 10, 10**; the CI self-test suite now
requires **10** cases. These are regression floors, not exhaustive coverage
proofs. Any authorized reduction needs explicit review and a separate change.

The runner continues to collect failure evidence from other suites before ultimately failing. No GUI matrix, WAM Core pin or security analysis job is removed or relaxed. Python architecture verification remains unchanged.

New Draft PRs #20, #21, #23 and #24, as well as research PR #16, add offline tests on independent branches. Before **any** of these PRs are merged, the reviewed owner must append the specific new tests to `MANDATORY_SUITES` on the resulting integration branch, preserve existing eight tests and this gate, and re-run the entire matrix on Windows x86/x64, macOS x64 and Linux x64. The aggregate rehearsal PR #25 is **DO NOT MERGE** and will need refreshing if the CI runner changes.

## Nonclaims and review checklist
1. Check all nine mandatory suites are discovered with counts meeting their baseline floor on each of the four offline jobs.
2. Confirm all eight Wallet CI jobs and CodeQL checks PASS at the exact PR HEAD.
3. Compare wall-clock duration to the previously merged wallet CI (~118s on Oct 10), noting runner variability.
4. Confirm a missing, empty, all-skipped or failing target cannot produce a successful offline job.
5. Keep WSP-1 PR #3, research #16, G0/G1 Drafts and WAM Core unchanged.

No merge without explicit approval. Real WAM Core execution and production wallet qualification remain **BLOCKED**.

## Case-count regression hardening

PR #26 initially verified 80 cases (8 self-tests plus 72 existing cases) per
architecture. This revision adds two self-tests (pinned baseline registry and
one-test false-green denial) for **82** per architecture. Baselines are checked
before suite execution so an unexpectedly reduced module cannot pass quietly.
This remains a review-only CI qualification, not production authorization.
