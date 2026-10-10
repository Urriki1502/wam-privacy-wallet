# G1-04 + G1-05 + SEC cookie — combined offline gate rehearsal

**STRICTLY DO NOT MERGE THIS PR.** This temporary branch is a reproducible
cross-PR compatibility check, not a production-ready wallet or authorization
to merge any individual research/security PR. It starts from
`main@aae2f35c837ab71ed2b02ccc6cc042db9e67582b` after G1-02.

## Exact source precedence
- G1-04 [PR #45](https://github.com/Urriki1502/wam-privacy-wallet/pull/45)
  at `6d51b806b28e7ac8200f529eea0451d83e200184`.
- G1-05 [PR #46](https://github.com/Urriki1502/wam-privacy-wallet/pull/46)
  at `54519698a5f05288e79726db3a5dbb0e152178ad`.
- SEC cookie-path first mitigation
  [PR #47](https://github.com/Urriki1502/wam-privacy-wallet/pull/47)
  at `c54af4f4d75e6d4a00f96a18bfb09ce2c2cbea6d`.

All nine stage-owned source/tests/docs files were transplanted byte-for-byte
from those exact PR heads. Only both mandatory CI floor maps were harmonized,
plus this new integration document. No semantic changes to the three
individual implementations. Main protected branch is untouched.

## Required quality gates

Base main: **17 suites / 168 tests**.
- + G1-04: 13 offline cases, +1 suite.
- + G1-05: 13 offline cases, +1 suite.
- + SEC cookie: 2 new harness tests, same suite.
- Combined: **19 suites / 196 tests per native architecture**.

Require four independent native platforms (Windows x86/x64, macOS x64,
Linux x64), three GUI jobs, read-only pinned WAM Core source and both CodeQL
analyzers. All results must be bound to this rehearsal HEAD; do not inherit
green status from the separate PRs.

## Still BLOCKED

- Publisher-authenticated WAM Core binary and build/source proof.
- SHA verification-to-process-launch identity (TOCTOU issue #36).
- Real WAM Core regtest nodes, RPC, cookie rotation, actual reorg/recovery.
- Scanner writer lock and WSP-1 integration, any signing/broadcast/funds.
- Production packaging, deployment, external security certification.

Owner must approve each real integration PR separately, preserve its exact
changes and rerun all mandatory checks on the resulting protected main SHA.
Do not merge this rehearsal as a shortcut.
