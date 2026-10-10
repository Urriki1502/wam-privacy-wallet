# WAM Privacy Wallet G1 — Roadmap after offline G1-01/G1-03 integration

**Snapshot: 2026-10-10.** Current main source baseline
`65356c96081d92b7c63572923245bdd11d12f070` passed mandatory CI
(8/8) and CodeQL (2/2) after the controlled merge of
[#27](https://github.com/Urriki1502/wam-privacy-wallet/pull/27),
[#29](https://github.com/Urriki1502/wam-privacy-wallet/pull/29),
[#38](https://github.com/Urriki1502/wam-privacy-wallet/pull/38),
[#40](https://github.com/Urriki1502/wam-privacy-wallet/pull/40) and
[#42](https://github.com/Urriki1502/wam-privacy-wallet/pull/42).
Legacy preview and structured schema v1 coexist as **offline**
representation and parity audit only.

## Next steps and security gates

| Phase | Work | Acceptance | Must **not** be claimed |
| --- | --- | --- | --- |
| G1-02 metadata intake | Port the historical [#28](https://github.com/Urriki1502/wam-privacy-wallet/pull/28) candidate, enforce strict types, preserve all suite floors | 17 mandatory suites / >=168 cases per architecture; GUI, pinned read-only Core and exact-HEAD CodeQL; source review | Publisher identity, binary provenance, source-to-binary identity, runnable daemon |
| G1-04 offline readiness | Reconcile [#31](https://github.com/Urriki1502/wam-privacy-wallet/pull/31) against new main without reducing 17-suite baseline | Offline RPC/cookie, restart/error inventories; independent review | Real cookie rotation or real RPC PASS |
| G1-05 offline readiness | Reconcile [#32](https://github.com/Urriki1502/wam-privacy-wallet/pull/32) after G1-04 | Offline reorg/recovery, local-only scanner and lock-negative inventory | Actual two-node divergence, scanner or reorg PASS |
| Trusted artifact + launch | Independently authenticated Core release and reviewed [TOCTOU blocker #36](https://github.com/Urriki1502/wam-privacy-wallet/issues/36) | Publisher proof, exact artifact, verified execution snapshot, host isolation and adversarial tests | Trust from submitter-provided checksum alone |
| Real two-node E2E | Owner-authorized isolated regtest [#9](https://github.com/Urriki1502/wam-privacy-wallet/issues/9) only after preceding security gates | Native sockets/peer restrictions, RPC cookie/restart, fork/reorg and recovery evidence | Production, real funds, automatic signer permission |

## Branch and release boundaries

The live GitHub `main` ruleset now requires PR, up-to-date source,
8 Wallet CI checks and 2 CodeQL checks; branch rules protect code review
*workflow*, not artifact authenticity. Do not lower checks for any draft.
Re-run all checks on the exact final HEAD and actual `main` merge SHA.

Historic Draft #28 is preserved for traceability; reconcile only the
**G1-02-only delta** into a fresh branch. Existing WSP-1 wallet
[PR #3](https://github.com/Urriki1502/wam-privacy-wallet/pull/3),
Phase 010 [PR #16](https://github.com/Urriki1502/wam-privacy-wallet/pull/16)
and upstream WSP Windows locking remain separately gated. Do not modify
WAM Core consensus, scanner, signer, real wallets, or mainnet. Never
label a simulated test as production-qualified.
