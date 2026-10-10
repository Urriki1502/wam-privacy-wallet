# WAM Privacy Wallet G1 — Four-step gated roadmap (2026-10-10)

**Baseline:** `main@862bb7692bca9a6f66f490cf5b6bc1dfb9f69fe5`; G1-01
[topology Draft PR #27](https://github.com/Urriki1502/wam-privacy-wallet/pull/27).
WAM Core real two-node qualification [issue #9](https://github.com/Urriki1502/wam-privacy-wallet/issues/9)
remains **BLOCKED**. This roadmap does not authorize mainnet, real funds, WSP
integration, scanner execution or a Core source change.

| Stage | Deliverable | CI / acceptance | Hard blocker / nonclaim |
| --- | --- | --- | --- |
| G1-02 | Offline provenance candidate intake; canonical pinned source metadata and exact SHA256 shape | Fail-closed malformed, forged approval, unsigned proof; full platform/CodeQL matrix | Candidate SHA is NOT publisher proof or source-to-binary attestation |
| G1-03 | Strict offline policy audit for G1-01's proposed two-node loopback config | Deny public hosts, divergent ports, option injection, altered authority/status, mutation; matrix/CodeQL | No sockets, binary, datadir, cookies or actual peer reachability |
| G1-04 | Real isolated RPC/auth, cookie rotation, restart, timeout and correct genesis checks, with reproducible logs | Test only exact independently attested WAM Core binary in disposable dual-node regtest and all OS gates | **BLOCKED** until publisher proof, verified artifact and reviewed executor |
| G1-05 | Two-node divergence/reorg, restart/recovery, local-only scanner read boundary, writer lease and independent review | Reproduce state changes and negative paths, review evidence, keep signer separate | **BLOCKED** until G1-04 and upstream Windows-lock/WSP approvals |

## Overlapping execution without unsafe integration

- Start **G1-02** as an independent Draft PR based on stable `main`.
- Start **G1-03** as a *stacked* Draft PR based on G1-01 PR #27 (not `main`),
  so the prospective config has one auditable policy layer. Its CI runs
  against the stack; do not merge the stack or confuse stacked green with a
  `main` result.
- Both PRs must retain **all existing suites**, add their own fail-closed
  mandatory suite floors, preserve native Windows x86/x64 plus macOS/Linux,
  GUI x64, GET-only pinned-Core and CodeQL. No test suppression.
- After exact-HEAD 8/8 Wallet CI and 2/2 CodeQL, independent reviewer decides
  order and any subsequent merge; refresh against new `main` before merge.
- Any unsatisfied real-node, publisher-identity, WSP-1-lock, scanner, wallet
  signer or release condition is explicitly **BLOCKED**, never skipped-as-PASS.
- Explicitly leave frozen/review-only PR #3, #16, no-merge PR #25, WSP PR #9
  and WAM Core untouched.

## Evidence requirements before G1-04 / G1-05 execution

Publisher-authenticated source/release association, exact binary and SHA256,
verified fresh isolated datadirs and loopback RPC/P2P configuration,
native process handles and cleanup, no inherited secrets or external network,
RPC negative cases, restart and cookie rotation, two-node fork/reorg/recovery,
portable test artifacts and independent maintainer review. A SHA checksum
provided by the same submitter is not independent evidence.
