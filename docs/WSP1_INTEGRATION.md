# WSP-1 integration boundary

**V1 approved architecture:** [Traceability plan](ARCHITECTURE_V1_PLAN.md) and [WSP-1 pinned source reuse / scanner RPC gap](WSP1_SOURCE_REUSE_GATE.md). A verified Git source blob is **review evidence, not an imported dependency or an operational scanner**.

**Status: planned / review-gated**. The pinned WSP-1 interface candidate is tracked in [PR #3](https://github.com/Urriki1502/wam-privacy-wallet/pull/3) and must not be described as merged, complete or secure until independently qualified.

## Intended components

1. A version/commit-SHA-pinned `wam-silent-payments` source; verify license, provenance, public API and test vectors before import.
2. A wallet-local scanner using a locally operated, validating WAM Core node; no centralized scanning service fallback.
3. Separate scan and spend capabilities; never export spending secrets to scanner processes or diagnostic output.
4. Verified PSBTv2 input/output/amount/fee and signer-approval semantics; wallet policy decisions alone must not authorize signing.
5. Backup/recovery, duplicate processing, reorg and rescan logic with deterministic negative tests.
6. Cross-platform single-writer locking for scanner state. No `fcntl` import on unsupported platforms, and **no no-op flock replacement**.
7. Explicit WAM chain identity and testnet/regtest profile accepted by maintainers; do not assume Bitcoin-default network parameters.
8. Reproducible integration tests that connect to frozen source SHAs without changing the upstream repositories.

## Acceptance checklist for the integration PR

- Exact upstream dependency SHA and legal provenance recorded.
- Linux/Windows/macOS unit and interface tests; true Windows locking exclusion and crash/restart tests.
- Real WAM Core local-node identity and bounded RPC failures verified on an opt-in test environment.
- Scanner/observer threat-model review, including WAM-operated bootstrap/seed first-hop visibility.
- Synthetic test vectors, mock-network nonclaims, and sensitive-data/log-redaction verification.
- Independent reviewer acknowledgement and passing required checks at the final PR HEAD.
- Explicit maintainer sign-off for WSP network profile before moving beyond research/regtest.

## Prohibited shortcuts

No fake `flock` semantics, hosted-scanner requirement, unlocked mainnet signing, implicit PSBT approval, altered WAM consensus, removal of security tests for green CI, or automatic merge of frozen upstream research.
