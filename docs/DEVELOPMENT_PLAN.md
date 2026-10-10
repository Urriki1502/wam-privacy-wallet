# Development plan

## Foundation (this commit)

- Private repository, deferred license.
- README, .gitignore, initial module placeholder, docs.
- Dependency-free scaffold CI: Windows/macOS/Linux Python 3.12.
- **No production code, no GUI, no wallet functionality.**

## Proposed sequential gates (not started)

1. Formalize API boundaries, version pins and WSP network-profile assumptions.
2. Desktop GUI shell; smoke and packaging tests on macOS/Windows.
3. WSP-1 adapter + local node-only scanner; Windows locking fixes.
4. Signing, wallet-state, backup/recovery and crash tests.
5. Coin selection and wallet privacy policy.
6. PayJoin, network privacy and selective disclosure, each review-gated.
7. Independent security integration and end-to-end tests.
8. Platform packaging, supply-chain verification and external review.

**Merge rule:** One narrow PR at a time; CI tied to exact commit; no merge on missing/failed mandatory checks. A passing unit test never substitutes for cross-module or external assurance. If multiple CI jobs are queued, only independent changes may proceed before predecessor qualification is complete.

No shielded/Halo2 or consensus work is part of this release plan.
