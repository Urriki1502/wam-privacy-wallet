# Development plan — current public repository

**Visibility:** Public (2026-10-10). **Licensing:** MIT on the open-source documentation PR pending merge. **Release status:** experimental, no production wallet.

This document replaces the original foundation-era plan; for the live milestone and residual-risk list see [ROADMAP](ROADMAP.md), [THREAT_MODEL](THREAT_MODEL.md) and [RELEASE_POLICY](RELEASE_POLICY.md).

## Existing repository phases

- Phase 001 — offline GUI shell: **merged**.
- Phase 002 — local regtest endpoint contract: **merged**.
- Phase 003 — pinned WSP-1 adapter provenance/public API: **OPEN DRAFT PR #3**, not merged.
- Phase 004 — read-only WAM regtest chain identity: **merged**.
- Phase 005 — bounded loopback-only read RPC: **merged**.
- Phase 006 — local read-only regtest gateway: **merged**.
- Phase 007 — opt-in verified WAM Core regtest harness: **merged**.
- Phase 008 — Core regtest profile gate: **merged**.
- Phase 009 — WAM Core source pin/drift gate: **merged**.

Merged means accepted into repository history, **not** ready for real wallets or mainnet.

## Immediate open-source work

1. Ship MIT LICENSE and maintainer/contributor documentation through a reviewed PR.
2. Complete full history/branches/artifacts secret audit; rotate compromised material if anything is found. Public visibility happened before this review, so do not claim it is already completed.
3. Establish enforceable branch rulesets, private vulnerability reporting, dependency scanning and CI/fork permissions.
4. Revalidate exact-head Actions checks, cross-platform runner coverage and license detection after merge.
5. Announce the repository to WAM developers with an explicit non-production warning.

## Subsequent engineering gates

1. Formalize pinned WSP-1 API/network-profile and local scanner dependency contracts.
2. Verify functional Windows locking, scanning/signer separation and recovery, including crash/restart.
3. Implement wallet storage, PSBT safety and trusted UI user-approval boundaries only after tests and security review.
4. Add reviewed wallet privacy/PayJoin/network privacy/disclosure features with negative tests.
5. Reproduce full-source tests across Windows/macOS/Linux and verified WAM Core testnet/regtest conditions.
6. Complete independent audit, signed builds and release qualification before any real-funds claims.

## Immutable boundaries

- No consensus/WAM Core modifications from this repo.
- No shielded/Halo2 CORE-003 consensus integration in V1.
- No automatic merges of Phase 003, frozen research or sensitive signer code.
- No reduction in existing required security checks merely to produce a green CI.

**Merge rule:** Each PR requires an exact-head CI record, review of changes and explicit maintainer approval. If a runner is unavailable, record the unavailable coverage as a blocker rather than silently omitting it.
