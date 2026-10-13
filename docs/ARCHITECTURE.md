# Architecture boundaries (proposal, not implementation)

**Canonical V1 scope:** [Approved diagram traceability & three-stream integration plan](ARCHITECTURE_V1_PLAN.md). Machine-checked [14-box traceability manifest](ARCHITECTURE_V1_TRACEABILITY.json). Architecture edges denote dependencies and approved data-flow boundaries, **never** transferable signing, RPC or Core execution authority. In particular, an offline signer MUST NOT acquire RPC/network access from a diagram arrow.

## Objective

A single Python/Qt desktop GUI for macOS and Windows, connected to a user-owned WAM Core validating full node. The app is an integration layer, not a protocol fork.

## Future application modules

1. **GUI and sessions:** one cross-platform UI and explicit user-approval boundaries.
2. **WSP-1:** pinned `wam-silent-payments` engine with scanner / signer separation.
3. **Local node:** WAM-specific RPC profile, loopback authentication, chain/network checks, reorg behavior, no hosted scanner fallback.
4. **Wallet privacy:** reviewed coin-selection and transaction policies.
5. **PayJoin and network privacy:** fail-closed adapter boundaries; never bypass signing intent or route policy.
6. **Selective disclosure:** explicit consent, revocable authority and cross-process consistency only after dedicated qualification.
7. **Security assurance:** independent regression/release checks from `wam-security`; evidence linked to immutable commit SHAs.

## Explicit exclusions

- Shielded pool / Halo2 consensus integration is **not** included in V1.
- No consensus change or chain activation is authorized by this repository.
- No real wallets, real funds, public-node security tests, or public releases are authorized by a passing scaffold CI run.

## Portability requirements

- Test under Python 3.12 on macOS and Windows.
- Do not assume POSIX-only `fcntl` locking; implement/test a genuine exclusive-lock abstraction before any scanner write operations on Windows.
- Never use Bitcoin's default regtest RPC port as a WAM default; derive RPC configuration from the adopted WAM network profile and local node settings.
- Guard native dependencies and packaging separately for each target OS.

## Change control

No unpinned dependency integrations. Changes touching signer, wallet storage, scanner, RPC, disclosure, policy, or release status require explicit tests and review. Research baselines in source repositories remain untouched.

## Review integrations now present

See the [V1 evidence categories](ARCHITECTURE_V1_PLAN.md#privacy-integration-evidence-categories)
and [source reuse map](PRIVACY_INTEGRATION_2026_10_13.md). PayJoin and network
reviews reuse unchanged pinned privacy models. Local selective disclosure uses
existing WSP history state only. All are non-authorizing review interfaces;
private transport, authenticated ownership and operational wallet acceptance
remain unqualified. The local export is a copy of selected observations, not a
reusable capability or cryptographic proof; copied data cannot be revoked.
