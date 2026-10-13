# REGTEST-MOCK-001 — Runtime vs synthetic evidence audit (2026-10-13)

**DRAFT / review required.** Source baseline: `main@1ca537a64ae1a3de7fa9b931f09e594246f96781`. This document records the inspected source and preserved acceptance boundary; it is not a real-Core execution report.

## Finding: preserve the existing real scanner seam

The existing operational, manually consented REGTEST read path is:
`application/live_regtest_scanner.py:scan_existing_regtest`
→ `node/regtest_gateway.py:LocalRegtestIdentityGateway`
→ `integrations/wsp1_scanner_only_rpc.py:Wsp1ScannerOnlyRpc`
→ `application/qualified_scan_session.py:SourceQualifiedScanRuntime`
→ upstream pinned WSP-1 `Scanner.sync` / SQLite.

`application/wsp_scan_coordinator.py` invokes upstream `scanner.sync`; `node/core_readiness_rpc.py` checks optional peer-reported index/filter readiness. This path has real localhost HTTP transport and no synthetic RPC fallback in the reviewed implementation. A live localhost peer may impersonate a qualified WAM Core executable: **socket I/O is not immutable process/binary provenance**.

The new pure-Python negative regression `tests/test_regtest_runtime_no_synthetic_fallback.py` rejects imports of fixture/mock code and direct Mock/Fake/Synthetic-provider constructors in this reviewed operational source boundary. It does not start WAM Core, sign, broadcast, or assert successful E2E.

## Keep versus retire

| Item | Disposition | Reason / exit gate |
| --- | --- | --- |
| `live_regtest_scanner.py`, `wsp1_scanner_only_rpc.py`, `qualified_scan_session.py`, `wsp_scan_coordinator.py`, `core_readiness_rpc.py` | **KEEP** | Real implementation code with read-only, fail-closed checks; not fake runtime providers. |
| `tests/test_regtest_scanner_wire.py`, `tools/ci_wsp1_scanner_loopback.py`, synthetic WSP native CI | **KEEP under explicit SYNTHETIC label** | Adversarial reply-shapes, replay/reorg, faults, cancellation and parser tests. They are not a release acceptance surrogate. |
| `application/synthetic_policy_demo.py`, `test_app_synthetic_policy_demo.py` | **QUARANTINE as offline research/demo; do not treat as scan path** | UI/research demonstrations cannot supply wallet balance, keys, signer, Core identity, or E2E authority. Retire user-facing demo only after a tested real replacement exists; keep pure-policy negative tests. |
| `gui/main_window.py` synthetic privacy/recovery/preview panels | **LEGACY PRESENTATION DEBT** | Panels label evidence synthetic/untrusted and enforce nonauthorization. Migrate each to a verified read-only/regtest equivalent in a dedicated PR before removing associated GUI regression tests. |
| `gui/regtest_window.py`, app receipt/history UI | **KEEP AND VALIDATE** | Real WSP/SQLite UI code exercised against synthetic peer; needs separate operator-host WAM Core acceptance. |
| Linux synthetic fd/ELF/process identity regression suites | **KEEP** | Necessary negative tests only; never represent authenticated actual WAM Core invocation. |
| Production signing, broadcast, real funds/mainnet, network anonymity claims | **BLOCK** | Outside accepted scope. |

## Blockers; no mock deletion may conceal these

- [#9](https://github.com/Urriki1502/wam-privacy-wallet/issues/9): actual secure, isolated two-node WAM Core E2E and captured verification artifacts **NOT RUN**.
- [#82](https://github.com/Urriki1502/wam-privacy-wallet/issues/82) / [#86](https://github.com/Urriki1502/wam-privacy-wallet/issues/86): signed v0.1.11 still fails executable-stack qualification (GNU_STACK RWE); cannot pretend source-pinned static inspection authorizes launch.
- [#153](https://github.com/Urriki1502/wam-privacy-wallet/issues/153): same-build signed official config/help parity pending DEV.
- [#148](https://github.com/Urriki1502/wam-privacy-wallet/issues/148) / [#151](https://github.com/Urriki1502/wam-privacy-wallet/issues/151): local checkpoint integrity is not an independent monotonic anti-rollback anchor.
- Upstream frozen WSP PR #3 remains unmerged; no arbitrary ref upgrades or Core source edits.

## Dependency-ordered migration

1. **No fake fallback on the live path (this PR):** lock down the existing production-facing entrypoints with adversarial AST tests; preserve the current suite floors unchanged.
2. **Operator-owned real REGTEST read acceptance:** run an existing user-owned node on a private host only after artifact/loader/custody review. Capture safe redacted RPC and genesis/index readiness evidence; do not run a daemon in hosted Work/CI.
3. **Real WSP chain acceptance:** scanner → durable SQLite → restart → one-node and two-node reorg → checkpoint restore/rescan, with actual node, release digest and execution identity bound. Synthetic CI remains independently required.
4. **GUI migration:** replace *individual* synthetic-only presentation flows with verified regtest read-only receipts; keep negative tests and add parity tests before deprecating any UI/module. Never remove a synthetic test only to make a green CI count.
5. **Sign/release boundaries:** remain OFF; do not imply any production wallet authorization from read-only regtest tests.

## Non-goals

No deletion of forensic fixtures, no Core launch, no WAM Core edits, no WSP PR #3 merge, no changes to protected production gates, no release qualification claim. This is an additive guard and actionable debt ledger, **not a claim that all mocks were deleted**.
