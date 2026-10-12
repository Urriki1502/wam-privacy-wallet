# Mock / prototype consolidation ledger — WAM Privacy Wallet V1

**Policy:** Every real feature integration must review mock and prototype successors *in the same PR*. Mock fixtures remain useful for negative/security tests. Never silently fall back from a failed real RPC, scanner or WAM Core invocation to fixtures. Removal requires import/reference inventory, retained invariant mapping, independent CI and review.

## Checkpoint: application scanner coordinator (PR #135)

| Existing code / fixture | Current consumers and role | Decision | Removal condition |
| --- | --- | --- | --- |
| `src/wam_privacy_wallet/integrations/scanner_window_contract.py` | Offline negative/coherence tests, no network or keys | **KEEP — testing/review model** | Only replace if equivalent adversarial chain-window invariants run against real WSP scanner + regtest and CI preserves coverage |
| `src/wam_privacy_wallet/application/scanner_session_workflow.py` | GUI Node panel's **untrusted RPC-count observation**, not a wallet scan | **KEEP SEPARATE — non-authorizing status view** | Merge with real scanner presentation only after reviewed source-qualified runtime loader/scan-only key custody, session permissions and no stale state |
| `tests/test_app_wsp_scan_coordinator.py` | Dependency-free protocol/error/cancellation mocks | **KEEP — tests only** | May consolidate duplicate tests only when coverage and critical IDs are migrated, not deleted |
| `tools/ci_wsp1_scanner_loopback.py` | Executes **real pinned WSP-1 Scanner.sync** with synthetic local HTTP peer, real SQLite and OS lease | **KEEP — integration qualification, not fallback** | Genuine approved WAM Core E2E (#9) supplements, not replaces, synthetic reorg/invalid-input tests |
| `src/wam_privacy_wallet/application/wsp_scan_coordinator.py` | New actual `scanner.sync()` invocation, explicit consent, <=16 blocks and redacted metrics | **ADD — integration coordinator** | Promote to operator runtime only after complete WSP source/dependency pin, trusted scan-only account provisioning, and reviewed GUI lifecycle |
| `src/wam_privacy_wallet/node/real_regtest.py` | Official Core execution interlock | **KEEP BLOCKED** | DEV-approved binary (#84/#86) and executed-image binding (#82), then genuine E2E (#9) |

## This PR's cleanup evidence

- **No production mock fallback introduced:** the application coordinator *requires* an externally supplied scan engine and exact scanner-only RPC; upstream exceptions produce a fixed denial and no fabricated success result.
- **No unsafe deletion:** there is no demonstrated unreferenced old module to remove in this slice. Blind deletion risks losing security properties; instead record the exact code owner and exit condition above.
- **Test-only mocks remain under `tests/`**; the native scanner CI imports the actual WSP source at the pinned revision after source verification. Neither path executes official WAM Core.
- **No automatic wallet enablement:** a successful synthetic scan returns only scalar counters. Core authenticity, balances, signing, broadcast and mainnet remain false/unqualified.
- **Future audit evidence:** before removing any module, inspect imports/callers, record the replacement PR and regression IDs, run full cross-platform CI and native pinned WSP integration, and obtain owner review.

## Next maintenance checkpoints

1. **Source provenance:** current pinned-source review authenticates four WSP blobs; an operational loader must additionally bind the *complete imported dependency closure* (including editable install exposure and dynamic imports) before creating a scanner for an operator. No implicit `import wam_sp` on the default wallet path.
2. **Scan-only account custody:** the external WSP engine stores sensitive scan secrets. Implement reviewed provisioning, encrypted storage and shutdown semantics before enabling scan in the GUI; do not reuse spend keys.
3. **Application/GUI unification:** replace offline fixture-based scanner status with strictly qualified scan run evidence in a separate explicit UI workflow. Keep harmless RPC-observation state until then.
4. **Core:** executable stack (`GNU_STACK RWE`) of signed WAM v0.1.11 remains DEV HOLD; no real Core process, no two-node E2E or signing authority.
