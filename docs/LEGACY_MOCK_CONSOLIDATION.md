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

## Checkpoint: full WSP-1 import closure (PR #136)

- **Real requirement:** importing the actual external WSP scanner transitively loads `keystore`, `core`, `store`, `watcher`, `limits` and other package Python sources. Four API blobs alone do not qualify their bytes.
- **Integrated control:** check exact upstream Git commit, every committed `src/wam_sp` Python blob and declared exact dependencies, reject missing, modified, symlinked or extra importable Python/native-extension files **before any import** in native synthetic regtest CI.
- **Mock assessment:** `tests/test_wsp1_full_source_closure.py` uses a synthetic Git tree and is **test-only**. Keep it for tampering/negative cases. Native source qualification uses a real Git checkout and real pinned WSP scanner/SQLite. No production mock fallback is introduced.
- **Removal decision:** no legacy test or module meets evidence-backed deletion conditions in this slice; leave runtime `scanner_session_workflow.py` as explicitly labeled untrusted RPC observation until GUI scanner state can be bound to a qualified external engine without exposing scan secrets.
- **Remaining:** this gate is a CI/source provenance prerequisite, NOT an operational loader, hardware trust or transitive native dependency attestation. Actual user scan accounts / encryption / GUI activation and WAM Core approval are still separate gates.

## Checkpoint: encrypted scan-only disposable intake (PR #137 candidate)

- Reuse **actual pinned WSP-1** `export_scan` / `import_scan` and `Scanner` from a previously qualified native source checkout. The application imports **no** external source by default and does not construct a `Keyring` or spend keys.
- One explicit-consent, bounded, **disposable** encrypted scan-backup session runs scanner + SQLite inside an isolated temporary directory; close and cleanup are required, failure is redacted. Native CI exercises upstream AES-GCM scan-only envelope and actual upstream SQLite/scanner with synthetic localhost RPC.
- KEEP dependency-free adversarial tests as negative fixtures. No old runtime module has yet qualified for deletion.
- This is **not durable account custody**: plaintext scan secrets exist temporarily in upstream Python objects and memory zeroization is not assured. No persistent encrypted vault, operational GUI, source loader, real Core runtime, signer, broadcast or mainnet authorization is provided.

## Checkpoint: real Scanner → Application → GUI loop (PR #139)

- **Direct integration instead of mock-only progress:** composed merged encrypted scan-only WSP intake (#137) with merged GUI WSP receipt presenter (#138) through a fail-closed application workflow. The native Linux CI runs actual pinned `import_scan`, `Scanner.sync`, SQLite and offscreen `MainWindow` against a synthetic local regtest-shaped HTTP server.
- **Failure gate:** wrong passphrase must deny before any RPC call and erase stale GUI scan receipt. GUI receives immutable scalar counters only. No API grants spend, signer, broadcast or mainnet authority.
- **KEEP:** negative security test doubles in `tests/test_scan_preview_workflow.py` because they validate cancellation, consent, cleanup and render exceptions. Native WSP-1 + Qt CI separately proves the real integrated path; no fallback to fake success.
- **Still missing:** operational WSP source loader, durable encrypted custody, event-loop worker/cancellation semantics, genuine DEV-approved WAM Core two-node regtest, independent production qualification. Qt is invoked synchronously here for a bounded CI-only test; do not enable a user scan button based on this PR.

## Checkpoint: native BIP352 receive/replay/reorg → Qt (PR #140 candidate)

- Extend the prior source-verified **actual pinned WSP-1 Scanner.sync + SQLite** CI fixture beyond genesis/coinbase: application scanner actually detects a synthetic BIP352 P2TR payment using real secp256k1 derivation, supplies its redacted scalar summary to offscreen Qt, scans the same height without duplicates, then processes a chain reorg and presents the rollback count to the same Qt window.
- Reuse real upstream database and scanner; do **not** replace existing raw WSP metrics validation, source-authentication gate, reorg negative cases, GUI authority guards or full platform tests with mocks.
- This still does not establish a genuine WAM Core network, a wallet balance, transaction acceptance, spend-key management, production receive addresses or native Win32 full-wallet packaging.

## Checkpoint: persistent encrypted WSP scan-only backup (PR #141 candidate)

- **Actual crypto, not a mock:** upstream pinned WSP `export_scan` creates AES-GCM encrypted scan-only ciphertext; a new Linux-only create-once private file store uses `openat` / nofollow, fsync, atomic hard-link publication with no overwrite, rejects bad modes, symlinks, hardlinks, oversize and partial writes.
- **Native WSP CI:** store → reload ciphertext → real upstream `import_scan` → real Scanner/SQLite synthetic scan with a *new instance*. Tampering the ciphertext is rejected by upstream authenticated decryption before any RPC.
- This **is not** a persistent scanner database, production vault, secure hardware keystore or proof against same-UID malware/directory rollback. Zeroization, portable Windows/macOS implementation, versioned backups and lifecycle worker remain out of scope.
- Keep negative synthetic filesystem tests. Never store `ScanAccount` plaintext, passphrase, seed or spender secrets in the new store.
