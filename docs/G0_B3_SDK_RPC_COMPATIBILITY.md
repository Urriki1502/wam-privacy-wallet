# G0-B3 — WAM SDK / RPC reuse compatibility audit (no runtime changes)

**Status:** research / review only, **NOT qualified for scanner, signer, mainnet or real funds**.

This assessment compares the current Wallet RPC profile, WSP-1's proposed
SDK scanner adapter, the independently reusable WAM SDK and the older Silent
Wallet services. All third-party snippets below refer to immutable source
commits. **No dependency is installed, imported, copied or activated.**

## Immutable source evidence

| Source | Reviewed commit | Relevant source (Git blob SHA) |
| --- | --- | --- |
| Wallet existing Core profile | `356a27c87fc3c7aad9ea0058f332ce1ec0c6a133` | `compat/wam_core_source_pin.json`, `src/wam_privacy_wallet/node/read_rpc.py` |
| WSP-1 candidate | `ac55f13423620252bdbf848c7e8a280c3b84721e` | `src/wam_sp/adapters/sdk.py` (`f4a2c1bcb6248cd9629404d0b7934abaecef69a0`), `src/wam_sp/rpc.py` (`23624626cd7d04ce6e1915f1bef01b5002`) |
| Pinned WAM SDK dependency tree | `ac55f13423620252bdbf848c7e8a280c3b84721e` within WSP-1 | `integration-deps/wam-sdk/src/wam_sdk/config.py` (`6a1fa89f7deaa8c68200c7b8727716784b4b3563`), `client.py` (`9a5201740eb58a5f65b1c20888d677a16bad0088`), `transport.py` (`03c4ebf507de9e53a73c71dba5c0a009741f8065`) |
| Legacy Silent Wallet NodeService | `44e749a5c8fde82f672d0bc9d11e43af4e52c673` | `src/wam_silent_wallet/services/node_service.py` (`5a55d0b83ba5687cf9e86f7b211e3fa84dda6b56`) |

**Caveat:** Git SHA and blob references bind a review target; this document
does not verify signed publisher identity or the runnable node binary.
WSP-1 upstream Windows locking PR #9 and wallet provenance PR #3 remain
unmerged/review-gated.

## Capability matrix (do not conflate)

| Interface | Actual observed scope | Safe reuse decision |
| --- | --- | --- |
| Wallet `LocalReadOnlyRpc` | Direct loopback, bounded JSON-RPC 1.0, explicit in-memory Basic auth; four chain identity/profile methods | **KEEP** for diagnostic identity only. Never widen to scanner or mutation methods. |
| WSP-1 `RPC` | Cookie-authenticated, bounded JSON-RPC 2.0; read methods include block/mempool; `sendrawtransaction` is separately gated | **REVIEW_GATED**. No arbitrary RPC object exposed to UI. |
| WSP-1 `SDKChain` | Wraps `WamClient`, calls `attest()`, allowlist includes block/mempool and `testmempoolaccept`; optionally enables `sendrawtransaction` with `allow_broadcast=True` | **BLOCKED as drop-in** for scanner. Explicit read-only scanner facade needs independent review. |
| SDK `Config` / `WamClient` | Supports MAIN/TEST/REGTEST networks; `wallet().send()` and `new_address()` capabilities exist behind opt-in config; transport uses JSON-RPC 2.0 | **REVIEW_GATED** for a strictly regtest, read-only projection. Never hand unrestricted client to UI or scanner. |
| Legacy Silent Wallet `NodeService` | Constructs **both** scanner chain and broadcast chain at initialization; default `127.0.0.1:18443` | **BLOCKED as drop-in**; potential broadcast authority and mismatch with pinned WAM regtest RPC `29554`. |

## Confirmed blockers

**P0 — Authorization boundary:** Legacy `NodeService` eagerly creates
`SDKChain(..., allow_broadcast=True)` and exposes `broadcast_chain()`.
Do not instantiate/copy that service into the new Wallet scanner. No
approved application-to-signer or transaction-broadcast permission system
exists in the new Wallet.

**P0 — Profile / identity:** Current Wallet source pin specifies WAM
regtest RPC `29554` and genesis
`b88f3d262f285e38e184f50bf3eea1c8e615486ae67d3d9eaf0976fbd6d3d30d`.
The old desktop sample uses `18443`. This is an unsafe default, not
evidence of a live exploit. Randomized isolated regtest ports remain
permitted when explicitly configured and verified.

**P0 — Runtime evidence:** Wallet real WAM Core two-node E2E issue #9 is
still blocked by a verified binary and repeatable isolated runner.
Do not mark real-world scanner/broadcast or RPC wire compatibility PASS
based on synthetic tests.

**P1 — Protocol mismatch:** Wallet diagnostics speak JSON-RPC 1.0,
while WSP-1/SDK RPCs speak JSON-RPC 2.0. Core acceptance, cookie rotation,
error codes, race handling, size budgets and stale-tip policy require
independent verification. Do not silently glue one client's `call`
method into another without testing.

**P1 — Encapsulation:** `SDKChain` reaches into the SDK private
`WamClient._transport`; this is a candidate coupling/upgrade risk.
Treat the exact API as pinned and review transitive licenses/dependencies
before adopting.

## Next reviewed implementation slice (separate PR)

1. After Phase 010 scanner method-shape review, design a minimal read-only
   `ScannerRpc` interface that cannot call mutation methods and requires
   fresh `attest()` at each scanner phase.
2. Apply verified regtest-only profile, authenticated loopback endpoints,
   bounded outputs/errors, no arbitrary URLs and no hosted scanner fallback.
3. Test wrong genesis, stale tip, unavailable daemon, invalid cookie,
   unexpected methods, oversized response, reorg/race, and attempt to
   reach `sendrawtransaction`.
4. Exercise against a verified Core binary in an isolated two-node fixture;
   mark `BLOCKED` until this external prerequisite exists.
5. Perform independent security review; keep Phase 003 wallet PR #3,
   Phase 010 PR #16 and WSP-1 upstream PR #9 review-gated.

## CI nonclaim

This documentation-only PR does **not** add or relax any test.
Existing Wallet CI and CodeQL must still PASS on the exact HEAD. A passing
documentation PR is not an integration approval, network validation, or
release-readiness gate.
