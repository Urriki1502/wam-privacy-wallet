# Phase 004 — Regtest chain-identity probe (no transport)

This module is a **pure, read-only contract** for checking a user-owned WAM
Core regtest node's expected chain identity. It does **not** implement a live
RPC client or connect to the user's computer. All responses are supplied by a
caller-injected callback; CI uses synthetic responses only.

## Read-only sequence

1. `getblockhash(0)` must equal the pinned WAM regtest genesis from the
   WSP-1/Core v0.1.11 profile.
2. `getblockcount` must return a real `int` (not `bool`), between 0 and
   100,000,000.
3. `getbestblockhash` must return a canonical 64-character lowercase hash.
4. `getblockhash(height)` must equal the reported best-block hash.
5. Best-block hash and height must remain unchanged on a second read.

The only acceptable endpoint descriptor is `LocalRegtestEndpoint` (numeric
loopback and caller-supplied port; `network='regtest'`). The probe never
calls wallet, signer, send, or raw-transaction RPC methods. It has no file
operations, wallet keys, credentials, or transport implementation.

### Critical security limitations

- An injected callback **could connect remotely or forge responses**. This
  pure contract cannot prove the actual network peer or full-node binary.
  A separate transport must enforce real socket-level loopback destination,
  no proxy/redirect, authenticated RPC, minimum permissions, trusted Core
  version, and validated network genesis before use.
- A stable tip is **not** a cryptographic chain-consensus proof. An attacker
  could emulate RPC replies. No actual regtest node was contacted by CI.
- This module is not linked to WSP-1 scanner and must not be used for real
  funds or mainnet. Core profile must be rechecked before adoption.
- A full Windows x86 GUI and cryptographic runtime is **not** qualified by
  these architecture tests. See `WIN32-PACK-001`.

## Test gates

Ten synthetic tests cover accepted stable regtest, height zero, wrong genesis,
malformed hashes and heights, tip reorg/race, transport-error redaction,
endpoint type enforcement and exact method allowlist. GitHub Actions runs
Python 3.12 on Windows x86/x64, macOS x64 and Linux x64, validating native
pointer width. Every job is a **contract-only smoke test**, not connected
WAM Core functionality.
