# SCAN-RESP-001 — Offline scanner reply-shape prefilter (research)

## Boundary

This implementation is a **pure Python, non-executing** validation of synthetic
candidate `getblock(hash,3)` responses and `getrawmempool` transaction-ID
lists. It does NOT import the WSP-1 engine, open an RPC connection, load a
wallet, handle keys, persist data, perform cryptography or scan the blockchain.

It complements—but does **not merge or modify**—the frozen Phase 010 PR #16
request-shape work. Request and response checks together are **not an adapter**:
the still-blocked real adapter must separately handle authenticated local-only
transport, network/genesis/profile attestation, verified WAM Core release
provenance, response size/bandwidth caps before JSON parsing, caller capabilities,
per-phase fresh `rpc.attest()`, cookie rotation, reorgs, cursor replay and
scanner crash consistency.

## Pinned compatibility evidence

- Upstream scanner source: `Urriki1502/wam-silent-payments` pin
  `ac55f13423620252bdbf848c7e8a280c3b84721e`.
- `Scanner._sync` requests `rpc.attest()`, then `getblockhash(h)`, then
  `getblock(blockhash,3)`; checks the exact returned `hash`, `height`,
  `previousblockhash` and the number of transactions.
- WSP-1 `Limits.max_block_transactions = 10000`.
- `Scanner.sync_mempool` checks `len(getrawmempool()) <= 10000` and unique
  txids before fetching individual transactions. Mempool scanning is **not**
  activated by this prefilter.
- These checks validate *untrusted structure*, not chain identity, consensus
  correctness, WSP cryptography, or actual transaction shape/amounts.
- The result retains only scalar item count/height/phase; it intentionally
  drops all nested transaction data. All authority flags remain false.
- Errors are stable code strings without attacker-provided payloads.

## Gates

- 14 mandatory unit tests (positive, shape mismatch, malformed values,
  reorg-chain mismatch, 10000+ limits, duplicate txids, forbidden IO).
- Mandatory contract suites increase 24 → 25, with existing floors unchanged.
- Full GUI discovery floor increases 284 → 298; the scanner does not add a GUI.
- Exact-head Windows x86/x64, macOS, Linux, GUI, CodeQL, and independent review
  are prerequisites to merge; do not lower gates for green CI.
- **This PR is independent of Draft #60 (Application) but both grow the CI
  manifest; consolidate and rerun when either is merged first.**

## Explicit HOLD

Frozen WSP-1 wallet PR #3 and frozen scanner RPC PR #16 are unchanged.
Upstream Windows native locking PR #9 remains unmerged/review-gated.
WAM Core issue #9 and binary TOCTOU issue #36 remain BLOCKED. Never
interpret this file or its tests as permission to execute WAM Core, start a
scanner, spend coins or release a production wallet.
