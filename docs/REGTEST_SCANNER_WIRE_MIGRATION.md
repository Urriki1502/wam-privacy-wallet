# Real WAM regtest scanner RPC — first wire-boundary migration

**Scope:** experimental, read-only, caller-owned and already-running local **regtest** endpoint. Does not launch Core, load a wallet, scan WSP keys or broadcast/sign.

## What has migrated off synthetic-only inputs

- `RegtestScannerReadBridge` does actual authenticated JSON-RPC over a numeric loopback address. No injected callback or hosted scanner fallback.
- Before and after a `getblock(hash,3)` or `getrawmempool` read, the bridge freshly queries genesis, chain, headers, unpruned status, height and tip with the existing local diagnostic gateway.
- Per-block `getblockhash(height)` is matched to returned block metadata; height and previous-block hash are validated using the existing fail-closed WSP response-shape model. Mempool IDs are bounded.
- Fixed method allowlists separate scanner reads from the existing identity RPC transport. No write calls, arbitrary endpoints, key import or dynamic method forwarding.
- Native CI executes the **actual loopback HTTP protocol** with a disposable deterministic fixture, including auth errors, malformed envelopes, reorg/profile changes, duplicate TXIDs, bounds and process-launch denial.

## Critical limitations (do not misreport)

- The loopback test server is a protocol fixture, **not genuine WAM Core**. Real node SHA/signature/build provenance, correct regtest protocol support and peer isolation are **not established by these CI tests**.
- The returned summary retains `SHAPE_ONLY_UNTRUSTED`, `scanner_enabled=False`, `chain_identity_verified=False`, `wallet_ready=False`. No raw transaction is returned, decoded or persisted.
- Caller-supplied previous hash is not a trusted chain checkpoint. In-flight reorg checks reject ordinary changes, not dishonest RPC peers.
- This is **not** the WSP-1 Scanner interface. It does not import frozen WSP #3/#16; no file locks, SQLite store or wallet state involved. Additional pinned upstream API/locking and regtest review are prerequisites.
- A real Core process must remain prohibited by `CORE_EXECUTION_REVIEW_REQUIRED` until #36 and #9 prove publisher-authenticated official binaries, verified-bytes-to-executed-image binding, isolated two-node profiles, and explicit DEV WAM approval. No mainnet or funds.

## Mock retirement sequence

1. Keep old offline validator as the pure untrusted-input unit-contract; make the new transport the *only candidate network path* for scanner-shaped reads.
2. After Core security gates, verify official `wamd` on isolated disposable two-node **regtest** and collect exact-head read-only RPC transcript without credentials.
3. Qualify WSP-1 upstream scanner/locking and replace synthetic scanner fixtures with genuine regtest vectors one feature at a time, retaining adversarial fixtures as regression tests.
4. Introduce crash-consistent scanner-only storage after independent writer/backup/reorg validation. Only DEV WAM can authorize any later real-money integration.

This phase deliberately does **not** delete security-negative mocks: they remain essential tests for malformed/malicious node responses. It removes the *synthetic-only boundary* for read-only RPC, not the need for deterministic tests.
