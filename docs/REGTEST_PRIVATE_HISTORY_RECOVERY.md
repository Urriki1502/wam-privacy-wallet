# REAL WSP-1 REGTEST session: private transaction history + checkpoint recovery

Implementation operates on the **actual pinned upstream WSP-1 Scanner and
SQLite Store**. It adds no fake runtime backend and no home-grown signing or
cryptography. The session exposes bounded PRIVATE history (txid, block height,
credit/debit atoms, confirmations), with explicit consent, a fresh current
scanner and a native single-writer SQLite lease. No raw history is put into the
existing Qt read-only review receipt or telemetry.

Source-pinned WSP-1 `Store.export_checkpoint` produces authenticated AES-GCM
ciphertext. The existing Linux create-once private archive stores those bytes
without re-encryption. A new empty Store can restore the ciphertext with the
original upstream `Store.restore_checkpoint`; restored state must perform a
fresh scanner/RPC sync before history or UTXO presentation. No cached mempool
state becomes current on restore.

**Boundaries:** Linux x64 experimental disposable regtest only; native CI uses
a synthetic localhost RPC peer to exercise real WSP and SQLite paths. Real
WAM Core two-node E2E #9, executable #82, GNU_STACK #86, config parity #153,
trusted rollback anchors #148/#151, and upstream WSP review remain pending.
SQLite is unencrypted on disk. An AES-GCM checkpoint does not prevent restoring
a stale yet valid state. The checkpoint is create-once (not rotatable).
Transaction signing, wallet broadcast, real keys and mainnet are never enabled.

The native proof adds private paginated SQLite history and actual AES-GCM
restore→rescan checks, raising the positive native case count 15→17.
