# STORAGE-RECOVERY-001 — Read-only WSP-1 state/recovery disposition

This isolated phase uses **only caller-provided synthetic metadata**. It does
not import WSP-1 Store, instantiate SQLite, access real wallet files, verify
database locks/ownership or perform a migration. It cannot prove node
consensus, keys or publisher integrity.

## Compatibility and intent
- Pinned upstream `Urriki1502/wam-silent-payments` commit
  `ac55f13423620252bdbf848c7e8a280c3b84721e` has
  `wam_sp.store.SCHEMA_VERSION = 3`.
- The upstream Store accepts schema versions `0, 2, 3`; existing legacy
  versions follow a migration path that requires a blockchain **rescan**.
- Current WSP-1 profile, WAM regtest genesis, and case-sensitive schema are
  pinned. Any other network, profile, genesis or version fails closed.
- All `writer_lock`, `db_integrity` and `wallet_identity` fields must
  explicitly equal `UNATTESTED`. Claims of verification are rejected, rather
  than silently promoted from untrusted input.
- Version 0/2 => `MIGRATION_RESCAN_REQUIRED`. Version 3 with stale, ahead
  or mismatching checkpoint => `RESCAN_REQUIRED`. Version 3 with equal
  claimed checkpoint/tip => `REVIEW_ONLY_NOT_VERIFIED`, **not READY**.

An attacker can supply a matching fake checkpoint and tip; it remains
`REVIEW_ONLY_NOT_VERIFIED` and cannot activate the wallet.

## Qualification gates
- 18 mandatory deterministic tests; total suite floor 24→25 and GUI full
  discovery floor 284→302 (the component itself never creates GUI widgets).
- Negative tests reject schema drift, foreign genesis, bool alias, invalid
  hashes/heights, forged lock/identity/integrity, output privilege mutation,
  secrets and I/O; all may run on native Windows x86/x64, Ubuntu, macOS.
- Exact-head CI 8/8, independent CodeQL Python/Actions and reviewer
  validation are mandatory before any merge, with postmerge requalification.

## What remains required
**Do not duplicate the upstream Store writer.** Real integration must first
review WSP-1 #3 and upstream Windows locking #9, then qualify genuine
cross-process writer ownership, SQLite integrity, crash/restart and
rollback/reorg histories, backups/restore, old-schema migration, identity
binding, local WAM Core pin and explicitly authorized DEV regtest E2E.
Nothing here opens a database, gives scanner authority, signs, broadcasts,
uses keys/funds or changes WAM Core.

Parallel branches #60/#61/#64/#65 all alter suite manifests. A future
merge must take an **additive union** and run tests afresh; no floor may
shrink to make CI green.
