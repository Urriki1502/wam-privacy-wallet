# Recovery transition & desktop preview — synthetic-only Phase

## Architecture and isolation
**Source research:** `application/recovery_transition.py` extends the
pin-validated `recovery_disposition.py` contract. It compares two caller-owned
in-memory metadata dictionaries for a one-step revision transition.
Nothing here opens files, SQLite, WAL, wallets, scanner locks, RPC, Core or
key material. A matching checkpoint is NOT evidence of persistent wallet
recovery or chain provenance.

The strict transition version is `new_revision == old_revision + 1` with
bounded nonnegative native integers. Both snapshot envelopes must pass the
WSP-1 regtest profile/schema/genesis/hash/type checks independently.

Conservative outcomes:

| Observation | Output |
| --- | --- |
| Valid synthetic v3->v3 progression, no contradicting metadata | `REVIEW_ONLY_NOT_VERIFIED` |
| Legacy v0/v2 appears on either side, including 2→3 | `MIGRATION_RESCAN_REQUIRED` |
| Schema downgrade | `VERSION_DOWNGRADE`, never ready |
| Checkpoint-height decreases | `CHECKPOINT_ROLLBACK` / rescan required |
| Claimed tip height rewinds | `REPORTED_TIP_REWIND` / rescan required |
| Same-height checkpoint or tip hash changes | `CHECKPOINT_FORK_OR_RESTORE` / rescan required |
| Candidate's own snapshot is stale or inconsistent | `RESCAN_REQUIRED` |
| Reused/stale revision, foreign genesis/network, claimed authenticated writer | fixed redacted error, no intermediate result |

The output retains only bounded numeric values and fixed status words, not
hashes, paths, keys, wallet handles, history, RPC credentials or persistence
receipts. Flags `writer_verified`, `chain_verified`,
`recovery_completed`, `wallet_enabled` remain **false** under all inputs.

## GUI (integration candidate #67 only)
The new **Recovery** page is a non-authorizing display of a validated
`OfflineRecoveryTransition`. It participates as the fifth managed research
panel in `OfflinePresentationController`, sharing whole-snapshot replacement,
revision invalidation, best-effort all-panel cleanup, and fail-closed Qt
render/clear faults. The previous four research panel gates remain untouched.
It displays only fixed text for review-only / rescan / migration+rescan, never
the caller's hashes or checkpoint details. There is deliberately no restore,
backup, secret input, scanner, sign or send action.

If a source Storage disposition contradicts the accepted Recovery presentation
decision, the cross-module integration rejects the combination with a fixed
redacted error. The default empty/rejected/cleared state cannot retain a
Recovery indication. GUI state does not prove any recovery has occurred.

## Testing / qualification
- **Source #66:** 16 new offline regression tests for downgrade, migration
  carryover, rollback, tip rewind, same-height fork, revision replay, forged
  network/writer claims, secretless immutable output and blocked I/O.
  Expected native suites 25→26, GUI-host discovery floor 302→318.
- **Integration #67:** 16 source tests + 7 new GUI Recovery tests +
  3 cross-boundary consistency tests. Target **30 mandatory suites**,
  **44 GUI tests**, **406 full-discovery tests** and 19 pinned GUI case IDs.
  All older preflight, scanner, lifecycle, CodeQL and negative gates remain
  additive and must not be lowered.
- **Acceptance:** exact current-head 8/8 Wallet CI on native Windows x86/x64,
  Linux and macOS; 2/2 CodeQL Python & GitHub Actions check contexts; repository
  owner review/approval. No outside reviewer is requested by the owner.

**Explicit nonclaims:** WSP-1 Store durable migration, crash-safe DB rollback,
wallet key recovery, publisher/Core binary identity, rescan completeness,
actual chain reorg detection, real two-node testing, runtime node execution,
or production readiness. These require separately approved DEV WAM work;
frozen WSP-1 wallet #3, scanner #16, held security #50/#51 and Core binary
TOCTOU #36 are unaffected.
