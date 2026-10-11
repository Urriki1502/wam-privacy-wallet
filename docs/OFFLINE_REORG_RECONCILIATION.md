# Offline reorg reconciliation: transition ↔ resume ↔ segment claims

## Scope and threat model
`application/offline_reorg_reconciliation.py` is a pure in-memory research
classifier. It accepts three **untrusted** DTOs representing the same
*synthetic* WSP-1 regtest interruption: `OfflineRecoveryTransition`,
`OfflineResumeReview` and `OfflineRescanSegments`. Passing any of these
checks does **not** attest WAM Core, consensus history, scanner correctness,
WSP-1 identity, a database writer, journal durability or a safe rescan cursor.
No socket, process, file or wallet handle is opened or retained.

The receipts have to agree on the exact non-boolean integer revision,
claimed checkpoint, interrupted horizon and review intent. Individually
plausible receipts are rejected if they contradict each other.
A coherent but forged trio remains `REORG_RECONCILIATION_UNTRUSTED`.

## Conservative consistency gates
- **Ordinary preview:** claimed segment start must equal the claimed
  checkpoint height; no actual checkpoint trust or progress authority.
- **Rollback/fork/rewind review:** segment start must not be ahead of the
  checkpoint; a synthetic recheck gap >**128** blocks is rejected, but
  this cap is **not** a real chain reorg limit or safe rewind policy.
- **Migration review:** research segments must claim a genesis anchor of
  height 0. This is a strict *fixture* assumption, not a prescription for
  a wallet birthday scan or real migration procedure.
- **All modes:** claimed processed segment end may not exceed the
  interruption horizon. Numbers are checked for bounds, exact native types,
  impossible counts, authority flag forgery, and redacted fixed-code errors.
- The source segment model's **one immediate identical replay** is never
  counted twice. Six deterministic *metamorphic* replay variants verify that
  appending one identical segment preserves unique block/transaction counts.
  Mutation of hash, attempt or count must fail.
- A displayed rollback verdict takes precedence over a replay label; replay
  status alone never hides the requirement for further review.

Returned data has only fixed verdicts and bounded scalar counts.
`chain_verified`, `checkpoint_durable`, `restart_authorized`,
`rescan_authorized`, `scanner_enabled`, `wallet_enabled` and
`release_allowed` all remain **False**.

## Desktop projection (integration PR #67)
The Recovery page adds a read-only **Checkpoint / Reorg · Synthetic Review**
panel as the eighth managed research view under single-writer
`OfflinePresentationController`. It shows only fixed labels for
`NO_PROGRESS_EVIDENCE`, `CONTIGUOUS_BUT_UNVERIFIED`,
`REPLAY_NOT_DOUBLE_COUNTED`, `ROLLBACK_RESCAN_REVIEW`, and
`MIGRATION_RESCAN_REVIEW`. No numeric cursor/hash is exposed. The GUI
rejects synthetic verdicts that contradict concurrently displayed
Recovery, Restart or Segment receipts. Any invalid input or Qt error
invalidates the accepted revision and clears every independent panel.
No button initiates a rescan, restore, wallet load or signer.

## Additive acceptance
- Source Recovery [#66](https://github.com/Urriki1502/wam-privacy-wallet/pull/66):
  **24** deterministic cross-source/mutation tests,
  **29 mandatory suites / 384 full-discovery tests**.
- Integrated [#67](https://github.com/Urriki1502/wam-privacy-wallet/pull/67):
  same 24 tests, **7 GUI + 3 cross-boundary tests**,
  **33 mandatory suites / 499 full-discovery tests**,
  **64 GUI tests**, **31 pinned GUI identities**.
- Both exact-head Wallet CI 8/8 and CodeQL Python+Actions 2/2 must complete
  successfully before owner acceptance. CI success is not an external audit.
- Repo owner personally reviews and decides on merge; there is no outside
  reviewer requirement for this development phase.

## Explicit exclusions
No production-grade chain fork/finality inference, persistent replay
deduplication, rescan starting-point selection, verified checkpoint resume,
WAM Core launch/RPC, scanner engine, database restore/WAL, signing, private
keys, balances, money or mainnet interactions. Frozen WSP wallet/scanner
#3/#16 and held security #50/#51, TOCTOU #36 remain untouched.
