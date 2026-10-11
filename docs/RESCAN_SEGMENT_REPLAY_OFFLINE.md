# Bounded offline rescan segments & immediate replay — research contract

## Purpose and precise limitation
This adds `application/offline_rescan_segments.py`, a **pure**, bounded,
in-memory consistency check for a small list of caller-controlled synthetic
segment envelopes. It is **not a WSP-1 scanner or persistent idempotency
implementation**. No trust in Core, RPC, chain provenance, checkpoint
durability, wallet writer lease, transaction identity or rescan completeness
can be inferred from passing this model.

A valid `OfflineResumeReview` input is required with an exact matching
synthetic revision, blocked capability flags and one of three fixed untrusted
resume actions. Each segment must be an exact-shape dictionary containing
bounded `start_height`, `end_height`, `parent_hash`, `end_hash`,
`transaction_count`, and `attempt`. Up to **8** segments per call,
**16** blocks per segment and **20,000** aggregate claimed transactions
are accepted for research. Inputs must use native exact types (no bool as
an int), 64-character lowercase ASCII hex hashes, an uninterrupted chain of
synthetic intervals and linked parent/end hashes. Cycles back to an ancestor,
gaps, overlaps and conflicting digests fail closed.

## Replay / restart interpretation
A **single immediate, byte-for-byte-equivalent logical segment replay**
(same six typed fields) is recognized in the supplied tuple. Its claimed
blocks/transactions are **not counted twice** and result disposition becomes
`REPLAY_NOT_APPLIED`. More than one replay, a replay that is not adjacent,
a changed attempt, changed hash, or new segment following a replay is denied.
Even a correctly deduplicated tuple confers **NO restart idempotency across
process restarts**, because no durable history or trusted last-writer identity
is stored. The returned summary includes counts/height only; it never
retains block hashes, input objects, private keys, paths or handles.

Three display-only dispositions:
- `NO_SEGMENTS`
- `CONTIGUOUS_UNVERIFIED`
- `REPLAY_NOT_APPLIED`

Every output has `scanner_enabled=False`, `resume_authorized=False`,
`checkpoint_durable=False`, `chain_verified=False`,
`wallet_enabled=False`, `release_allowed=False`.

## Application projection (#67 only)
The Recovery screen gains **Rescan Segments · Simulated Accounting** as a
seventh, non-authorizing panel, under the same single-writer lifecycle and
redacted Qt failure cleanup as the other six. It shows only fixed labels,
not caller-controlled heights, hashes or transaction data. Clear/reset and
stale revisions remove all evidence. When a resume DTO and a segment DTO are
supplied atomically, the application requires matching synthetic resume
revisions/actions. No button starts a scan, resume, wallet load, backup or
signing operation.

## Strict acceptance
- Source Recovery #66: **23 new deterministic tests**, **28 mandatory suites**,
  **360 full-discovery tests**, 26 legacy GUI cases, no Core/RPC/SQLite.
- Integrated #67: identical source module and 23 source tests, plus
  **6 GUI and 2 cross-component regressions**. Expected **32 mandatory
  suites, 57 GUI tests, 465 full-discovery cases and 27 pinned GUI IDs**.
- Rerun full native Wallet CI **8/8** and CodeQL Python/Actions **2/2**
  on exact current head; older commit-green runs do not qualify new code.
- Owner reviews and decides acceptance; no independent outside reviewer is
  requested.

**Not delivered:** real wallet scanner, transaction-level deduplication,
journal replay, durable recovery checkpoints, WAM Core attestation,
reorg-correct rescan plan, restart idempotency, WSP Store writer, keys,
funds or production release. WSP wallet #3/scanner #16 remain frozen;
held security #50/#51 and Core launch TOCTOU #36 are unaffected.
