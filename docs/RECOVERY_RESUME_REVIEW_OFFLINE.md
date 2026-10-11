# Offline crash/restart/rescan review — research contract

## Boundaries
`application/offline_resume_review.py` operates **only on caller-provided
synthetic WSP-1 regtest metadata**. It is not a journal replay engine, file
writer, blockchain scanner, resumable token, key recovery mechanism or trusted
checkpoint. An adversary can forge two individually coherent snapshots.
The model never opens SQLite, reads WAL, makes RPC, imports WSP-1 scanning
code, starts Core, or retains addresses, private keys, hashes, paths or handles.

The caller provides before/after profiles, a sequential synthetic revision,
a bounded height at which execution was allegedly interrupted, and a fixed
untrusted event label (`CRASH`, `RESTART`, `UNCLEAN_SHUTDOWN`).
Both payloads must independently pass the existing recovery transition's
exact schema, network, genesis, version, hash and denied-authority checks.
A checkpoint allegedly *ahead* of the interruption height is contradictory.

## Classification

| Case | Research display action |
| --- | --- |
| Coherent v3 metadata even after restart | `REVALIDATE_BEFORE_RESCAN` |
| Rollback, tip rewind, fork, conflicting or stale candidate | `REWIND_RESCAN_REVIEW` |
| Legacy schema, unproven migration or downgrade | `MIGRATION_RESCAN_REVIEW` |
| Malformed input, stale revision, checkpoint ahead of interruption | fixed redacted denial |

There is **no action meaning “resume approved.”** All returned DTOs are
immutable scalar-only observations, with
`resume_authorized=False`, `scanner_enabled=False`,
`wallet_enabled=False`, `checkpoint_durable=False`,
`chain_verified=False`, `release_allowed=False`.

Neither interrupt height nor claimed checkpoint height is a valid rescan
starting point, even if the application later displays it. Determining a
safe and complete reorg rollback, historical birthday range, single-writer
lease, durable journal or verified Core tip requires independently reviewed
runtime implementation and real-node DEV WAM E2E.

## Integration into the desktop (PR #67 only)
Recovery page includes a second **Restart / Rescan · Synthetic Review** panel.
Fixed, redacted labels describe revalidation, rewind/review and migration;
no actual resume, rescan or restore button exists. It is the sixth managed
research projection under `OfflinePresentationController` and uses exactly
the same atomic whole-view replacement, revision invalidation and all-panel
cleanup if Qt raises during render.

State and summary checks reject a forged resume DTO with claimed authority,
a mismatched action/reason, impossible bounded integers, or stale
cleared/rejected research evidence. No wallet, node or process permission is
created.

## Additive test gates
- Source recovery #66: **19** new no-IO rollback/restart regressions, expected
  **27/27 mandatory suites** and **337/337 GUI-host full discovery**.
- Integrated application #67: the same **19** regressions, plus **7 GUI
  preview cases and 2 cross-module state checks**; expected **31 mandatory
  suites**, **51 GUI tests**, **434 full-discovery cases** and **23 pinned GUI
  identities**. All previous tests/floors remain.
- All exact-HEAD Windows x86/x64, Ubuntu, macOS Wallet CI **8/8** jobs and
  CodeQL Python+Actions check runs must qualify new commits independently;
  historical green checks do not qualify a new HEAD.
- Repository **owner** alone reviews and decides merge acceptance, with no
  additional outside reviewer requested.

**Not implemented:** durable checkpoint attestation, transactional recovery,
WAM Core verification/execution, WSP-1 writer lock, live scanner, disk restore,
wallet key custody, any signing or mainnet functionality. WSP #3/#16 remain
frozen, Core TOCTOU #36 and security #50/#51 on hold.
