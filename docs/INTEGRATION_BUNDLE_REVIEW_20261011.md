# Integration review bundle — WAM Privacy Wallet (2026-10-11)

## Purpose and pinned input
This **Draft-only** integration branch exists to validate the **additive union**
of five individually tested, still-unmerged research PRs before considering
separate acceptance/merge decisions. GitHub main is authoritative.

- Source main @ `7929dcbdcfb7d7fa4f21806ff10155f681f86bec`.
- Application lifecycle #60 @ `1141f721cc0e71edb48141d27d3429b86e163e12`
  (base of this integration branch).
- Core offline preflight #61 @ `b50b8867c5ef45356d8f8630c57e9c842eaa9382`.
- Scanner reply-shape #64 @ `dba9466782089673d0936c975f8443905d2fd668`.
- Scanner synthetic window #65 @ `a0ad602d3ed58ca78e585d09e15575a9a1137ff9`,
  stacked on #64 in its original PR.
- Offline recovery disposition #66 @
  `b76c2a47d5a72a1f92867a32b5d186f61c1f0d65`.

The component modules, docs and tests are copied from their pinned source
PR heads. Shared CI manifests are manually unioned: **no suite, GUI identity,
security-critical case or minimum may be dropped**.

## Expected exact-head discovery and negative gates

| Scope | Main | Additional on this branch | Expected |
| --- | ---: | ---: | ---: |
| Mandatory offline suites | 24 | +1 App +1 reply +1 window +1 recovery | **28** |
| Full GUI-host discovery tests (floor) | 284 | +19 App +3 preflight +14 reply +18 window +18 recovery | **356 minimum** |
| New Core binary preflight minimum | 7 | +3 | **10** |
| App lifecycle (non-GUI) | 0 | +10 | **10** |
| Scanner reply shapes | 0 | +14 | **14** |
| Scanner window | 0 | +18 | **18** |
| Recovery disposition | 0 | +18 | **18** |
| GUI pinned IDs | 4 | +9 App | **13** |

Individual PR 8/8 green results apply to **their own HEADS only** and are
**not** validation of this union. Require 8/8 Wallet CI contexts, CodeQL Python
and Actions exact head, proper independent review and governance #35 before
any main branch change. If a new combined test fails, do not bypass or
reduce it: inspect the specific job log and fix the integration defect.

## Acceptance boundaries

1. Tests are synthetic/offline research, not WAM Core binary publisher
   attestation. Issue #36 verify-to-execute remains unresolved, #50/#51 HOLD.
2. No WSP-1 #3/#16 merge or upstream locking #9 adoption without reviewer
   acceptance; no real scanner RPC, wallet writer, keys, funds, PSBT signing.
3. No WAM Core mutation, real-node launch, mainnet or release authorization.
   DEV WAM independently approves eventual real two-node E2E.
4. Never close #35 based only on a green workflow. Ruleset and independent
   reviewer evidence need to be inspected separately.
5. This bundle is **not** a substitute for reviewing each security-sensitive
   source PR. Treat its own code review and exact-head qualification as another
   gate, not an automatic shortcut to release.

## Cross-module research interaction gate — review revision 2

The original five-PR union above was verified separately at
`85dc11dbe563f588298e5553a9548de3292fc941` with **28/28 mandatory
suites and 356/356 full-discovery tests**. A *new*, additive sixth piece
was then introduced on this integration branch (not one of the five source
PRs): `application/offline_integration_status.py`.

This is a **read-only aggregation of three already-untrusted scalar DTOs**:
offline GUI presentation, synthetic scanner window, and synthetic storage
recovery disposition. Invalid or inconsistent claims fail closed with fixed
redacted errors. A normal-looking aggregate still reports
`REVIEW_ONLY_UNTRUSTED` and keeps Core, scanner, storage, signer, send and
release authority **false**. It never retains keys, endpoints, raw blocks,
database paths, RPC handles, credentials or source DTOs. It is not a
wallet coordinator or operating state machine.

The accompanying **20 cross-module regressions** include correctly typed
but internally forged states (cleared/rejected panel persistence, illegal
revision progression, fake Core/release authority), mutated scanner RPC flags,
incoherent window counts, misrepresented recovery outcomes/lock states,
immutable output, sensitive-field nonretention and no file/socket/process
access.

**Current exact-HEAD acceptance targets (supersede the table above for this
new candidate):** 29/29 mandatory suites, 376/376 full-discovery cases
(minimum floor 376), 13 GUI pinned IDs, preflight >=10, integration status
>=20; retain **every** original regression. Previously green 28/356
logs DO NOT qualify any updated HEAD. Obtain new 8/8 Wallet CI job evidence
including Win x86/x64, macOS and three GUI hosts, then independently verify
CodeQL Python and Actions and an eligible reviewer before considering any
merge. Governance #35, WAM Core #36 and frozen/held PR boundaries still apply.

## 11 Oct follow-up: repeated block identity review

A review of the stacked offline scanner-window contract detected that a
self-consistent previous-hash chain could still repeat the same block hash
at two heights, or reuse its ancestor anchor as a new block. This is a
synthetic input consistency defect (not an observed chain attack).
The original scanner window PR #65 is patched first with
`SCAN_WINDOW_DUPLICATE_BLOCK_HASH` and a negative test; the same exact
validator/test improvement is mirrored into this #67 integration candidate.
Its window mandatory floor is **19**, and **current cumulative thresholds**
become **29 mandatory suites / at least 377 full-discovery tests**. All older
29/376 and 28/356 green check results belong to older commit SHAs, and
MUST NOT be reused as qualification of the newest HEAD.

All prior real-Core, CodeQL, independent review and main ruleset blockers
remain unaltered. This negative test does not enable a scanner or node.

## 11 Oct review finding — forged empty-window transaction count

Targeted review found that a manually forged `OfflineScanWindowSummary`
could claim zero processed blocks but nonzero transactions, which could
not be produced by `validate_offline_scan_window`. The downstream
`inspect_offline_integration` now rejects this inconsistent research
metadata before producing a combined status. This prevents contradictory
display evidence; **it does not prove the data source or enable scanning**.

Added one deterministic negative regression to
`tests/test_offline_integration_status.py` and raised the mandatory
integration suite floor to **21**. The current integration candidate
requires **29 mandatory suites and a full GUI-host discovery floor >=378**
(21 new cross-module cases); all earlier 29/377 checks belong to a
previous HEAD. Requalify all eight Wallet CI jobs and both CodeQL jobs
on the latest SHA, retaining the exact-head reviewer gate.

## GUI clear-stage fault injection (11 Oct 2026)

A GUI-source review found that `replace_offline_presentation()` performed
`_clear_managed_panels()` **after accepting a controller revision but before
entering the guarded render block**. If a Qt label or direct presenter failed
in that pre-render clearing stage, the accepted revision could survive while
the display remained stale. Another panel's exception could also prevent the
remaining reset functions from running.

The clear helper now attempts **all four independent panel reset functions**
without retaining their exception payloads, then raises the redacted
`APP_OFFLINE_RENDER_DENIED` error on any failure. Both pre-render clearing
and panel rendering are guarded as one acceptance transaction: any failure
invalidates the controller revision, retries best-effort cleanup and exposes
only the fixed failure code. Explicit resets invalidate the controller before
attempting all view clears. In an actual permanently broken Qt widget, no
claim of visually successful cleanup is made; the application state is still
`CLEARED` with all operational wallet capabilities blocked.

Two adversarial GUI regressions cover a **one-time** pre-render cleanup fault
and **persistent** fault during explicit clear. They confirm revision
invalidity, reset of other unaffected panels, and fixed-error redaction. The
source lifecycle #60 now requires >=**305** full-discovery tests; combined
integration #67 now requires >=**380** full-discovery tests with **37 GUI
cases and 15 pinned GUI identities**. Earlier 303/378 PASS runs qualify only
their old commit SHAs; new exact-head Wallet CI and CodeQL must be re-read
before acceptance. This change does not touch WAM Core, WSP-1 runtime,
scanner, storage writer or any real key/funds.
