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
