# Application offline GUI lifecycle — single-writer contract

**Status:** experimental presentation of synthetic/untrusted evidence only.
No wallet is loaded. No node/RPC, scanner, keys, signing, broadcasting or
production authorization is possible through these methods.

## The failure addressed

Prior to APP-LIFECYCLE-001 (issue #63), direct legacy GUI
`present_*` / `clear_*` calls could change a label without revising the
`OfflinePresentationController` snapshot. A caller reading
`offline_presentation_state` might then see a stale `PUBLIC_FIXTURE`
indicator after the associated panel had been cleared.

## Contract after the review patch

- **Single writer:** all four legacy `present_*` entrypoints validate the
  caller's exact immutable, offline-only DTO *before* rendering. Each valid
  standalone call routes through `replace_offline_presentation` and increments
  its revision exactly once. The new view contains only the supplied panel;
  previously displayed research panels are cleared. Input objects are not kept.
- **Clear all:** all four legacy `clear_*` methods delegate to
  `clear_offline_presentation` when called externally. This intentionally
  clears all panel evidence and invalidates prior revisions. Do not assume
  old per-panel clear semantics.
- **Internal rendering:** a tightly scoped depth counter suppresses recursive
  controller writes while the coordinated renderer calls individual setters
  and clearers. It is UI bookkeeping, **not a security boundary**.
- **Reject stale/malformed:** a stale expected revision or malformed DTO fails
  closed, clears the view and invalidates prior evidence. A malformed direct
  legacy present call is rejected before the displayed evidence is changed,
  preserving previous standalone GUI contract behavior.
- **Render exceptions:** an exception during a committed presentation clears
  all panels and resets the controller; error details are not shown in UI.
- **Fixed demos:** deterministic offline demos use the legacy presenter APIs
  and therefore participate in the same controller revision lifecycle.

## Regression and release checks

Four additional GUI regressions cover mixed managed/legacy presenters, legacy
clear, invalid direct values and sequential fixed demos; 10 application-only
lifecycle tests are retained. Combined total: **9 lifecycle GUI regressions**
and GUI full-discovery minimum **303** on #60 isolated branch. This branch
also preserves mandatory 25 suite targets and all previous security tests.

The scanner #64 and preflight #61 branches independently extend discovery.
When integration-ready, the cumulative CI manifests must be merged by **union**,
with all suites, critical test identities and higher case floors retained.
Do not blindly take one conflicting CI manifest.

**Never use `OfflinePresentationState` for wallet authorization or actual
chain identity.** All source DTOs and status fields remain research only.
WAM Core binary execution, WSP #3/#16, scanner and signer remain blocked.
