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

## Reentrant Qt transaction poisoning (11 Oct 2026)

Security review of the single-writer GUI identified a *reentrant callback*
interleaving not covered by earlier render/clear exception tests: a Qt widget
callback could invoke public `clear_offline_presentation()` or
`replace_offline_presentation()` while an outer transaction was already
clearing or rendering research labels. A nested update could otherwise alter
the revision, and a swallowed nested failure could allow the outer accepted
snapshot to survive in an inconsistent visual state.

The GUI now maintains a **per-window active transition guard**. Any nested
public clear/replace is rejected with fixed, redacted
`APP_OFFLINE_REENTRANT_DENIED` and permanently poisons the enclosing
transaction until it rolls back. Even when the inner callback *catches* the
error, the outer transaction detects the poison, invalidates the accepted
revision, retries best-effort all-panel cleanup and raises the redacted
`APP_OFFLINE_RENDER_DENIED`. A later valid update can proceed with a fresh
revision; no source DTO is retained. The guard has no persistence and grants
no wallet, WSP scanner, Core execution or signer authority.

Three deterministic GUI tests inject (1) nested clear during rendering,
(2) nested replace during panel clearing, and (3) nested replace during
explicit clear followed by an ordinary valid update. They assert fixed errors,
revision invalidation and that unaffected panels remain cleared. The
required additive GUI discovery threshold is **308** full tests,
with **40** GUI cases. All previously pinned GUI and native mandatory
IDs remain required. Earlier green runs belong to previous Git commit SHAs;
only new exact-head Wallet CI 8/8 and CodeQL Python/Actions 2/2 qualify this
change. Owner decides final acceptance; no outside reviewer required.
