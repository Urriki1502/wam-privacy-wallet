# Selected history local export — review foundation

This application feature reuses source-qualified WSP-1
`ac55f13423620252bdbf848c7e8a280c3b84721e` Scanner/Store history and the
existing `PrivateHistoryPage` / private Qt history projection. No shielded-note,
CORE-003, Halo2, consensus state or viewing-key research is imported.

`LocalHistoryExport` accepts 1–20 explicitly selected transaction IDs already
present in the approved history page and an exact nonempty field allowlist:
height, confirmations, credit atoms, debit atoms. No default-all, silently
missing row, duplicate selection, unknown field, seed/key/script/tweak or
caller object callback is accepted. Txids are inherently sensitive: they leave
the private view only through explicit local review and final approval.

The canonical JSON labels records as unqualified local WSP observations as of
one reported tip, not current authenticated chain facts. The snapshot includes
neither wallet/account identifiers nor source-page rows outside the selection.
It never grants spend authority or claims a cryptographic proof. A hash binds
approval to exactly the reviewed export bytes; it does not authenticate Core,
ownership, inclusion or scanner provenance. Caller-constructed DTOs can be
forged and remain unqualified. Existing SQLite consistency/currentness checks
belong to `QualifiedScanSession.history`, not this export policy.

Pending approval lives in memory, expires at 120 monotonic seconds, and is
consumed on every final export attempt. Cancellation, denied consent, incorrect
hash, GUI navigation, a new lifecycle revision, history replacement, consent
withdrawal and close clear pending state. A lock permits one concurrent export
winner. This is a **local user-authorized copy**, not a reusable authorization;
revocation cannot retract bytes already previewed/copied or provide secure
Python-memory erasure. Private preview/row representations and errors omit
contents. No application telemetry or filesystem/network write is added.

Integration: existing WSP history -> private Qt receipt ->
`RegtestWindow.prepare_selected_history_export` -> exact private preview ->
`export_selected_history`. Both APIs require the same active REGTEST revision,
Transactions page, separate history consent, local unverified-Core acknowledgment
and no running worker. There is no new operational transport, signer, Core
execution, file-saving widget or external sharing action. A selection/save UX
and trusted consent qualification remain separate next tasks.

Tests: 14 independent policy adversarial cases; three new actual Qt boundary
cases alongside the prior 27; the existing source-pinned native Linux WSP
runner now checks real SQLite -> selected export and real Qt -> approved bytes
against a synthetic chain peer. Native Win/mac persistence remains explicitly
unqualified. CI results are pending until observed on the PR head; no genuine
Core E2E is claimed. All Core/checkpoint/WSP HOLDs stay unchanged.
