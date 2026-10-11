# Application research-readiness adapter — offline only

This step **reuses existing WSP-1 source-inventory metadata and WAM Security review gates** in the desktop application's Privacy page. No upstream implementation is copied, imported, initialized or executed.

## Fixed inputs

- `compat/reuse_candidates.json` — eight review candidates pinned to exact source repository, paths and commit SHA. The current WSP-1 candidate pin is `ac55f13423620252bdbf848c7e8a280c3b84721e`; Silent Wallet is `44e749a5c8fde82f672d0bc9d11e43af4e52c673`.
- `compat/g0_security_gate_ledger.json` — ten fixed release/security gates, including blocks on WSP dependency adoption, signer, scanner bridge, real Core and privacy policy.
- These records are supplied **in memory** to `application.privacy_readiness.research_readiness(manifest, ledger)`; the package performs no filesystem, network or WAM Core I/O.

## Behavioral contract

1. Fail closed on missing, extra, altered or promoted manifest identities, commit pins, paths, statuses, blocked security gates and release/mainnet flags.
2. Produce a fresh immutable nine-field `PrivacyResearchSnapshot`, with `RESEARCH_ONLY`, `PIN_RECORDED_UNATTESTED`, privacy/PayJoin/network `MODEL_ONLY`, selective disclosure `NOT_INTEGRATED` and scanning/signing/sending all `BLOCKED`.
3. The Privacy page accepts only that exact non-authorizing snapshot and prints fixed, redacted labels. Invalid or forged snapshots do not mutate the display; reset removes the displayed state. Wallet session remains unloaded and node remains disconnected.
4. Application startup never auto-loads the research inventory or enables any WSP-1, PayJoin, network, scanner or signer adapter. This is **not** a capability-negotiation or permission-grant API.

## Important limitations

A 40-character Git blob SHA in a supplied manifest has only *recorded pin* status here. This seam does **not** authenticate fetched upstream bytes, prove a review occurred, attest WAM Core binaries, establish source trust, or approve integration. Existing independent validation tools and manifest/security CI suites remain intact.

Upstream `wam-silent-payments` exposes scanning, wallet proposal and broadcast functions; none of them are permitted behind this UI step. `wam-privacy` PayJoin and network-route modules remain independent offline prototypes. `wam-security` assurance runs separately.

## Tests and escalation

- Add eight dependency-light application regressions (valid pins, mutation, fake approval, dropped gates, immutable output).
- Add three GUI regressions (default disabled, canonical evidence composition, forged input and reset).
- Maintain previous 20 mandatory suite floors, add the 21st suite minimum 8, and raise the GUI full-discovery minimum **230 → 241**. Keep 10 protected check contexts unchanged.
- Future *separate* reviewed interfaces may use normalized WSP-1/PayJoin/network policy ports after upstream source provenance, consistent scanner/signer separation, mock-driven tests and approval. They are not activated here.

**Core execution, live networks, signer/scanner operation and production release stay excluded from this application's offline baseline.**
