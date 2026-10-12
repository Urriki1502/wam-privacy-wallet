# V1 diagram: independent application implementations and remaining holds

This supplements the original 14-node/19-edge architecture gate. Its frozen
release/readiness categories are not evidence that a public experiment is an
operational wallet feature. Implementation evidence below does not change the
Core, signer, upstream-review, trusted-runtime or trusted-rollback gates.

| Diagram component | Application implementation | Actual executed evidence | Scope/limits |
| --- | --- | --- | --- |
| Wallet Privacy & PayJoin — selection | application/coin_selection_review.py | unchanged db3d2dca policy, 10 upstream policy + 3 property tests, 22 application cases; native Linux/macOS/Windows x64/x86 | normalized synthetic candidates; no ownership, balance or spending authority |
| Wallet Privacy & PayJoin — validation | application/payjoin_proposal_review.py | unchanged db3d2dca validator, 16 upstream cases plus application adversarial cases; all four native architectures | normalized proposals; not a raw PSBT, chain or signature validation |
| Network Privacy Policy | application/network_plan_review.py | unchanged db3d2dca network policy, 10 upstream cases plus application adversarial cases; all four native architectures | synthetic endpoint plans; no Tor/HTTP transport or network authorization |
| PSBTv2 / Signer | application/psbt_v2_review.py + isolated worker | unchanged ac55f134 unsigned decoder/Reader, 21 native cases + 2 actual worker-to-Qt cases on three x64 OS targets | unsigned whitelist only; no signer/ownership/chain; Windows x86 unqualified denial |
| Selective Disclosure | application/selective_disclosure_review.py + native/hpke_readonly | exact Git db3d2dca Rust crate, 8 upstream HPKE tests + 3 adapter tests + native fixture/Qt cases; Rust HPKE executes on x64 and Windows x86 | fixed public incoming/audit fixtures; no caller key/note or plaintext output; external crypto review pending |
| WAM Security — assurance | application/security_assurance_review.py + isolated worker | original c9b1ce87 pure provenance APIs; 3 upstream + 8 native app cases on four architectures; actual source-to-Qt cases | one constant artifact, unsigned deterministic digest; not a build/publisher/runtime attestation or independent audit |
| WSP-1 / Local Scanner | application/wsp_scan_coordinator.py, scan_preview_workflow.py | exact ac55f134 real Scanner/Store, actual BIP352 public receive/replay/reattest/reorg/Qt on x64; unchanged full Linux proof | local synthetic peer, no WAM Core; app receipts always untrusted and nonauthorizing |
| Backup / Recovery | existing encrypted_scan_backup, encrypted_checkpoint_archive, versioned_checkpoint_journal, checkpoint_recovery_workflow | real pinned crypto/SQLite/checkpoint/recovery/reorg in existing full Linux native workflow | Linux-only filesystem qualification; external monotonic anchor absent; no verified recovery or production durability grant |
| Application Layer / UI | presentation_lifecycle.py, offline_integration_status.py, gui/main_window.py | native worker/scanner-to-Qt plus 98 GUI, 18 lifecycle, 34 summary tests in the integrated branch | single-writer replacement, consent/scope, stale evidence cleared; no payment/import/sign/send actions |
| WAM SDK / RPC / User-owned Core | existing scanner-only read-RPC bridge and Core preflight/source diagnostics | synthetic loopback wire and GET-only source qualification | real Core process/owned-node chain qualification held; CORE-003 excluded |

All listed application paths are under `src/wam_privacy_wallet/`. Every source
pin remains exact: privacy db3d2dcaa540f1129d540101813b761167d33174, security
c9b1ce872c2b0b65276883d4e210b6a2f7c96467, WSP
ac55f13423620252bdbf848c7e8a280c3b84721e. Tests using mocks cover denial/protocol/
display shape only; they do not count as upstream/native execution evidence.

## Holds preserved

- Wallet #9: actual owned-node two-node/Core qualification.
- #82: signed Core member to immutable launch binding.
- #86: official Linux GNU_STACK executable-stack review by DEV.
- #153: same signed Core help/config qualification.
- #148/#151: externally trusted monotonic anti-rollback/CAS/recovery evidence.
- WSP upstream PR #9 and wallet qualification review: still pending.
- Privacy Phase15C/15D external review and maintainer handoff: still pending.
- Signer approval, mainnet, real keys/funds and transaction broadcast: absent.
- Windows x86 PSBT/WSP dependency/native GUI qualification: unqualified; denied.
- macOS/Windows retained backup/checkpoint storage: Linux gates stay in place.

These holds cannot be satisfied by a consistent synthetic chain, a source hash,
an unsigned digest, a schema-valid GUI DTO or a green unit test. The independent
read-only experiments can progress without a new Core release. A custody wallet,
real selective disclosure/export, transaction signing/broadcast and production
release remain outside the approved operational scope.
