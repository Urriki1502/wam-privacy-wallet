# WAM Privacy Wallet V1 — Privacy Integration Sprint

Start main, verified live: `51d523f05c082a4935145477c774ec2b38e2e832`.
Work credit balance is not exposed by this session. No consumption percentage
is claimed. Bounded engineering units and a final handoff reserve are used.
Previous sprint artifact: `docs/2026-10-13-credit-sprint-handoff` at
`a27a9cde399ec41649d3df2979f3c1c435093aa3` (four code PRs #186–#189 merged).

## Source inventory and reuse map

| Source repository / exact commit | Existing module | Wallet target / adaptation | Evidence |
| --- | --- | --- | --- |
| Urriki1502/wam-privacy / `db3d2dcaa540f1129d540101813b761167d33174` | `prototypes/payjoin_safety/{model,validator}.py` | Existing unchanged `research_models/payjoin_safety`; extend `application/payjoin_proposal_review.py` with fixed read-only PSBTv2 worker | Exact upstream blobs `8e3e8be096a66fc960f75a56f1ac34daa9306017`, `598596a8bde118204b3baf69bb53a884c6dad21a`; upstream 16-test gate |
| Same privacy commit | `prototypes/network_privacy/{model,policy}.py` | Existing unchanged `research_models/network_privacy`; strengthen `application/network_plan_review.py`, no operational transport | Blobs `efba5aa0f4cd7d57615dfde47206e7e0dde8d865`, `3d24c9a9a010220503e6c81251da7c42309a63a0`; upstream 10-test gate |
| Same privacy commit | `prototypes/wallet_privacy/{model,policy}.py` | Reuse existing `application/coin_selection_review.py`; no rewrite | Existing pinned coin-selection CI |
| Urriki1502/wam-silent-payments / `ac55f13423620252bdbf848c7e8a280c3b84721e` | `src/wam_sp/psbt.py` | Shared existing source/dependency/no-sign worker gate; parser and public receiver-signature verification; no second signing implementation | Full source closure, native `tools/ci_pinned_psbt_v2.py` |
| Same WSP commit | Scanner / Store history | Existing `QualifiedScanSession.history` / native scanner lease; candidate selected-record local export only | Native synthetic-chain WSP runner; Core acceptance separate |
| Urriki1502/wam-security / `c9b1ce872c2b0b65276883d4e210b6a2f7c96467` | Existing independent regression assurance | Existing pinned worker retained | Existing native security CI |
| Urriki1502/wam-silent-wallet / live `44e749a5c8fde82f672d0bc9d11e43af4e52c673` | Separate wallet architecture | Inventory only; existing WSP/application boundary already covers this unit | No code imported or qualification inferred |
| Privacy shielded-note / CORE-003 research | Halo2, consensus state, viewing protocol | EXCLUDED; original source/frozen branches untouched | Application exports must not import this closure |

## Live verification

Wallet #170–#183 are merged, including #182 `f29208926b07a41c381fd9ceea2a403da63a4a5f`
and #183 `9cd6397bbe771167dcb377839e8d44c80c403895`. No recreation.
Upstream WSP #3 remains OPEN/DRAFT/HOLD at
`396f444e3a5f1b8f3105144c6fa8dd7e465e7fae`.
Wallet issues #82/#86/#153/#9/#148/#151 remain OPEN.
Core main is `c85259102a366caf62ea82837775f9bd47af1efc`; no change since the
previous handoff today. Latest official release remains v0.1.11 prerelease.
The release API still reports Linux archive SHA256
`bd010ed615ab8063d5c12aa61236311ece7e9d19896d9541dacba1888dd9987a`.
Prior genuine GPG/hash/readelf/NOEXEC evidence remains the static baseline;
no new signature revocation, secure launch or runtime qualification is inferred.
No Core execution or --help is performed in this sprint.

## Unit B — exact PSBT PayJoin review

The application authorizes only an explicit local synthetic-regtest review.
A fixed fresh worker reuses full WSP source/dependency/origin qualification,
read-only audit instrumentation and no-sign profiling. Exact PSBTv2 bytes are
parsed using upstream Reader/PSBT. Unknown fields, keypaths, partial signatures,
modifiable globals, unsupported non-P2TR structures and sender final witnesses
deny. Sender outpoints/order/amounts/sequence and witness UTXO scripts are
preserved. Receiver final key-path witnesses are verified with the existing
WSP public signature verifier. Unchanged privacy validator enforces protected
outputs, no substitution and zero sender fee contribution.

**Limits:** candidate original inputs do not prove wallet ownership; witness
UTXO annotations do not prove chain inclusion. No PSBT, keys, signature,
amounts, script or signer objects return from the worker. All ownership, chain,
signing and broadcast flags remain false. No network, Core or wallet signer is
called. Native tests construct disposable transactions with publicly fixed
fixture scalars; this is synthetic transaction evidence, not Core E2E.

Local focused boundary suites and actual native source tests are recorded in
the PR. CI/merge acceptance is pending until exact-head checks are observed.

## Completed units and observed CI checkpoints

| Unit / PR | Exact reviewed head | Merge | Actual evidence |
| --- | --- | --- | --- |
| A/B — inventory + PayJoin [#190](https://github.com/Urriki1502/wam-privacy-wallet/pull/190) | `2b9447931e079debb639717cdff323987a7f31ed` | `ab0ee910ecee645cad65e7656cdbbc9992aeaf39` | All 16 applicable checks success: Wallet 8/8; PSBT native 4/4; CodeQL language/aggregate. Ubuntu full discovery 1413/1413 |
| C — network [#191](https://github.com/Urriki1502/wam-privacy-wallet/pull/191) | `ccf28ae371b1e5d5464c09aca40c14512900687f` | `137efdd4e1ff9244d0aa44bf46c72aa2011e5c45` | All 12 applicable checks success: Wallet 8/8; CodeQL. Full discovery 1419/1419 |
| D — selected export [#192](https://github.com/Urriki1502/wam-privacy-wallet/pull/192) | `c0b4be1ba19ad03559314197b036ea9326512ccf` | `21ab2b5df08fac6d618443999819c802f6202bb2` | All 21 applicable checks success: Wallet 8/8; WSP 5/5; desktop preview 4/4; CodeQL. Full discovery 1436/1436; actual Linux WSP session 19/19 |
| E — canonical witness + architecture sync | Recorded in this PR's final checkpoint comment | Pending exact-head CI at document authoring | Local native PSBT/PayJoin/Qt 34/34, traceability 8/8, Qt 30/30, CI gate 14/14; final merge evidence must be observed separately |

CI URLs:
- #190 [Wallet](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38364143484), [actual PSBT](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38364143481), [CodeQL](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38364140923).
- #191 [Wallet](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38365318809), [CodeQL](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38365316546).
- #192 [Wallet](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38366320890), [actual WSP](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38366320791), [preview build](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38366320776), [CodeQL](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38366316758).

Unit D's first head `98018d259b40909fb8c09e37204863b289e9edd2` was superseded
when #191 merged; only the recorded current-base head qualified the merge.
All source models remain unchanged. The sole new witness regression initially
failed (no denial); the fixed worker rejects explicit DEFAULT=0 in a 65-byte
signature BEFORE the existing public verifier. See
[canonical-witness evidence](PAYJOIN_CANONICAL_WITNESS_REVIEW.md).

## Architecture categories — separated

| Component | IMPLEMENTED | TESTED | INTEGRATED | ACCEPTED | BLOCKED |
| --- | --- | --- | --- | --- | --- |
| Wallet privacy / PayJoin | Existing coin-selection; fixed PSBTv2 review with unchanged validator | Actual pinned source parser/public verifier; synthetic transaction fixtures; malicious fee/output/metadata cases | Existing application review + fixed read-only worker | Operational NO | Authenticated ownership/UTXO inclusion, actual Core compatibility, trusted consent and signer handoff |
| Network policy | Existing source policy + no fallback/canonical endpoint application restrictions | Unchanged source tests + application and Qt negatives | Existing non-authorizing application/Qt review | Operational NO | Actual private transport/runtime availability and first-hop evidence |
| Selected disclosure | Local selected records/fields, one-use exact-byte approval, cancellation/expiry | Actual WSP SQLite/Qt with synthetic chain; scope/concurrency/redaction cases | Existing private Qt history -> preview/export APIs | Operational NO | Trusted selection/save UX; reusable consent/proof protocol not implemented |

The traceability gate fixes these three application-review statuses and paths;
all external WSP/security, official Core/ELF HOLDs, 14 nodes, 19 edges and false
operational flags stay enforced. Legacy privacy-readiness DTOs remain
conservative operational readiness, not a route to activate these review APIs.

## Issue-by-issue disposition and blockers

| Issue | Status / classification |
| --- | --- |
| #120 | Genuine application integration progress; remains OPEN for operational acceptance |
| #82 | OPEN/BLOCKED — DEV Core secure release and independent immutable process/loader qualification |
| #86 | OPEN/BLOCKED — upstream executable-stack review; v0.1.11 remains GNU_STACK RWE |
| #153 | OPEN — future same-build signed example/help evidence; internal schema review alone cannot accept it |
| #9 | OPEN/BLOCKED — actual Core two-node startup/RPC/payment/reorg/restart/restore/rescan NOT RUN |
| #148 | OPEN — existing authenticated local checkpoint/journal; independent freshness unqualified |
| #151 | OPEN/BLOCKED — independent monotonic provider/attestation not available; protected restore denies |

Internal executable tasks are distinguished below from DEV/future Core release
and independent runtime/anchor/security qualification. No upstream repository
or frozen branch is changed; upstream WSP #3 stays OPEN/DRAFT/HOLD.

## Real code versus synthetic environments

Real unchanged source: privacy validators; WSP PSBT parser and public signature
verifier; native Linux WSP Scanner, SQLite, encrypted scan import/restore and
Qt. Synthetic/disposable inputs: publicly fixed transaction keys/PSBTs,
normalized policy fixtures, local RPC chain peer and adversarial/fault inputs.
Native Linux/macOS/Windows jobs are observed separately; Windows x86 parser
and non-Linux retained-persistence jobs are explicit denial evidence only.
No Tor/I2P/OHTTP runtime adapter, Core process or --help is executed. No actual
WAM Core v0.1.11 runtime test occurs in this sprint. The preceding genuine
signed/hash/NOEXEC/readelf evidence is preserved, not relabeled as new E2E.

## Files changed and meaningful behavior

- `application/payjoin_proposal_review.py`, `_payjoin_psbt_worker.py`, `_psbt_v2_worker.py`: exact-byte, source-pinned read-only wire review; reuse no-sign qualification; preserve sender scripts and fee/output constraints; canonical receiver-witness check.
- `application/network_plan_review.py`: reject every fallback, reuse numeric RPC loopback policy, deny endpoint aliases and unused scope; no transport activation.
- `application/selected_history_export.py`, `gui/regtest_window.py`: selected minimal local observation export, exact-byte approval/one-use/expiry, private GUI revision/cancellation/consent boundary.
- Tests: `test_payjoin_proposal_review.py`, `test_network_plan_review.py`, `test_selected_history_export.py`, `test_regtest_gui.py`, `test_architecture_v1_traceability.py`, `test_ci_contract_gate.py`: adversarial, wire, consent, scope and HOLD regressions; all prior suites preserved.
- Tools: `ci_pinned_psbt_v2.py`, `ci_qualified_scan_session.py`, `ci_contract_gate.py`, `gui_ci_contract_gate.py`, `architecture_v1_gate.py`: actual pinned native tests, additive 84-suite and 1387 full-case floors, exact non-operational architecture targets.
- Workflows: `psbt-v2-native-readonly.yml`, `wsp1-real-scanner-synthetic-regtest.yml`: trigger the existing relevant native gates for the new modules; no CI protection weakened.
- Documentation: README; ARCHITECTURE, ARCHITECTURE_V1_PLAN, ARCHITECTURE_V1_TRACEABILITY, ROADMAP, THREAT_MODEL; this durable reuse/handoff ledger; NETWORK_PRIVACY_APPLICATION_POLICY, SELECTED_HISTORY_LOCAL_EXPORT, PAYJOIN_CANONICAL_WITNESS_REVIEW.
Paths above are relative to `src/wam_privacy_wallet`, `tests`, `tools`,
`.github/workflows` or `docs` as appropriate. The final immutable handoff adds
an exact path list and live branch/PR heads.

## Residual risks / resolved failures

Source checks and audit/profile hooks do not constitute hostile-process or OS
custody isolation. Sender ownership and annotated prevout inclusion remain
unproven. Actual private transport, first-hop anonymity, trusted UI, key custody,
independent rollback anchor and operational release qualification remain open.
Selected txids/amounts are sensitive private data; already previewed/exported
copies cannot be revoked or securely erased in Python. Export does not supply
an authenticated proof. Existing SQLite metadata remains unencrypted.
The malformed-witness regression is fixed; initial source-bytecode cache was
correctly denied; isolated local worker installation was pointed to the tested
worktree after editable packaging lacked its build backend. Native GitHub
installation uses its existing workflow and is qualified separately.
Local full-discovery has the two known prior /proc identity errors established
at the earlier baseline; no skip or weakened gate was introduced. Actual
GitHub full discovery results above are observed, not inferred from local runs.

## Next three executable engineering tasks

1. #120: `application/payjoin_proposal_review.py`, `_payjoin_psbt_worker.py`, `qualified_scan_session.py` — design and test a read-only source-qualified sender-outpoint/UTXO ownership comparison, reject receiver-added wallet-owned coins; no signing authority or real Core execution. Reuse #190 and the canonical-witness follow-up, not a new signer.
2. #120: `gui/regtest_window.py`, `application/selected_history_export.py`, `tests/test_regtest_gui.py` — implement a visible selected-row/field preview/save UX and reviewed create-once private file output, bind GUI revision/cancel/consent to exact bytes and test partial-write faults. Keep observations unqualified and no external sharing/proof.
3. #120: `application/network_plan_review.py`, `node/endpoint.py`, `tests/test_network_plan_review.py` — specify a bounded actual private-transport readiness/evidence interface, test unavailable route => denial with no direct fallback. Any real adapter/route acceptance needs separate runtime proof; do not infer Tor/I2P/OHTTP operation from names. Core #82/#86/#153/#9 and anchor #148/#151 remain external gates.

## Ready-to-use continuation prompt

Continue Urriki1502/wam-privacy-wallet from the final immutable Privacy
Integration handoff and live main. Fetch GitHub first; never assume this
checkpoint HEAD is current. Read docs/PRIVACY_INTEGRATION_2026_10_13.md,
ARCHITECTURE_V1_PLAN.md, ARCHITECTURE_V1_TRACEABILITY.json and the three privacy
security documents. Do not recreate #170–#183/#186–#192 or the canonical
witness/traceability follow-up. Verify exact privacy/WSP pins and open PR heads.
Preserve unchanged source models, no CORE-003, WSP upstream #3 HOLD and all
Core/checkpoint operational gates. Reuse the pinned read-only PayJoin worker,
strict no-fallback network review and one-shot selected local export; no second
signer, proof, hosted scanner or mock Core acceptance. Start with the prioritized
internal ownership or selection/save UX task. Work in complete committed/pushed
units; require exact-head/current-base Wallet/native/CodeQL evidence before
merge. No Core process, real keys/funds, signing, broadcast or mainnet is
authorized. Update the durable ledger and final live main/CI/branch handoff.

## Final synchronization rule

The self-referential final merge SHA cannot be embedded in its own committed
file. Exact final main, this unit's head/merge/CI, any unmerged branch heads and
stop/reserve decision are recorded in the final PR handoff comment and the
intentional documentation checkpoint artifact. No CI PASS is claimed for a
pending unit at document authoring. All finished code must be recoverable on
GitHub; no unfinished engineering branch or local-only completed change is
allowed at final handoff.
