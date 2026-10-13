# WAM Privacy Wallet — Sprint Handoff

Privacy Integration Sprint, final synchronized artifact.

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
the PR. That authoring-time CI snapshot is superseded by the completed PR evidence below.

## Completed units and observed CI checkpoints

| Unit / PR | Exact reviewed head | Merge | Actual evidence |
| --- | --- | --- | --- |
| A/B — inventory + PayJoin [#190](https://github.com/Urriki1502/wam-privacy-wallet/pull/190) | `2b9447931e079debb639717cdff323987a7f31ed` | `ab0ee910ecee645cad65e7656cdbbc9992aeaf39` | All 16 applicable checks success: Wallet 8/8; PSBT native 4/4; CodeQL language/aggregate. Ubuntu full discovery 1413/1413 |
| C — network [#191](https://github.com/Urriki1502/wam-privacy-wallet/pull/191) | `ccf28ae371b1e5d5464c09aca40c14512900687f` | `137efdd4e1ff9244d0aa44bf46c72aa2011e5c45` | All 12 applicable checks success: Wallet 8/8; CodeQL. Full discovery 1419/1419 |
| D — selected export [#192](https://github.com/Urriki1502/wam-privacy-wallet/pull/192) | `c0b4be1ba19ad03559314197b036ea9326512ccf` | `21ab2b5df08fac6d618443999819c802f6202bb2` | All 21 applicable checks success: Wallet 8/8; WSP 5/5; desktop preview 4/4; CodeQL. Full discovery 1436/1436; actual Linux WSP session 19/19 |
| E — witness + architecture [#193](https://github.com/Urriki1502/wam-privacy-wallet/pull/193) | `6fa2091de098d7fb3e5e8404db43101a2e7a504c` | `66161a021a9782f03cbb14fd33a7e4be7ee3db9b` | All 16 applicable checks SUCCESS; Wallet 8/8, native PSBT 4/4, CodeQL; full discovery 1438/1438, actual PSBT/PayJoin/Qt 34/34 |

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

## WAM Privacy Wallet — Final Sprint Handoff

Start wallet main: `51d523f05c082a4935145477c774ec2b38e2e832`.
Final verified wallet main: `66161a021a9782f03cbb14fd33a7e4be7ee3db9b`.
Final source tree: `d2d8fdb559fee92828ff1ecbcf613b0895c4f3cb`, identical to the reviewed #193 tree.

All four engineering PRs #190–#193 are MERGED. No unmerged sprint code,
uncommitted completed work, abandoned engineering unit or interrupted ref/PR
operation remains. Extra engineering worktrees were removed after confirming
their authoritative remote heads; the original detached baseline remains for
reproducing the two prior local /proc identity errors. Source clones are clean.

Final #193 head `6fa2091de098d7fb3e5e8404db43101a2e7a504c`, merge `66161a021a9782f03cbb14fd33a7e4be7ee3db9b`.
Observed PR checks: Wallet 8/8, native PSBT/PayJoin 4/4 (x86 denial-only),
CodeQL languages + aggregate, all 16 applicable checks SUCCESS.
Actual final PR Ubuntu full discovery 1438/1438; native synthetic PSBT 34/34.
Separate post-merge Ubuntu full discovery also observed 1438/1438.

#193 CI: [Wallet](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38367920756),
[native PSBT](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38367920731),
[CodeQL](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38367919130).
Post-merge main: [Wallet](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38368972433),
[CodeQL](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38368971433).

Fresh local Core static corroboration: archive/member hashes exactly match
the pinned authentic v0.1.11 baseline; member is 12,132,344 bytes; readelf still
reports GNU_STACK RWE; no wam.conf member. Temporary data file was mode 0400
and deleted; no Core process or --help executed. Signature was NOT reverified
in this static recheck; prior genuine signed-release evidence is preserved.
Publisher trust/revocation and secure image/loader acceptance remain unqualified.
All genuine Core runtime scenarios are NOT RUN; #9 remains OPEN/BLOCKED.

Security/failure disposition: canonical witness gap reproduced then fixed;
all actual applicable GitHub gates passed before each merge; no unresolved
new test/security failure. Production ownership, real private transport,
trusted UI/key custody and independent anchor remain unqualified as detailed
above. No proof or local-only rollback guarantee, signer/broadcast/mainnet or
CORE-003 integration is introduced.

Stop/reserve decision: four complete units and final synchronization; exact
Work credits are not exposed, so no numeric exhaustion or reset is claimed.
New engineering stopped at this clean boundary to reserve execution capacity
for CI completion, current-main verification and durable handoff. Next internal
tasks are the three executable paths above; external Core/anchor qualifications
require their actual unavailable approved evidence.

### Exact existing open PR / branch snapshot

| PR | Branch | Exact head | Disposition |
| --- | --- | --- | --- |
| #184 | `feat/core-successor-offline-signed-intake` | `ef3402f0ee68bea71b9ce16b5d82b74dba29bc5c` | OPEN; separate review |
| #84 | `security/core-signed-elf-loader-preflight` | `5f75177d470cbc4c5bd623711fce5e528a07cad8` | DRAFT/HOLD |
| #66 | `storage/offline-recovery-disposition-20261011` | `04b00608ec8249db8be12cc8adef7221e4411953` | DRAFT/HOLD |
| #65 | `integration/scanner-window-offline-20261011` | `62353fcb09a7c75e6a2077898fd05135700f7c9f` | DRAFT/HOLD |
| #64 | `integration/scanner-response-shape-offline-20261011` | `dba9466782089673d0936c975f8443905d2fd668` | DRAFT/HOLD |
| #61 | `security/g1-core-preflight-nonauthority-20261011` | `b50b8867c5ef45356d8f8630c57e9c842eaa9382` | DRAFT/HOLD |
| #60 | `app/offline-presentation-lifecycle-20261011` | `df201335fd5fa0504090bf9e4f45526e6111642e` | DRAFT/HOLD |
| #51 | `security/g1-binary-fd-prehash-race-20261011` | `7fafef52450cc0a3ed9ff274d3369c86bf52a116` | DRAFT/HOLD |
| #50 | `security/g1-cookie-after-g1-05-20261011` | `66d3577a40758813bf086ad78f0896abde859d67` | DRAFT/HOLD |
| #34 | `docs/governance-g1-safe-integration-gates` | `4ef0356c91b4940fdb6be0e609cb2e187f822a61` | DRAFT/HOLD |
| #18 | `dependabot/github_actions/actions/setup-python-7` | `e9aa72e250f1b37b110614ba4a79cdf7a6294504` | OPEN; separate review |
| #17 | `dependabot/github_actions/actions/checkout-7` | `a08dfa01be454c0fb6f5cb34565a93b96183aa71` | OPEN; separate review |
| #16 | `research/010-scanner-read-rpc-contract` | `ef3f9a8ed6aeb6bca4053936b963eeb63e4612c5` | DRAFT/HOLD |
| #3 | `feat/003-wsp1-pinned-probe` | `59820c2208a2563b0b968c1e88490ade06ce14e2` | DRAFT/HOLD |

Upstream WSP #3 remains OPEN/DRAFT/HOLD at
`396f444e3a5f1b8f3105144c6fa8dd7e465e7fae`. Frozen branches were not touched.
Existing Dependabot #18 moved from its starting snapshot to the recorded head
by its own update; no main change or dependency approval is inferred.

The existing `docs/2026-10-13-credit-sprint-handoff` branch is an intentional
documentation-only checkpoint artifact. Its final immutable commit is linked
from the #193 final handoff comment. It preserves the earlier sprint document
and genuine static CI artifact alongside this new report and machine-readable
`PRIVACY_INTEGRATION_HANDOFF.json`. Resume engineering from final main above;
the artifact branch carries documentation, not a new code integration.

### Exact engineering file list

- `.github/workflows/psbt-v2-native-readonly.yml`
- `.github/workflows/wsp1-real-scanner-synthetic-regtest.yml`
- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/ARCHITECTURE_V1_PLAN.md`
- `docs/ARCHITECTURE_V1_TRACEABILITY.json`
- `docs/NETWORK_PRIVACY_APPLICATION_POLICY.md`
- `docs/PAYJOIN_CANONICAL_WITNESS_REVIEW.md`
- `docs/PRIVACY_INTEGRATION_2026_10_13.md`
- `docs/ROADMAP.md`
- `docs/SELECTED_HISTORY_LOCAL_EXPORT.md`
- `docs/THREAT_MODEL.md`
- `src/wam_privacy_wallet/application/_payjoin_psbt_worker.py`
- `src/wam_privacy_wallet/application/_psbt_v2_worker.py`
- `src/wam_privacy_wallet/application/network_plan_review.py`
- `src/wam_privacy_wallet/application/payjoin_proposal_review.py`
- `src/wam_privacy_wallet/application/selected_history_export.py`
- `src/wam_privacy_wallet/gui/regtest_window.py`
- `tests/test_architecture_v1_traceability.py`
- `tests/test_ci_contract_gate.py`
- `tests/test_network_plan_review.py`
- `tests/test_payjoin_proposal_review.py`
- `tests/test_regtest_gui.py`
- `tests/test_selected_history_export.py`
- `tools/architecture_v1_gate.py`
- `tools/ci_contract_gate.py`
- `tools/ci_pinned_psbt_v2.py`
- `tools/ci_qualified_scan_session.py`
- `tools/gui_ci_contract_gate.py`

Core main remained `c85259102a366caf62ea82837775f9bd47af1efc` throughout this
privacy sprint. No additional upstream Core change or new signed release was
observed after the earlier Oct13 bounty/treasury documentation update.
Privacy/WSP/security source pins remain unchanged; no upstream edits.

Final post-merge Wallet **8/8 PASS** and CodeQL **3/3 language jobs PASS**,
observed separately from PR CI; all 11 attached final-main checks SUCCESS.
Final verification: `2026-10-13T08:33:56.085Z`.
Exact source, all 29 changed paths, observed check URLs and open PR heads are
also recorded in [the machine-readable handoff](PRIVACY_INTEGRATION_HANDOFF.json).
