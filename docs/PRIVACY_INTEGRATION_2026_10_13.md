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
