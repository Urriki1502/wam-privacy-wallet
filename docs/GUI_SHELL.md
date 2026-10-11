# Phase 001 — Desktop GUI shell (experimental)

## Scope

A single PySide6 / Qt desktop shell supports Windows and macOS. The pages are
Overview, Receive, Send, Privacy, Node and Recovery. Receive, Send and
Recovery remain disabled placeholders. Node and Privacy support explicit,
non-authorizing in-memory research diagnostic views.

## Incremental offline application integration

The Node page can now accept an exact immutable `application.node_status.NodeOverview`
via `MainWindow.present_offline_node_snapshot(snapshot)`. It renders the
validated regtest height only as an **UNVERIFIED READ-ONLY PROJECTION**, with
an explicit reset method. On startup there is no diagnostic snapshot and
Overview remains `DISCONNECTED · NO RPC` even after a snapshot is presented.

This is a one-way in-memory display seam for synthetic/contract tests:
the UI neither constructs a WAM Core profile nor connects to a node. It does
not retain the profile or snapshot and cannot grant scanner/signer authority.
Callers are **not** authenticated, so the UI cannot attest freshness, origin,
or correctness of a presented value. The existing frozen WSP-1 adapter remains
unmerged and untouched.

The Privacy page can also accept a strict immutable research-only snapshot from
`application.privacy_readiness.research_readiness(manifest, ledger)`, composed
from **injected** WSP source-pin inventory plus blocked security gate records.
It labels the pin UNATTESTED, the privacy/PayJoin/network modules MODEL_ONLY,
and scan/sign/send BLOCKED; reset clears the view. The GUI never reads source
files or imports the upstream implementations itself. See
[Application research readiness](APP_PRIVACY_RESEARCH_READINESS.md).

## Synthetic privacy policy evidence (research-only)

The Privacy page has a **separate, non-authorizing policy evidence panel**.
`MainWindow.present_offline_policy_report(report)` accepts only an exact,
immutable `SyntheticPolicyReport` validated by a strict mock-schema adapter.
It displays **SIMULATED / UNTRUSTED / NOT AUTHORIZED** and never retains
the report or enables a wallet action. Clear with
`clear_offline_policy_report()`. No SDK, WSP scanner, signer, transaction,
RPC, transport or external `wam-privacy` implementation is imported.

See [Application Policy Evidence](APP_POLICY_EVIDENCE_OFFLINE.md) for exact
upstream source pins, trust limitations and negative tests.

## Explicit fixed offline model demonstration

`MainWindow.run_fixed_offline_policy_demo()` is a deliberate, zero-argument
test/demo-only action. It first verifies byte-identical copies of the pinned
MIT-licensed pure Python `wam-privacy` Network Privacy and PayJoin model
sources, then exercises them with **fixed fake endpoint and transaction values**
inside the Application. The display still says `SIMULATED / UNTRUSTED /
NOT AUTHORIZED`; scan, signer, wallet creation and broadcast stay disabled.
The demo is never invoked automatically on GUI startup. A failure clears the
previous display and yields a fixed redacted error.

See [Pinned Privacy Research Models](PINNED_PRIVACY_RESEARCH_MODELS.md) for
commit SHA, four exact Git blob hashes and original MIT attribution.

## Receive — public WSP-1 synthetic vector only

The Receive page can explicitly show a **redacted fingerprint** of a single
prepublished public WSP-1 regtest test vector through
`MainWindow.run_fixed_public_receive_demo()` or
`present_public_receive_vector()`. This validates only the pinned MIT pure
Bech32m codec and public example format. No seed, private key, scanner, wallet
address derivation, live Core connection, QR code, clipboard/copy action or
receive capability is present. It never displays a full address. The page
warns **NOT A RECEIVING ADDRESS**, and `clear_public_receive_vector()` resets it.

See [Public WSP Receive Vector](APP_WSP_PUBLIC_RECEIVE_VECTOR.md) for upstream
commit/blob SHA evidence, MIT notice, checkout LF pins, negative tests and
non-production limitations.

## Explicit non-features

- No WAM SDK, WAM Core RPC, scanner, transaction builder or network requests.
- No wallet state, key generation, storage, passphrase handling, signing, or broadcasting.
- No actual receiving address, balances, coin history, privacy guarantee, or recovery feature.
- No imports from `wam-silent-wallet`, `wam-silent-payments`, `wam-privacy` or `wam-security`.
- No Shielded/Halo2 functionality or consensus modification.

Overview status remains a **fixed DISCONNECTED placeholder**. An explicitly
injected Node-page snapshot is labeled UNVERIFIED and NEVER updates that
status. Neither value is a measurement of the user's actual WAM node.

## Verification contract

- `test_scaffold.py` remains dependency-free, so foundation CI works independently.
- `test_gui_shell.py` constructs Qt's real widgets headlessly and verifies navigation,
  nonproduction wording, offline placeholders, and absence of transaction buttons.
- `wallet-ci.yml` installs the optional GUI extra, enforces the fail-closed
  discovery floor, and runs offline smoke suites on Windows/macOS/Ubuntu.
- A green GUI CI is a cross-platform smoke test, not evidence of wallet correctness,
  secure key management, release installation, or end-to-end mainnet support.

## Manual GUI preview

```sh
python -m pip install -e ".[gui]"
python -m wam_privacy_wallet
```

Never load real wallet material into this prototype. User interface design,
accessibility, platform packaging and integration with the protocol engine remain
future review gates.
