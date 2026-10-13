# REGTEST application lifecycle (gate-held)

The desktop entry point now opens an application workspace with nine V1 views.
The user explicitly selects REGTEST, separately consents to local gate
inspection, and can cancel or close while inspection runs on an owned Qt
worker. The former offline receipt viewer remains available with
`wam-privacy-wallet --offline-review`.

`wam-privacy-wallet --mode regtest` selects REGTEST without consenting to any
operation. The command line does not accept node credentials, wallet paths,
keys, mainnet, or an override switch. Install the optional GUI dependency before
using this entry point.

## Implemented application behavior

- `RegtestLifecycle` owns mode, revisions and work-ticket identity. A matching
  forged ticket, cancelled ticket or closed-session completion cannot publish
  state. Results cannot promote readiness into wallet/spend/network authority.
- `RegtestWorkerController` runs the existing `TwoNodeReadiness` local policy
  on a `QThread`; scalar results reach the GUI thread by queued signals.
  Completion and error paths always request worker/thread cleanup. Errors are
  fixed codes; no backend exception, credential or path is rendered.
- Cancellation invalidates the ticket immediately, signals an `Event`, and
  keeps the controller busy until the owned thread finishes. No second job
  can share the session. Shutdown never terminates a worker or destroys a
  running `QThread`; the window defers destruction while cleanup is pending.
- Dashboard, Node Connection, Receive, Transactions, Balance / UTXO,
  Send / Transaction Preparation, Backup / Recovery, Privacy, and
  Security / Diagnostics show explicit BLOCKED or REVIEW_ONLY states.
  Missing balances/history are not represented as zero or synthetic records.

## Evidence and limitations

The actual positive operation is **local policy inspection**, not network or
artifact authentication. There is no operational synthetic backend or hidden
mock fallback. No WSP module, retained account, credential, Core process or
signer is imported/created by this workspace. Existing receipt display tests
remain in the separate preview; none count as a connected wallet.

Twenty dependency-free lifecycle tests and ten Qt tests exercise consent,
real worker/GUI thread separation, responsive navigation, cancellation,
stale completion, redacted errors, retry, and cooperative shutdown. Slow/error
callbacks are explicitly lifecycle adversarial fixtures; they are not evidence
of a real scanner or Core connection. Existing native WSP/PSBT/HPKE evidence
remains separate and unchanged.

The workspace deliberately cannot activate a node/account backend before
Core issues #9/#82/#86/#153, WSP review and runtime identity approval. Trusted
recovery holds #148/#151 remain. Selecting a mode or merging this PR is not
approval of those dependencies, signing, broadcast or production release.

Next integration seam: source-qualified scanner sessions can execute through
an independently tested disposable REGTEST adapter; their actual SQLite and
scan receipts must remain unqualified until genuine Core acceptance passes.
