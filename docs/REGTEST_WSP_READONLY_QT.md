# REGTEST workspace: source-pinned WSP scan evidence to Qt (read-only)

The nine-view REGTEST workspace receives an immutable scalar `ScanSnapshot`
from the already source-qualified WSP application session. It never imports or
executes WAM Core, a signer, a wallet Keyring, or a transaction broadcaster.
No operator scan button is enabled. External operational Core/WSP gates remain
blocked even when native tests pass.

The new `RegtestWindow.present_untrusted_scan_receipt` requires explicit
consent and REGTEST selection plus the exact current GUI lifecycle revision.
Cancelled, failed, closed and stale-revision sessions cannot publish receipts.
It accepts only the exact immutable DTO type,
reconstructs the DTO to detect post-construction corruption, rejects any
authority claim, and clears earlier evidence before invalid input. A lifecycle
revision or cancellation removes the displayed evidence. Only untrusted
scalar counts and scanner tip are displayed; no amounts, receive address,
transaction IDs, account identifiers, scan keys, file paths, or passwords.

The GUI always labels the receipt `REVIEW_ONLY_UNTRUSTED`, shows
`NO VERIFIED CORE` and `NO WALLET BALANCE`, and retains the existing
`NO WALLET LOADED` authority boundary. Partial scanning displays
`UNAVAILABLE (INCOMPLETE SCAN)` instead of zero or cached balances.
The source SHA in a DTO is not standalone attestation of its origin.

Cross-platform Qt regression coverage adds five negative/positive identities;
full discovery floor increases 1314→1319 without removing earlier tests.
The Linux native retained scanner runner adds a fifteenth positive proof:
actual pinned WSP Scanner/SQLite output from the synthetic loopback peer is
presented through the real REGTEST Qt window and cleared by cancellation.
All native source pins, independent tests, and prior platform denials remain.

This is a step toward functional application integration, NOT live Core E2E,
not qualified wallet balances, not a wallet release, and not signing/broadcast.
WAM Core #9/#82/#86/#153, WSP #3, and checkpoint #148/#151 remain HOLD.
