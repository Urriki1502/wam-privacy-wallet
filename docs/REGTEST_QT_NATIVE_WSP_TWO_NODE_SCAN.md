# Qt REGTEST real two-node WSP scan-only (Linux x64 experimental)

Node Connection adds an explicit Linux x64-only scan button. The operator
supplies **existing** source-qualified pinned WSP-1 checkout, a disposable
0700 scan-only directory with an encrypted account backup, and a scan-only
backup passphrase plus two separate, already-running localhost Core-shaped
RPC/P2P nodes. The same Qt worker lifecycle as the existing node diagnostic
starts an actual `scan_two_existing_regtest_nodes` call. No mock/fake backend
is available in the application. Source qualification, pinned dependencies,
RPC identity snapshots, local P2P peer topology and actual WSP Scanner/SQLite
checks all remain enforced.

Only scalar proof (height, blocks/tx scanned and UNQUALIFIED observed UTXO
count if chain-current) reaches the GUI. The Qt view never handles txids,
addresses, amounts, account secrets, decrypted scan tuple, signing intent,
PSBT, broadcast or production approval.

The scan is bounded to 16 blocks per operation. Cancellation is cooperative
through `QualifiedScanSession.scan(cancelled)`; RPC and upstream SQLite may
have done work BEFORE a cancellation, and SQLite state may persist, but
stale or cancelled results never reach the GUI. The Qt worker owns shutdown.
Passwords are hidden and cleared from Qt widgets after submission, but Python
strings and worker kwargs cannot guarantee zeroization in RAM. No durable
credential vault is claimed.

Windows and macOS keep the scan button disabled: Native pinned retained WSP
custody has not passed there, despite GUI preview build success. Linux needs
real native WSP dependencies installed, no mock backend and an intentionally
prepared ephemeral REGTEST datadir. CI patches the real call only to verify
GUI presentation, cancel, privacy and invalid-scope boundaries. This does NOT
qualify signed WAM Core binaries, isolated processes, genuine two-node E2E,
signer/broadcast, rollback anchors #148/#151, WSP upstream review #3, or
Core #9/#82/#86/#153. No user funds, mainnet or production network.
