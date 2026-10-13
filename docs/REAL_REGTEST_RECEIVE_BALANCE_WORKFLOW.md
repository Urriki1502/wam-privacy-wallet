# Real-only REGTEST receive / observed balance / history / recovery operator

After PRs #170–#175, the existing actual pinned WSP Scanner/SQLite runtime
already implements `receive_code`, `snapshot`, `history` and authenticated
AES-GCM checkpoints. This change makes these existing operations available in
**the SAME real localhost-regtest scan session**; no synthetic peer, canned
transaction or mock state can be selected at runtime.

Existing TTY commands:
- `python -m tools.run_live_wsp_regtest ...` (one existing regtest node)
- `python -m tools.run_two_node_wsp_regtest ...` (two existing regtest nodes,
  with before/after P2P topology and chain agreement gate)

Explicit optional flags:
- `--receive-account-index 0`: only after a complete scan, output the
  **local/private, unqualified** upstream WSP receive code.
- `--show-observed-balance`: only after complete scan, output the scanner's
  exact `unqualified_confirmed_atoms`; **NOT an authenticated, spendable
  balance**, even if two local RPC sockets report agreement.
- `--history-limit 20`: previously available private source-pinned SQLite
  history with txids, confirmation count and credits/debits.
- `--save-checkpoint`: existing encrypted upstream WSP AES-GCM checkpoint;
  create-once, non-rotating.
- `--restore-checkpoint`: restore ciphertext into a fresh scan-only Store,
  then reattest against the actual RPC chain before displaying any history,
  receive code or observed balance.

The operator must consent, acknowledge unverified Core binary, and enter
disposable credentials/passphrase through an interactive terminal (not argv).
Private output is emitted only after successful close and after two-node
postscan audit if requested. Any incomplete scan denies explicitly requested
receive/balance/history/checkpoint. Scanner state, address, txid and atoms
never enter public GUI review receipts or CI logs.

**Security limits (unchanged):** Real socket != authenticated Core executable.
WAM Core release/process and two-node E2E gates #9/#82/#86/#153,
anti-rollback #148/#151 and upstream WSP review #3 are still HOLD. This
change does not grant wallet operational status, verified balance, a
separate signer process, broadcast, mainnet or production authority.
Cross-platform native retained scanner custody remains unqualified;
this command is Linux x64 only. CI tests validate negative-scope
and source review paths, not genuine WAM Core execution.

The next acceptance milestone is a DEV-qualified signed WAM Core binary
running isolated two-node REGTEST plus real payment/reorg evidence,
followed by isolated offline-signing and scoped broadcast validation.
