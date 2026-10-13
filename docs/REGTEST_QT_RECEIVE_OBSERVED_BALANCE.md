# Qt REGTEST — consented WSP-1 Receive and observed Balance/UTXO

This PR stacks on #182, reusing its actual source-pinned Linux x64
two-node localhost RPC/P2P + WSP Scanner/SQLite private Qt worker.
No mock/synthetic application runtime backend is added. All OS installers
other than Linux retain GUI preview without native scan/receive activation.

- **Receive page**: with explicit local consent, REGTEST mode and a
  source-qualified encrypted scan-only account, the operator can request
  the actual upstream WSP-1 scan-only receive code (account 0). The code
  is validated as a `wamrtsp1` 100–130-character BIP352 review-format
  address, displayed ONLY on the Receive page and cleared on navigation,
  mode change, cancel or window close. It is not a production spend address.
- **Balance / UTXO page**: with separate explicit consent and current
  chain scan, display only the scanner's `unqualified_confirmed_atoms` in
  atomic units, labeled NOT SPENDABLE. It is not a chain-authenticated
  balance, not proof of key custody or valid core binary, and never enables
  transaction/signing/broadcast.
- Every request requires the operator to reenter the two disposable RPC
  passwords and WSP scan-backup passphrase. Qt clears input widgets on
  submission; Python heap/GUI text cannot guarantee secret zeroization.
- Strict receipt rules block unexpected address/amount fields in other
  operations, wrong amounts, forged auth flags, partial scans, two-node
  tip changes, stale Qt revision and result-after-cancel.
- Transactions/Backup/Recovery introduced by #182 remain separate and
  do not leak receive codes or atom balances.

Trusted WAM Core binaries/two-node E2E are NOT qualified (#9/#82/#86/#153).
Trusted anti-rollback (#148/#151) and upstream WSP #3 remain HOLD.
No signer in Qt, no network broadcast, mainnet, user funds or release claim.
CI UI tests patch external I/O only for lifecycle coverage and are NOT
real-node tests; real operational code has no synthetic fallback.
