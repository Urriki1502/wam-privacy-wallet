# Qt REGTEST — private WSP-1 transaction history and AES-GCM recovery

After #181, this workflow uses the SAME real two-node localhost RPC/P2P
and source-pinned WSP-1 Scanner/SQLite runtime. No synthetic peer is selected
at runtime; GUI/contract CI still uses independent test doubles and therefore
is NOT proof of genuine WAM Core two-node E2E.

On **Linux x64 only** the operator must first select REGTEST, consent,
acknowledge unverified binaries, provide both distinct preexisting localhost
node RPC credentials and a pinned WSP source checkout plus disposable
scan-only directory and encrypted scan-backup passphrase.

- **Transactions page:** an additional checkbox explicitly authorizes
  local presentation of up to 20 real SQLite confirmed history records.
  IDs, heights, credits/debits in atomic units are PRIVATE/UNQUALIFIED.
  The private Qt history view clears on navigation, mode change, cancel,
  error or close; it never appears in general scanner evidence, normal Qt
  diagnostic receipts, CI logs or telemetry. The operator must reenter the
  password for each new request; no auto refresh or stale-cache display.
- **Backup / Recovery page:** an additional explicit acknowledgment allows
  a create-ONCE WSP Store AES-GCM checkpoint or restoration from an existing
  checkpoint in a **fresh empty** scan-only Store. Restore must pass another
  real RPC sync and chain-current check before a success status is shown.
  The UI never exposes ciphertext, plaintext scan-account secret, txids,
  passphrases, spending keys or account balances on this page.
- The Qt worker owns each blocking operation and cooperatively cancels
  upstream scanning; results delivered after cancel or leaving the target
  page are rejected. This is not rollback of an already written archive or
  SQLite changes that occurred before cancellation.

The existing WSP cryptography and source verification are REUSED; no
hand-rolled encryption and no in-process signer. No private account or Core
node is created by Qt, and no sender/sign/broadcast/mainnet capability is
granted. Qt/Python text/byte objects cannot guarantee RAM zeroization and
local displayed txids can be observed by a person with screen access; this
is NOT secure secret custody.

IMPORTANT: a valid encrypted checkpoint can be stale: trusted rollback
anchors #148/#151 remain HOLD. Genuine Core binary/executable and two-node
acceptance #9/#82/#86/#153 and upstream WSP PR #3 are still HOLD. Windows
and macOS Qt native scanner/storage are not yet qualified, even though GUI
preview installers build. User production funds are prohibited.
