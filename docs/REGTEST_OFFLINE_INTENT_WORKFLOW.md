# Manual REGTEST encrypted WSP-1 payment intent — separate signer boundary

The scanner-only runtime is already real WSP/SQLite. This new **opt-in
developer coordinator** expands it to the genuine source-pinned
`wam_sp.wallet.Wallet.propose` (UTXO selection/reservation) and
`wam_sp.wallet.encode_request` (encrypted signing intent sidecar).
It never creates Keyring, invokes Signer, signs, launches Core or
broadcasts a transaction. It cannot operate mainnet.

The source-verified WSP code encrypts the actual proposal with its own
AES-GCM + scrypt `intent` purpose. Only after a new full scan and fresh
local WAM REGTEST RPC profile does the coordinator create the encrypted
`wsp-intent-v1.enc` in a preexisting PRIVATE 0700 output folder. Staging
file fsync → atomic hardlink publication → unlink → directory fsync must
all succeed. Existing intent ciphertext is never overwritten. The upstream
Wallet records UTXO reservations and marks them `signed` after successful
sidecar publication **as a reservation state, not proof a signature exists**.
An ambiguous failure may leave UTXOs locked and/or a ciphertext file; do not
retry automatically or unlock signed/uncertain reservations.

## Operator use: disposable funded REGTEST only

```sh
PYTHONPATH=src python -m tools.prepare_regtest_offline_intent \
  --wsp-source-root /absolute/exact-pinned-wsp-source \
  --private-dir /absolute/private/disposable-scanner \
  --output-dir /absolute/private/empty-signer-transfer \
  --rpc-port 29554 --rpc-user disposable_regtest \
  --acknowledge-unverified-binary
```

Three passphrases/credentials, the public WSP destination and atomic amounts
are prompted on an interactive terminal; no credential or recipient/amount
needs to be passed in argv or environment. The output must be transferred to
a **physically or logically isolated offline signer** holding only the
disposable matching encrypted keyring.

The separate source-pinned WSP-1 upstream offline signer is already available:

```sh
python -m wam_sp.offline_signer \
  --keys /private/disposable-keys.enc \
  --request /private/wsp-intent-v1.enc \
  --output /private/signed-psbt.b64
```

This second command must run independently after operator review of recipients
and fee. It does NOT run from the application or in CI. No signed PSBT import,
broadcast or live transactions are enabled by this PR.

**IMPORTANT acceptance limit:** Correct source pin and real network socket
do not authenticate the executing WAM Core binary. The source-pin
requirement, anti-rollback #148/#151, Core #9/#82/#86/#153 and WSP upstream
review #3 remain held. Unit tests use inert ciphertext to validate file
publication only; they do NOT attest real WSP signing, encryption or real Core.
This PR is a reviewable step toward Functional Wallet V1, not acceptance.
