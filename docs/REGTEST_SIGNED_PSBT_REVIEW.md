# Review file returned by independent WSP offline signer (REGTEST ONLY)

`tools.review_regtest_signed_psbt` is the receiving half of the current
manual `tools.prepare_regtest_offline_intent` workflow. It does not execute
a signer, own spend secrets, use RPC, construct a payment, launch WAM Core,
authorize broadcast, or switch to mainnet.

The operator first runs existing source-pinned wallet coordinator to create
the **encrypted WSP request** on a separate private transfer medium; a
different physically or logically isolated machine/process runs the **actual
upstream WSP-1 `wam_sp.offline_signer` CLI** after on-screen recipient/fee
review. The resulting `signed-psbt.b64` file is transferred back.

```sh
PYTHONPATH=src python -m tools.review_regtest_signed_psbt \
  --wsp-source-root /absolute/exact-pinned/wsp-source \
  --encrypted-request /absolute/private/transfer/wsp-intent-v1.enc \
  --signed-psbt /absolute/private/transfer/signed-psbt.b64 \
  --request-sha256 <HASH_FROM_MANUAL_INTENT_RECEIPT> \
  --explicit-review
```

Passphrase is read from interactive TTY only, never argv or environment.
Both files must be private 0600 regular single-linked files inside a
private 0700 directory on Linux. Source checkout must verify original
WSP Git source closure, runtime dependency versions and package origin.

The review calls **real pinned WSP-1 `PSBT.from_base64` and
`PSBT.finalize()`** to validate every P2TR Schnorr signature and WSP sender
proof, and decrypts the original request with upstream `decode_request`.
It compares exact coin outpoints, witness UTXO amount/scripts, requested
recipient metadata/amounts, and fee, allowing at most one explicit
`change_output_present_unqualified`. Independent change ownership remains
UNVERIFIED and must be reviewed by an operator separately. The returned
receipt contains no recipient address, raw PSBT, spend secret or credential.

**Important:** This is NOT a completed signer workflow E2E. CI tests only
negative file/scope contracts; no signed regtest PSBT produced by an approved
isolated signer has yet been verified. WAM Core executable/process identity
#82/#86/#153, two-node E2E #9, recovery anchor #148/#151, upstream WSP
approval PR #3 remain HOLD. No broadcast, signing from app, real funds,
production release, mainnet or wallet authority.
