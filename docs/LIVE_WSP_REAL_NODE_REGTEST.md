# Real localhost WAM Core REGTEST → WSP-1 Scanner (developer integration)

The existing wallet source-pin checker validates WAM's public upstream
`wamcoin-core-dev/wam-coin` network profile. The dedicated
`scan_existing_regtest()` function now consumes a real, already-running
loopback WAM Core-shaped node through the existing genuine
`LocalRegtestIdentityGateway` and `Wsp1ScannerOnlyRpc`. It invokes the
actual pinned `wam_sp.scanner.Scanner.sync` and native SQLite under a strict
source-qualified Linux x64 scan-only runtime; NO synthetic peer is instantiated
or selected by this entrypoint.

## Example (developer-owned disposable isolated REGTEST only)

From an **interactive terminal** with a separately launched and reviewed
regtest full node and a preexisting encrypted scan-only backup:

```sh
PYTHONPATH=src python -m tools.run_live_wsp_regtest \
  --wsp-source-root /absolute/path/to/exact-pinned-wsp-source \
  --private-dir /absolute/private/disposable-scan-directory \
  --host 127.0.0.1 --rpc-port 29554 --rpc-user disposable_rpc_user \
  --max-blocks 16 --acknowledge-unverified-binary
```

The script asks for the disposable RPC password and scan-only account
passphrase interactively; neither is accepted via flags or environment.
Neither this command nor any GUI launches WAM Core. A local node must be
operated and qualified separately. Use no existing production datadir,
saved keys, real funds, mainnet, testnet or public RPC hosts.

This is a **REAL SOCKET** integration, not synthetic RPC. CI only checks
negative-path contracts and cannot qualify live WAM Core without a real,
approved binary. A local peer may impersonate Core and the source currently
is NOT bound to a signed executable process: all amounts and receipts remain
unqualified; wallet_operational/signing/broadcast/mainnet flags are false.
The caller must not interpret real socket connectivity as binary provenance.
Core #9/#82/#86/#153, WSP PR #3 and anti-rollback #148/#151 remain pending.

Core RPC port 29554 and regtest genesis
`b88f3d262f285e38e184f50bf3eea1c8e615486ae67d3d9eaf0976fbd6d3d30d`
are from official WAM source, with exact source and port drift already checked
by `compat/wam_core_source_pin.json`. Production wallet operation requires
genuine two-node Core acceptance and an approved isolated signer.

## Operator workflow (actual RPC and upstream SQLite, no synthetic fallback)

The same command provides a strictly local, opt-in private transaction
history. Add `--history-limit 20` to return up to twenty upstream SQLite
rows (txid, confirmed block, confirmations, credit/debit atoms). **This data
is PRIVATE** and is emitted only to the interactive operator console; it is
never exported to GUI public receipts or application diagnostics. If the
block scan is incomplete, history refuses rather than display stale rows.

On a current chain, add `--save-checkpoint` to export a single WSP upstream
AES-GCM checkpoint into the private directory through the existing
create-once Linux archive. It cannot replace, rotate or renew an existing
archive and it does not qualify external anti-rollback. To recover, provision
a fresh empty private scan-only directory with the encrypted scan-account
backup **and the archived encrypted checkpoint**, then use
`--restore-checkpoint`. WSP authenticates and restores the checkpoint,
then mandates a new actual RPC scan/revalidation before it returns any
private history.

`--save-checkpoint` and `--restore-checkpoint` together are rejected.
No CLI operation signs, broadcasts, creates Core processes or enables
mainnet. These features require genuine operator-host Core execution
evidence and are NOT validated by synthetic-only GitHub Actions.
