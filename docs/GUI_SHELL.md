# Phase 001 — Desktop GUI shell (experimental)

## Scope

A single PySide6 / Qt desktop shell supports Windows and macOS. The pages are
Overview, Receive, Send, Privacy, Node and Recovery. Navigation changes only
which static explanation is displayed.

## Explicit non-features

- No WAM SDK, WAM Core RPC, scanner, transaction builder or network requests.
- No wallet state, key generation, storage, passphrase handling, signing, or broadcasting.
- No actual receiving address, balances, coin history, privacy guarantee, or recovery feature.
- No imports from `wam-silent-wallet`, `wam-silent-payments`, `wam-privacy` or `wam-security`.
- No Shielded/Halo2 functionality or consensus modification.

The status labels are **fixed placeholders**. A displayed `DISCONNECTED` value is
not a measurement of the machine's WAM node or its real network state.

## Verification contract

- `test_scaffold.py` remains dependency-free, so foundation CI works independently.
- `test_gui_shell.py` constructs Qt's real widgets headlessly and verifies navigation,
  nonproduction wording, offline placeholders, and absence of transaction buttons.
- `gui-shell-ci.yml` installs the optional GUI extra and runs both suites on
  GitHub-hosted Windows, macOS, and Ubuntu runners.
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
