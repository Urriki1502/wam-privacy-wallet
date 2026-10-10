# Phase 003 — Pinned WSP-1 engine qualification

This phase intentionally **does not** implement receive, scan, signing or
broadcast. It establishes an auditable, fail-closed version/profile boundary
against the real, public `wam-silent-payments` repository.

## Reviewed source pin (not production adoption)

| Field | Exact expectation |
| --- | --- |
| Repository | `https://github.com/Urriki1502/wam-silent-payments` |
| Commit | `ac55f13423620252bdbf848c7e8a280c3b84721e` |
| Python distribution | `wam-silent-payments` |
| Package version | `1.0.0.dev0` |
| Public API | `SilentWallet`, `create_silent_wallet` |
| Protocol | `WSP-1` / API version 1 |
| Engine's own Core baseline | `0.1.11` / `8a3f4fe4f1d804c378f795d4cc281ec5125f75f3` |
| Regtest genesis | `b88f3d262f285e38e184f50bf3eea1c8e615486ae67d3d9eaf0976fbd6d3d30d` |
| Mainnet | Disabled |

The engine's embedded Core baseline may be different from the **current** WAM
Core HEAD. It must be requalified before live integration. WAM mainnet HD
coin type, address HRPs, and mainnet adoption remain maintainer decisions.

## What is checked

- The installed Python distribution reports the expected `direct_url.json`
  with its original Git repository and **exact commit id**, rather than merely
  matching a package version that could be supplied by unrelated code.
- Only after provenance passes is the engine module imported.
- Verify public API, protocol profile, genesis, source Core pin and explicitly
  disabled mainnet setting.
- Negative tests reject source/version/commit tampering, missing provenance,
  profile escalation and changed API.
- Windows, macOS and Ubuntu verify the **actual pinned package**, not a
  hand-written stand-in.

## Scope restrictions

No WAM Node RPC, wallet database, seed/key creation, scanner, signer,
transaction construction, network or GUI integration is performed. The
qualification is a prerequisite for future **regtest-only** adapter work,
not evidence of secure production behavior.

## Local verification

```sh
python -m pip install "git+https://github.com/Urriki1502/wam-silent-payments.git@ac55f13423620252bdbf848c7e8a280c3b84721e"
PYTHONPATH=src python -m unittest discover -s tests -p test_wsp1_contract.py -v
```

PowerShell uses `$env:PYTHONPATH = 'src'` before the second command.

## Before any functional integration

Review the WSP-1 source and license, establish a separate wallet permission
model, implement Windows scanner locking, validate current-Core RPC/genesis
compatibility, and complete regtest-only node tests. No dependency update
may bypass this qualification by selecting an unreviewed commit.

## Two distinct CI guarantees

- `wsp1-qualification-ci.yml` installs the source-pinned WSP engine and
  exercises its provenance, API and denial tests independently.
- `gui-shell-ci.yml` runs **GUI + scaffold only**, so it cannot pass/fail
  for reasons unrelated to its installed dependencies.
- `integration-matrix-ci.yml` installs **both** GUI and the pinned WSP engine
  and runs the **entire** suite on Windows, macOS and Ubuntu. This catches
  cross-module imports and packaging interactions, rather than just isolated
  test success.

All required jobs must pass at the exact commit before merge. A passing
integration test remains a non-production qualification, not a wallet audit.

## Windows x86/x64 lock remediation review status

This experimental pin contains the proposed native Windows scanner-lock fix
from [WSP-1 PR #9](https://github.com/Urriki1502/wam-silent-payments/pull/9).
The original reviewed WSP-1 baseline is unchanged; this commit is on an
unmerged remediation branch pending independent review. Both native Windows
x86/x64 lock regressions and full Windows x64 scanner regression are separate
gates. The Python/Qt GUI is **not yet qualified for native Windows x86**.
This probe remains non-production, and it grants no mainnet permission.
