# Phase 003 — Pinned WSP-1 engine qualification

This phase intentionally **does not** implement receive, scan, signing or
broadcast. It establishes an auditable, fail-closed version/profile boundary
against the real, public `wam-silent-payments` repository.

## Reviewed source pin (not production adoption)

| Field | Exact expectation |
| --- | --- |
| Repository | `https://github.com/Urriki1502/wam-silent-payments` |
| Commit | `dcf1aecc00a64bfad3151fa202c3e07d47d83e69` |
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
python -m pip install "git+https://github.com/Urriki1502/wam-silent-payments.git@dcf1aecc00a64bfad3151fa202c3e07d47d83e69"
PYTHONPATH=src python -m unittest discover -s tests -p test_wsp1_contract.py -v
```

PowerShell uses `$env:PYTHONPATH = 'src'` before the second command.

## Before any functional integration

Review the WSP-1 source and license, establish a separate wallet permission
model, implement Windows scanner locking, validate current-Core RPC/genesis
compatibility, and complete regtest-only node tests. No dependency update
may bypass this qualification by selecting an unreviewed commit.
