# Phase 009 — WAM Core source compatibility pin (read only)

**WAM Core is never edited or built by this project.**

## Source reviewed and frozen by file content

Official upstream (read-only): https://github.com/wamcoin-core-dev/wam-coin

Reviewed Core main SHA: `260bc468e5adffea7ce68d8f97fac3e27e4c50b2`.

Existing WSP-1 v0.1.11 Core baseline: `8a3f4fe4f1d804c378f795d4cc281ec5125f75f3`.

Comparison found the current Core main 41 commits ahead, but the precise Git blob
hashes for these three compatibility-critical files are unchanged between the
two commits:

- `src/wam/wam-params.h`
- `src/wam/chainparams.cpp`
- `scripts/patch_upstream.py`

The complete inspected blob hashes and network values live in
`compat/wam_core_source_pin.json`. This pinned source contract checks:

- RPC ports: mainnet 9554, testnet 19554, regtest **29554**.
- P2P ports: mainnet 9555, testnet 19555, regtest **29555**.
- `RPC = P2P - 1` on all networks (never Bitcoin regtest 18443).
- Regtest genesis: `b88f3d262f285e38e184f50bf3eea1c8e615486ae67d3d9eaf0976fbd6d3d30d`.
- The chainparams assert and patched upstream regtest RPC mapping agree.
- Checked-in wallet genesis remains identical to the Core source profile.

## CI and drift detection

Native Python 3.12 Windows x86 and x64, macOS and Linux unit tests check
positive and negative contract semantics offline with *synthetic source*.

A separate read-only CI job downloads only the three source files over HTTPS
from the exact pinned commit **and current upstream main**, then independently
verifies each Git blob SHA1 and parses its network constants. It performs GET
requests only. It never clones, modifies, builds or executes WAM Core.

If a compatibility-critical upstream file moves, the source check **fails
closed**, requiring review and explicit re-pinning. Changes in other Core
files do not automatically prove compatibility or incompatibility.

## Qualification boundary

The source check is not a real binary or node run, a signed-release check,
a wallet-privacy audit, or consensus validation. Core's v0.1.11 signed
release executable and actual two-node WSP-1 regtest remain unverified.
A source pin alone does **not** permit the scanner, signer, wallet keys or
real funds. Tracking: wallet issue #9; Win32 full packaging: #5.

The source repository is **never modified** by this feature. If upstream
changes, only the wallet's local manifest or adapters may be updated after
external review.
