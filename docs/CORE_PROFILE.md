# Phase 008 — WAM Core regtest profile guard

This project does **not modify WAM Core**. We only use documented RPC
interface details to add defensive validation in WAM Privacy Wallet.

## Sources / assumptions

- Official Core source: https://github.com/wam-coin-official/wam-coin
- Official chain/RPC documentation:
  https://github.com/wam-coin-official/wam-coin/blob/main/docs/LISTING_PACKAGE.md
- The installation configuration records **regtest RPC default 29554**
  (Bitcoin's 18443 is not appropriate for WAM):
  https://github.com/wam-coin-official/wam-coin/blob/main/install.sh
- Standard Bitcoin Core v28.1-compatible read-only RPC: getblockchaininfo.
- Regtest genesis currently comes from our pinned WSP-1/Core profile
  in attestation.py; any binary/profile drift **blocks real-node adoption**.

The local transport still requires an **explicit user-supplied RPC port**.
The official default (29554) is documentation, not a silently assigned port.
Tests using that number do not represent a live WAM node connection.

## New check

`LocalRegtestIdentityGateway.probe_core_profile()` first executes the existing
six-step genesis/height/tip verification, then reads `getblockchaininfo`
through the same loopback-only authenticated transport.

The response must satisfy:
- `chain == "regtest"`, never mainnet/testnet/signet;
- `pruned is False`, explicitly (no unknown or implicit default);
- `blocks` is the same exact integer height previously probed;
- `headers` is a valid integer in range and not less than blocks;
- `bestblockhash` is exactly the previously probed tip.

No token grants scanner access. This is only a per-call identity **snapshot**.
A tip reorg can occur immediately after the last response. An attacker running
an impostor on localhost could forge results. The signed binary, authenticated
local node, process isolation and later scanner gates remain essential.

## CI scope

Nine positive/negative unit tests validate the new profile contract and its
fail-closed RPC behavior; the existing HTTP transport test also asserts that
the new read-only RPC is allowed with **no params**, while transaction/wallet
methods remain denied. GitHub CI tests Python 3.12 on native Windows x86/x64,
macOS and Linux. Existing workflows continue separately.

No actual WAM Core binary is downloaded, executed, altered or committed.
No network RPC to an external/hosted scanner. No mainnet funds.

## Outstanding

- Run Phase 007 harness against an independently signature-verified WAM Core
  executable and compare actual responses.
- Two-node/reorg/recovery evidence remains BLOCKED in issue #9.
- WSP-1 upstream locking code awaits maintainer review.
- Win32 full GUI/cryptography packaging remains unqualified.
