# Phase 010 — Offline WSP-1 scanner RPC shape contract (research draft)

**No real node, no scanner, no private keys, no wallet DB and no transaction signing or broadcast.** This phase introduces only an inert, inspectable parser for method/parameter shapes used by WSP-1 scanner phases. A validated shape is **NOT** authority to access an RPC transport, authenticate a node, or process a block.

Tracked under [WSP1-SCAN-BRIDGE-001 #15](https://github.com/Urriki1502/wam-privacy-wallet/issues/15).

## Why a separate contract?

- The current wallet `node.LocalReadOnlyRpc` intentionally accepts only identity/profile methods (`getblockchaininfo`, `getblockhash`, `getblockcount`, `getbestblockhash`) using **explicit in-memory auth** and a bounded JSON-RPC 1.0 envelope. It does not provide a block or mempool scanner transport.
- Pinned `wam_sp.scanner.Scanner` requires `rpc.attest()`, plus `getblock(hash,3)` for confirmed scanning; mempool paths use `getrawmempool` and `getrawtransaction(txid,1/2)`.
- Pinned `wam_sp.rpc.RPC` is separately cookie-authenticated, bounded, uses JSON-RPC 2.0, and has its own read/mutate policy. **Do not** silently widen the wallet diagnostic transport's allowlist or bypass attestation by connecting it to a scanner.
- Source: [WSP PR #9](https://github.com/Urriki1502/wam-silent-payments/pull/9) head `ac55f13423620252bdbf848c7e8a280c3b84721e`; scanner locking and API review still pending.

## Present scope

`validate_scanner_read_shape(method, params, scope=...)` is *pure validation*:

| Scope | Allowed method shape |
| --- | --- |
| `confirmed` | `getblockchaininfo()`, `getblockcount()`, `getbestblockhash()`, `getblockhash(height:int)`, `getblock(lowercase_hex_64, 3)` |
| `mempool` (must be explicitly selected) | the same identity methods; `getrawmempool()`, `getrawtransaction(lowercase_hex_64, 1 or 2)` |

All other methods are rejected (including `sendrawtransaction`, signing, wallet RPC, `gettxout` and `testmempoolaccept`). No automatic scope upgrade; strict builtin argument types; bounded block height; no sensitive inputs in exception messages. The frozen result structure is only a **shape**, not a transport credential or security capability.

## Test evidence and nonclaims

Run against Python 3.12 from repo root:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p test_scanner_read_contract.py -v
PYTHONPATH=src python -m unittest discover -s tests -v
```

For PowerShell set `$env:PYTHONPATH = 'src'` first and run the same `python -m unittest` commands.

This document and its tests cover *only* offline synthetic method validation. They do **not** import the WSP engine, exercise a network connection, validate Core identity, parse actual block/RPC responses, persist wallet state, approve keys, or prove confidentiality. Passing Linux/Windows/macOS unit CI is not evidence of live wallet or WSP end-to-end integration.

## Mandatory future integration gates

1. Independent review of the WSP-1 upstream Windows locking [PR #9](https://github.com/Urriki1502/wam-silent-payments/pull/9); do not assume native Win32 Qt/crypto support.
2. Exact SHA-pinned library provenance and Core network profile; **wallet PR #3 is still DRAFT** and must not be merged solely due to CI results.
3. Implement a separate scanner read transport that performs fresh `attest()` checks, cookie/auth handling, response/size/timeout bounds, remote/DNS exclusion, fail-closed reorg/race/invalid chain handling and logger redaction.
4. Demonstrate locked, isolated user-owned two-node Core regtest with externally verified WAM binary SHA-256 and provenance ([REGTEST-E2E #9](https://github.com/Urriki1502/wam-privacy-wallet/issues/9)); no arbitrary downloads or personal wallet files.
5. Review metadata exposure to WAM-operated bootstrap nodes; no hosted scanner fallback.
6. Preserve signer independence and enforce production blocking until independent audit, native platform integration, release review and explicit maintainer signoff.

No WAM Core, WSP frozen branch, `main` or upstream consensus changes are part of this work.
