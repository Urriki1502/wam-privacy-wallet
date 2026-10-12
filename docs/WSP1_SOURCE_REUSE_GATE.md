# WSP-1 V1 integration — authenticated source inspection, NOT a loaded wallet

**Status: SOURCE REVIEW ONLY; all scanner/signer/money paths BLOCKED.** This adapter reuses **existing work**, not copied code. The upstream source revision is `Urriki1502/wam-silent-payments@ac55f13423620252bdbf848c7e8a280c3b84721e`; its public API, scanner, offline signer and backup Git blobs are verified on a separate read-only CI runner. No upstream Python module is imported, no Core process started, no keys read.

## Live interface mismatch confirmed

`wam_sp.scanner.Scanner` requires `rpc.attest()` and uses `getbestblockhash`, `getblockcount`, `getblockhash`, **`getblock([hash,3])`**, and optionally **`getrawmempool`** and **`getrawtransaction([txid,1/2])`**.

The new application's `LocalReadOnlyRpc` permits only `getblockhash`, `getblockcount`, `getbestblockhash`, `getblockchaininfo`, and `getblockheader`. It does not expose a WSP scanner-compatible `attest` interface. Therefore the actual scanner cannot be injected into the current transport, and the direct upstream WSP RPC class cannot be silently reused because its interface includes an optional `sendrawtransaction` mutation capability.

The read-only verifier **must** continue to output this exact method gap until a reviewed bridge exists. It is a blocker, not a false PASS.

## Exit criteria to integrate (dedicated future PRs)

1. Review pinned WSP-1 API and license provenance and independently verify all source bytes; do not merge the frozen app PR #3 by default.
2. Add a separate **scanner-only** interface with strict bounded `getblock` (verbose 3), `getrawmempool` and `getrawtransaction` response validation, minimal loopback credentials, explicit regtest identity and a resettable `attest` guarantee. Separate scanner from signer with no shared spend secrets.
3. Test malicious/oversize/deeply nested blocks and mempool, RPC response tampering, stale tip/reorg, cookie rotation, crash-resume and true Windows interprocess single-writer lock. No `sendrawtransaction` or wallet RPC method in scanner interface.
4. Independently qualify PSBTv2 signer consent, recipient+fee+input binding, and encrypted backup restore after scan-only gate; never infer sign/send authorization from scan success.
5. Only after DEV-approved genuine WAM Core binary, #36 process binding, #84/#86 ELF policy and #9 isolated two-node E2E may the wallet's live data path be considered for regtest qualification.

## Verification

`python -m unittest tests.test_wsp1_pinned_surface` exercises only synthetic AST/sha fixtures and denial behavior. The [read-only WSP-1 workflow](../.github/workflows/wsp1-pinned-source-readonly.yml) downloads exactly four public source files via HTTPS at the fixed commit, hashes their exact **Git blob bytes** and inspects Python AST without imports. A green read-only report does not attest the binary, local wallet, signer or real funds.
