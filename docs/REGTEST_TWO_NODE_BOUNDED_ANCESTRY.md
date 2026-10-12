# REGTEST-2NODE-ANCESTRY — bounded cross-node historical consistency

## Purpose
The merged live two-node transition observer (#89) already samples tip and immediate parent over real, explicitly authenticated localhost JSON-RPC. This additional module validates **up to 16 contiguous historical block heights**, from two independent, already-running numeric-loopback RPC endpoints. It is useful for detecting ordinary interior history divergence and silent changes that a matching tip/height alone may not reveal.

`TwoNodeBoundedAncestry(node_a, auth_a, node_b, auth_b).audit(window_size=8)` constructs all RPC transports internally from `LocalRegtestIdentityGateway` and `LocalReadOnlyRpc`. It does not accept a mock callback, RPC URL, default endpoint, Core path, wallet, process, key or external network. Only the previously pinned read-only methods `getblockhash`, `getblockcount`, `getbestblockhash`, `getblockchaininfo` are used.

## Exact fail-closed procedure

1. Probe each node's genuine *reported* regtest genesis, tip, height, and unpruned chain profile. Deny any cross-node disagreement.
2. Bound `window_size` to a strict **integer 1–16**, clamp the start to genesis, and read each height independently from **both** local HTTP endpoints.
3. Reject cross-node hash disagreement, malformed/lowercase hash violations or a tip/genesis hash inconsistent with the initial identity probes.
4. Repeat **the entire height window a second time** and compare all positions. After each pass, re-probe both full chain profiles; deny any visible chain drift or interior change. All failures return fixed redacted codes; no hashes, peer details or secrets appear in returned JSON.

These reads are **not an atomic ledger snapshot**. They reduce (but cannot eliminate) read-window inconsistency and cannot rule out malicious/racing RPC servers, ABA mutations between reads, hidden network sockets, untrusted process images or forged WAM Core responses. Values returned by `getblockhash(height)` alone do **not** cryptographically prove that blocks link as parent/child. The output explicitly sets `block_parent_links_verified=false`, `genuine_core_processes_verified=false`, `real_two_node_regtest_qualified=false`, and disables scanner/wallet/signing/broadcast/mainnet authority.

## TTY-only operator CLI (stacked PR #93)

After two genuine, independently approved regtest RPC endpoints **already exist**, the operator can initiate a one-shot ancestry audit:

```sh
PYTHONPATH=src python -m tools.audit_two_node_ancestry \
  --node-a-host 127.0.0.1 --node-a-port <A_RPC_PORT> --node-a-rpc-user <A_USER> \
  --node-b-host 127.0.0.1 --node-b-port <B_RPC_PORT> --node-b-rpc-user <B_USER> \
  --window-size 8
```

All ports are explicitly provided and numeric loopback only; no public address, DNS, cookie autodiscovery, Core subprocess or default port. Distinct disposable credentials are prompted through an interactive terminal; no passwords in argv or env, and non-TTY invocations **fail closed**. The output remains scalar non-authorizing JSON, with no secrets, block hashes or process-identity claims. The CLI adds 10 input/redaction/no-launch regressions on top of 15 actual TCP fixture tests from the core module. These CLI tests verify boundaries, **not** a genuine WAM Core process.

## Native real-transport regressions
15 additive tests exercise **two actual independent TCP/HTTP servers** used solely as adversarial protocol fixtures: consistent history, height-zero genesis, bounded windows, same-tip/different-interior fork, silent inner-window rewrite, chain-height/genesis/chain/pruned mismatch, malformed hashes and authentication, redacted output and no subprocess invocation.

The operational module never accepts test-server callbacks. A fixture-based CI pass is **not** genuine WAM Core two-node qualification. Actual WAM Core process launch remains blocked by #36 and #86 (the signed v0.1.11 `GNU_STACK RWE` upstream finding). PR #84 stays HOLD; separate read-only P2P topology PR #90 is governed by existing branch protection. We do not modify upstream WAM Core, install a Core executor, enable wallets or touch real funds.
