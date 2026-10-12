# REGTEST-2NODE-HEADER-001 — independent localhost header-parent consistency

This increment complements merged #92's bounded `getblockhash(height)` double-pass ancestry checks. It adds the **explicit read-only Bitcoin-compatible WAM Core `getblockheader(hash, true)` JSON-RPC method** to the existing `LocalReadOnlyRpc` allowlist, restricted to exactly one 64-character lowercase hexadecimal hash and the literal `true` verbosity flag. Any extra params, false/integer/string verbosity, malformed hash, wallet/transaction/broadcast RPC remain denied before opening a socket.

`TwoNodeHeaderLinkAuditor(node_a, auth_a, node_b, auth_b).audit(window_size=8)` reads the canonical chain heights from **two separate, explicitly credentialed, numeric-loopback HTTP endpoints**, verifies `getblockheader`'s returned `hash`, `height` and `previousblockhash` fields independently on BOTH endpoints, and rejects a parent that fails to match the hash reported for the preceding height. If the bounded window starts after genesis, it separately fetches `getblockhash(start-1)` as an anchoring parent. For genesis, the Bitcoin-compatible verbose JSON header must omit `previousblockhash`. The 1–16 block window is read in full **twice**, with two-node regtest identity + unpruned full-profile checks before and after each pass; changing or inconsistent reports fail closed using redacted, fixed error codes.

New native tests use **real TCP to two different localhost HTTP servers** configured with adversarial JSON-RPC responses. They check both peers' headers, changed interior blocks, a forged parent agreed by both endpoints, malformed header identity or shape, wrong genesis/mainnet/pruned profiles, authentication, no wallet execution, redaction, and strict window bounds. Three more tests pin the new RPC method allowlist boundary. Required floors: **50 mandatory suites / 782 full-discovery tests**, preserving prior #93 49/764. No invented genuine-node run.

## Optional combined operator review (follow-on PR #95)

The existing TTY-only regtest ancestry CLI from merged #93 now supports an explicit opt-in flag:

```sh
PYTHONPATH=src python -m tools.audit_two_node_ancestry \
  --node-a-host 127.0.0.1 --node-a-port <A_RPC> --node-a-rpc-user <A_USER> \
  --node-b-host 127.0.0.1 --node-b-port <B_RPC> --node-b-rpc-user <B_USER> \
  --window-size 8 --include-header-links
```

Unattended/non-interactive execution is intentionally unsupported and fails before any credential prompt or RPC request. Each disposable node RPC password is requested **once** from the terminal, shared only inside this one process between the separately constructed ancestry and header read-only auditors. The CLI rejects all forged TRUE operational flags from either report, checks only that their scalar height/start/count match, and emits `rpc_reported_parent_links_match=true` along with **`same_epoch_proven=false`**, `cryptographic_headers_verified=false` and every wallet/scanner/execution permission false. Two sequential RPC audits **cannot prove atomic coherence** or actual consensus/process identity even when scalar heights agree. Any RPC or epoch failure is redacted and produces **no JSON result**. The default CLI without the flag is unchanged and performs **no header RPC**.

Seven additive CLI regression methods pin positive opt-in, default-off, forged authority, scalar mismatch, rejected unexpected/secret-bearing receipt keys, strict two-pass counts and redacted failures. The full native CI floor becomes **50 mandatory suites / 789 full-discovery cases** for this follow-on.

## Trust boundaries remain explicit

This validates only **the parent-link statements reported by RPC endpoints**. It does NOT independently hash or cryptographically validate serialized headers, verify PoW or WAM consensus/BIP94, authenticate the kernel process image, prove the nodes are independent Core processes, prove P2P network isolation or enable scanner/wallet/spending/mainnet. The output records `rpc_reported_parent_links_match=true`, but **`cryptographic_headers_verified=false`**, `block_parent_links_verified=false`, `genuine_core_processes_verified=false`, `real_two_node_regtest_qualified=false`, and all financial/network authority flags false.

The official v0.1.11 Linux Core executable has separately authenticated GPG/archive SHA and independently observed `GNU_STACK RWE` (issue #86), so PR #84 remains fail-closed HOLD. The unconditional Core execution gate #36 stays blocked and DEV WAM alone reviews release/build acceptance. Read-only P2P PR #90 has a separate repository Default CodeQL/required-status issue. This PR does not alter Core upstream, WSP frozen PR #3/#16, historical HOLD #50/#51, wallet secrets or money.
