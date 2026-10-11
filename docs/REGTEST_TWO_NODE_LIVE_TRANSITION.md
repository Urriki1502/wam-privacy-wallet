# REGTEST-2NODE-LIVE-TRANSITION — bounded, real-socket chain observations

This phase advances the existing merged two-node read-only WAM RPC bridge. Unlike a mocked callback path, the operational observer uses **two distinct authenticated numeric-loopback JSON-RPC HTTP transports**, with independent fresh `getblockhash`, `getblockcount`, `getbestblockhash` and `getblockchaininfo` reads. The remote WAM Core nodes must **already be running** in disposable, independently approved regtest datadirs. The tool itself never starts, signs, broadcasts, discovers peers, reads a wallet or accesses a Core binary.

## Usage on already-running approved endpoints

```sh
PYTHONPATH=src python -m tools.observe_two_node_regtest_transition \
  --node-a-host 127.0.0.1 --node-a-port <A_RPC_PORT> --node-a-rpc-user <A_USER> \
  --node-b-host 127.0.0.1 --node-b-port <B_RPC_PORT> --node-b-rpc-user <B_USER> \
  --interval-seconds 2
```

The command checks endpoint and interval constraints **before** two TTY-only prompts for disposable RPC passwords. No env, CLI password, filesystem cookie, built-in default port, DNS or remote service is accepted. The bounded interval is at most five seconds; a single invocation takes two synchronously collected snapshots. It does not schedule background monitoring.

Every snapshot probes and rechecks the two local RPC Core profiles, matching genesis, chain, height and tip, then obtains the same parent and tip hashes through **actual independent RPC calls**. Observable changes during either snapshot, or disagreement between nodes, cause redacted fail-closed denial. The second snapshot classifies:
- `UNCHANGED` — same reported tip and parent;
- `EXTENSION` — higher common tip, with both nodes confirming the old tip remains at its former height;
- `REORG_RESCAN_REQUIRED` — common chain rewound or changed at the old height, including a higher tip which replaced the old block.

This is a **non-authorizing observation**, not a blockchain consensus proof, independent process attestation or scanner rescan instruction. The output contains only bounded scalar heights and booleans; no block hashes, TXIDs, addresses, cookies, credentials or wallet material. All signing, wallet, scanner and broadcast authority remains false.

## Remaining genuine-Core gate

The actual WAM Core v0.1.11 Linux archive is GPG/SHA authenticated and its exact `wamd` member has been verified in Linux NOEXEC sealed memory (#81/#83). The official ELF flags were independently observed as `GNU_STACK=RWE` (#85/issue #86); fail-closed ELF PR #84 remains HOLD pending DEV WAM review. The unconditional `CORE_EXECUTION_REVIEW_REQUIRED` launch gate under #36 has not changed. Neither the live RPC fixture tests nor this observer is proof that genuine independently launched WAM Core processes were used. Real-node 2-node E2E issue #9 remains BLOCKED until DEV-qualified source/build/process binding and keyless isolated regtest runner.

The new native tests use **real localhost TCP sockets** to disposable HTTP protocol fixtures, including fork/reorg/extension, mid-read mutation, wrong genesis/chain/auth, divergent peers, credentials redaction and zero-process launch. They cannot be substituted for actual WAM Core integration. Retain fixtures for adversarial regression while retiring them from operational data sources.
