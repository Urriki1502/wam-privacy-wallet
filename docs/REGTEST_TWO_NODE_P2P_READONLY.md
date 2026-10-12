# REGTEST-2NODE-P2P — read-only, actual localhost JSON-RPC topology audit

This phase builds on merged #88 private two-node workspace and #89 live two-node RPC chain-transition observation. The code does **not** start WAM Core, open a P2P socket, create/destroy peer links, read wallet state, use developer-unapproved binaries, spend, sign or broadcast.

`TwoNodeP2PReadOnlyAudit` makes bounded HTTP requests using **separate, fixed allowlist P2P RPC transport** (`getnetworkinfo`, `getpeerinfo` only) to two independently specified, already-running **numeric IPv4 loopback** RPC endpoints. It brackets two repeated peer observations with fresh unpruned regtest chain profiles and rejects any observable peer or chain changes. This is real TCP/HTTP to provided addresses, not a callback/mock fallback. Input requires four distinct explicit RPC/P2P ports and separate credentials; the CLI obtains secrets through interactive TTY prompts, never argv/environment/files.

## Fail-closed conditions

- Both endpoints report the same regtest genesis, chain height and tip via the established WAM chain-profile checker.
- One peer and exactly one reported connection per endpoint. Network active, no announced public/local addresses, no extra inbound/outbound connections. Require `connections_in/out` explicitly and check them against `getpeerinfo.inbound` on each node (A: 0/1, B: 1/0); missing or inconsistent counters fail closed.
- Node A reports a single outbound peer at `127.0.0.1:B_P2P`.
- Node B reports a single inbound peer at `127.0.0.1:<A_ephemeral>`, bound locally to `127.0.0.1:B_P2P`. Node A's locally bound source port must match B's reported inbound peer source. External IPs, DNS names, IPv6-mapped IPv4, unexpected peer directions and peer-count anomalies are denied.
- RPC replies are capped at 128 KiB, only uncompressed responses, bounded HTTP header length, exact JSON-RPC response envelope and redacted error codes. No RPC calls are made to `addnode`, `disconnectnode`, `sendrawtransaction`, `stop`, or wallet methods.
- The audit returns only scalar booleans and peer counts; no credential, IP address, TXID, blockhash, node ID or wallet data.

This deliberately qualifies only one **A→B outbound/B←A inbound** shape. It does not pretend to prove other valid P2P topologies (such as bidirectional outbound discovery). Bitcoin-derived `getpeerinfo` fields may vary between WAM versions, and any mismatch must result in a specific denied review, not a broadened acceptance policy without DEV WAM validation.

## Exact offline and live boundaries

Native CI exercises **real loopback TCP sockets to disposable HTTP protocol fixtures** with 18 adversarial tests: public peer, wrong P2P listener/source, spoofed advertised address, extra peers, missing/malformed network fields, wrong regtest identity, wrong auth, failed wire envelopes and post-read mutation. Fixtures are not WAM Core. Operational code has no fixture injection.

A pass only means two already-running RPC servers **report** the expected localhost P2P topology and consistent regtest chain profile during the observation. **It does not prove** independent genuine WAM Core processes, absence of hidden external sockets, kernel/process-image binding, actual consensus P2P handshakes, a fork/reorg E2E pass, wallet/scanner authority, or readiness for real funds.

Signed v0.1.11 `wamd` release verification and NOEXEC memfd evidence are merged #81/#83; the independent `GNU_STACK=RWE` build finding remains #86 and static ELF PR #84 stays HOLD. `CORE_EXECUTION_REVIEW_REQUIRED` in #36 is unconditional. DEV WAM approval of exact build, runner, runtime loader and safe executable-image binding is required **before** genuine two-node WAM Core launch. No mainnet, production wallets, WSP frozen-branch merges or core source changes are introduced.

Example (two pre-existing approved regtest RPC servers only):

```sh
PYTHONPATH=src python -m tools.audit_two_node_p2p \
  --node-a-rpc-port 39001 --node-a-p2p-port 39002 --node-a-rpc-user regtest-a \
  --node-b-rpc-port 39003 --node-b-p2p-port 39004 --node-b-rpc-user regtest-b
```

Ports above illustrate explicit input only; they are **not** claimed available or WAM Core defaults.
