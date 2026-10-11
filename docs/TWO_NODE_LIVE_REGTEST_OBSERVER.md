# Two existing WAM Core regtest endpoints: real loopback RPC observer

## Objective

Advance from single-node synthetic-only fixtures to **two actual socket-backed RPC
connections**, retaining fail-closed denial and zero spending authority.
The command reuses the production-code read-only transport from
`regtest_scanner_wire.py` / `regtest_gateway.py` rather than injecting
mock RPC callbacks. It neither downloads nor launches WAM Core.

## Preconditions (not automatically checked or satisfied)

- DEV WAM authenticates the genuine WAM Core release and host execution identity
  under #36 before **any** genuine executable is started.
- Two separately started, disposable, independently owned WAM Core processes
  have isolated regtest datadirs, P2P/RPC ports, no external peers and no real
  wallets, keys or production environment secrets. Regtest genesis must equal
  the pinned WAM profile; neither node may be pruned.
- Both existing nodes reach the same regtest height/tip before observation.
- Distinct numeric loopback RPC endpoint/port and disposable RPC username/password
  for each process. No DNS, hosted indexer, default port or exported password.

## Explicit interactive invocation

```sh
PYTHONPATH=src python -m tools.probe_two_node_regtest \
  --node-a-host 127.0.0.1 --node-a-port <A_RPC_PORT> --node-a-rpc-user <A_USER> \
  --node-b-host 127.0.0.1 --node-b-port <B_RPC_PORT> --node-b-rpc-user <B_USER>
```

Passwords are requested **twice** through an interactive TTY, not accepted by
CLI arguments, a config file or an environment variable. Invalid endpoints
and noninteractive shells are rejected before the password prompts.

The observer probes each node's genesis, height, tip, unpruned regtest profile,
compares the claimed chain states, requests a real read-only mempool summary
on each transport, then probes both again. Changed state, mismatched tip/height,
wrong genesis/chain, invalid credentials, malformed replies or network failures
are redacted and denied. Output contains only counts, a reported common height
and permanent FALSE operational-authority flags; no address, txid, signature,
hash, cookie, wallet secret, RPC response or executable path is retained.

## What it does **not** prove

Even two valid loopback responses might come from one process, a proxy or a
malicious peer. They cannot authenticate the signed WAM Core release, OS process
image, true independence of processes, consensus, P2P connectivity or fork
recovery. The output must never be used as a permission token to scan,
restore, sign, spend, broadcast or enter mainnet.

CI runs real localhost HTTP protocol fixtures, **not genuine WAM Core**; leave
mock/adversarial fixtures in the tests to prove failure handling while shifting
the *application transport path* to genuine user-authorized regtest RPC.
Mark real WAM Core execution and issue #9 two-node acceptance **BLOCKED**
until publisher provenance, verify-to-execute binding, isolation, DEV approval
and recorded genuine two-node test transcript are available.

## Next non-overlapping slices

1. Record exact official signed release + binary SHA, source/release provenance,
   host launch constraints and independent DEV signoff under #36. No automatic
   programmatic approval based only on self-supplied checksums.
2. Qualify the genuine two-node lifecycle: startup, local P2P connect, isolated
   chain divergence/reorg, tip convergence, authenticated RPC denial, restart.
3. Integrate the frozen WSP scanner only **after** upstream #3/#16 review
   and real file-lock/storage crash/recovery gates; no changing Core consensus.

## Confirmed block cross-endpoint mode (additive)

Pass `--block-height <HEIGHT>` to read a confirmed block through the **actual
authenticated loopback HTTP** on both endpoints. The two scanner bridges
independently retrieve `getblockhash(HEIGHT-1)`, `getblockhash(HEIGHT)`, and
`getblock(hash,3)` from their respective local nodes and reject inconsistent
payloads and observed ancestry changes. Then this observer explicitly
cross-compares **both parent and child hashes** from two fresh read-only RPC
views and rechecks them after final profile probes.

The input height must be an integer >=1 and no greater than the jointly
observed tip. No caller-provided parent/block hash is used as evidence; no
raw hash/txid/credential is printed. It reports redacted per-endpoint block
transaction counts and `mode=confirmed`; mempool counts are null in this
mode. Existing mempool behavior remains the default.

This catches some consistent-tip/different-parent and mid-read reorg cases,
but cannot prove an honest node, a shared canonical chain or atomic snapshots.
The fixtures in native CI are disposable HTTP servers. **Actual official WAM
Core execution, two independent process identity, P2P reorg testing, scanner
activation and wallet authorization are all still blocked by #36/#9.**
