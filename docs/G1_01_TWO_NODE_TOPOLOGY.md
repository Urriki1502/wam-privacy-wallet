# G1-01 — Two-node regtest isolation plan (OFFLINE / NO EXECUTION)

**Status:** BLOCKED_UNVERIFIED_CORE. This is a candidate topology contract, **not**
a test against real WAM Core. It does not launch a daemon, reserve sockets, create
temporary datadirs, validate credentials, sign, scan or connect to the network.

## Why this step exists

REGTEST-E2E-001 [issue #9](https://github.com/Urriki1502/wam-privacy-wallet/issues/9)
requires two isolated nodes, restart/reorg and RPC cookie checks on a real binary.
The existing `real_regtest._write_private_conf()` serves a **single-node**
identity diagnostic and deliberately contains `connect=0` and `listen=0`.
Those values cannot be copied verbatim into a two-node peer-connect scenario.

G1-01 prepares a **pure-memory candidate configuration** with two loopback-only
nodes and explicit reciprocal peer ports. This does not assert that WAM Core
accepts the exact options on a selected release: real compatibility must be
observed against a verified binary.

## Contract

`plan_two_node_topology((a_rpc, a_p2p, b_rpc, b_p2p))`

- Requires exactly four unique integer ports in the 1024–65535 range;
  booleans, strings and duplicate/invalid ports fail closed.
- Both RPC and P2P addresses are **literal 127.0.0.1**; DNS/seed discovery,
  UPnP and public peer discovery are disabled in previews.
- Each planned node points only to the other node's loopback P2P port.
- The returned frozen value holds **no credentials, binary path, datadir,
  network client, spending key, signer or authorization object**.
- The status stays `BLOCKED_UNVERIFIED_CORE`; all evidence/approval flags stay
  `false`. The module does not generate random ports or claim to reserve them.

## Remaining mandatory evidence

1. Independently obtain and verify official WAM Core release provenance,
   signing identity and exact executable SHA-256; G1-00 hash matching alone
   does **not** establish publisher trust.
2. A separately reviewed executor must create private **fresh temporary
   directories** for both nodes, never read existing user data, select and
   reserve isolated local ports safely, and only launch the reviewed Core
   binary with regtest and strict loopback controls.
3. Verify real Core supports every proposed config flag; prove only intended
   loopback listeners/peers and authenticated RPC. Never automatically fall
   back to a public network or hosted scanner.
4. Verify identity, cookie rotation, wrong-chain/timeout handling, restart,
   two-node divergence/reorg and recovery, with log redaction.
5. Review upstream Windows exclusive scanner-lock PR #9 and wallet WSP-1 PR
   #3 separately. Wallet Phase 010 #16 also remains Draft.
6. Windows x86 GUI/crypto packaging, full wallet signing, reproducible
   releases and independent security review remain **BLOCKED**.

## Offline test and CI

`PYTHONPATH=src python -m unittest discover -s tests -p test_two_node_topology.py -v`

Ten deterministic positive/negative tests run as the 14th mandatory wallet
offline CI suite on native Windows x86/x64, macOS x64 and Linux x64. Existing
13 mandatory suites, GUI tests, GET-only pinned Core check and CodeQL remain
required. No runtime use, Core change, real wallet or release claim is allowed.

**G1-01 PASS = topology contract test PASS only**, not REGTEST-E2E-001.

## G1-01 network-only config section correction (stacked follow-up)

The historical G1-01 PR #27 and reviewed G1-03/PR #38/#40 heads remain
unchanged. This separate follow-up branch revises **only the offline candidate**
to place both `bind=127.0.0.1` (P2P) and `rpcbind=127.0.0.1` (RPC)
**after the `[regtest]` header**, together with the already sectioned
`rpcport`, `port`, and reciprocal `connect`.

Reason: the WAM Core pinned installer places `rpcbind` under the network
section; Bitcoin Core's inherited configuration rules treat `bind` and
`rpcbind` as network-scoped options. A top-level entry may apply only
to mainnet or be rejected/ignored on regtest, depending on binary/version.
This is a **source-level risk correction**, not measured Core behavior.

Before/after (illustrative only, not a runnable config):

```ini
# BEFORE: global scope could be wrong for regtest
bind=127.0.0.1
rpcbind=127.0.0.1
[regtest]
rpcport=<A_RPC>
port=<A_P2P>
connect=127.0.0.1:<B_P2P>
```

```ini
# AFTER: network-only entries under [regtest]
rpcallowip=127.0.0.1
[regtest]
bind=127.0.0.1
rpcbind=127.0.0.1
rpcport=<A_RPC>
port=<A_P2P>
connect=127.0.0.1:<B_P2P>
```

No other config options, topology semantics, safety flags, network I/O,
signing, scanner or release behavior are changed. New regression tests
confirm the corrected ordering and deny the historical layout in the
policy gate. Schema v1 derives from the updated legacy canonical preview
and retains byte-exact parity. The reviewed test-count minimum on this
follow-up stack increases from 150 to **155 cases (16 mandatory suites)**;
original stage descriptions above are historical baselines.

**No real Core process was run; publisher provenance, option effectiveness,
P2P/RPC isolation, external-peer denial and G1-04/G1-05 remain BLOCKED.**
