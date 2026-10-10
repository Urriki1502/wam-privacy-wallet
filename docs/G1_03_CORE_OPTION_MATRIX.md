# G1-03 — WAM Core configuration/source compatibility intake (OFFLINE)

**Scope:** source-only option inventory and observable configuration mismatches.
**No verified binary, no daemon execution, no sockets, no runtime isolation proof.**
The canonical legacy G1-01 config is deliberately unchanged by this change.

## Source reference (2026-10-10)

- Core repository: `wamcoin-core-dev/wam-coin`.
- Wallet's existing pinned inspected Core commit:
  `260bc468e5adffea7ce68d8f97fac3e27e4c50b2`, recorded in
  `compat/wam_core_source_pin.json`.
- Wallet pin protects blobs for `src/wam/wam-params.h`,
  `src/wam/chainparams.cpp` and `scripts/patch_upstream.py`.
- At that Core commit, `install.sh` Git blob:
  `d644ffeb907e2bb6887dca6008f53306eca49d3d`.
  This installer is **observed and commit-addressed here**, but not covered
  by the wallet's current three-blob source-pin contract.
- The `install.sh` generated `wam.conf` places `regtest=1` at global
  scope for regtest, keeps `rpcallowip=127.0.0.1` globally, and places
  `rpcbind=127.0.0.1` **under `[regtest]`**. The installer explicitly
  warns that Core may refuse a network-specific `rpcbind` at global scope.

## G1-01 legacy proposal vs source-observed installer

| G1-01 preview option(s) | Source evidence | Status |
| --- | --- | --- |
| `regtest=1`, `server=1`, `daemon=0`, `listen=1` | Appears in installer config (regtest branch) | **Source observed only** |
| `rpcallowip=127.0.0.1` (global) | Installer uses global scope | **Source observed only** |
| `rpcbind=127.0.0.1` (global) | Installer instead puts it under `[regtest]`; warns about top-level rejection | **MISMATCH — block runtime qualification** |
| `[regtest]` with `rpcport`, `port`, `connect` | Installer uses `[regtest]` but does not establish those three override behaviors for paired nodes | **Unverified** |
| `bind=127.0.0.1` (global) | G1-01 candidate; installer does not establish P2P bind/isolation behavior | **Unverified** |
| `dns=0`, `dnsseed=0`, `discover=0`, `upnp=0`, `natpmp=0` | Not established by source observation of installer | **Unverified** |
| `listenonion=0`, `onion=0`, `proxy=0` | Not established by installer | **Unverified** |
| `connect=127.0.0.1:<peer-port>` | Reciprocally planned in G1-01; no real two-peer link tested | **Unverified** |

The wallet's pinned `wam-params.h` reports regtest default RPC/P2P ports
`29554/29555`. G1-01's four ports are caller-supplied preview placeholders,
not those defaults, not reserved, and not proof of bind/listen behavior.

**Security review finding:** do not run the current preview as if it were a
verified WAM Core configuration. A separate reviewed G1-01 legacy/config
revision may be needed to move `rpcbind` into `[regtest]` (and rebaseline exact
parity tests); do not silently normalize this in schema v1. This is an
identified source-level compatibility risk, **not a reproduced daemon error**.

## Core binary + network qualification (still BLOCKED)

To authorize future G1-04/05 execution, independently obtain:

1. WAM publisher identity and independently verifiable release signature or
   other independently authenticated publication proof; version/tag, exact
   source commit, target OS/architecture, binary SHA-256 and build provenance.
   A self-reported checksum alone does not satisfy this gate.
2. On that verified artifact, capture `wamd -version` and `wamd -help`,
   compare support, names and effective placement of *every* proposed option
   against this matrix; review any version-specific upstream changes.
3. Review disposable per-node datadirs, isolated host/sandbox, loopback-only
   RPC/P2P, distinct ports, strict allowlists, no public DNS/bootstrap/peer,
   cookie authentication, restarts/rotation and cleanup **before** execution.
4. Only then run authorized real regtest tests and prove bound sockets, actual
   peers, rejected external connections, RPC auth, chain identity and safe
   teardown. Audit logs and packet/socket evidence must be bound to exact
   binary and source SHA.

Until those conditions pass: **publisher identity UNVERIFIED; runtime options
UNVERIFIED; OS-level network isolation UNPROVEN; G1-04/G1-05 live tests BLOCKED**.

This document is a source observation and issue inventory, not a compatibility
certificate or permission to run WAM Core, WSP, signer, wallet or funds.
