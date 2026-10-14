# REAL two-node WAM REGTEST scan-only operator (unqualified Core process)

This composed application path uses NO synthetic backend at runtime. It first
audits the **real localhost RPC and P2P** of two already-running, separately
configured WAM REGTEST-shaped nodes: each reports the same genesis, chain tip,
and one exclusive loopback P2P peer. It then runs the source-pinned WSP-1
Scanner/SQLite only against node A, followed by another two-node RPC/P2P
audit. Mid-operation tip/P2P changes refuse success; no stale successful
wallet, history or balance receipt is issued.

## Prerequisites

Two genuine operator-provisioned Core nodes with private disposable datadirs,
separate RPC/P2P ports and credentials, exactly one peer between them, and no
external networking, production wallet, real seed or mainnet. The pinned
upstream WAM source defaults are REGTEST RPC=29554, P2P=29555. Choose
noncolliding ports for node B (example below only). This application neither
downloads nor launches any binary and cannot authenticate process identity.

Optionally add `--require-synchronized-indexes` to the interactive command to
require the live node's txindex, coinstatsindex and basic block-filter indexes
and consistent filter-header observations before and after scanning. This
uses the **existing actual RPC readiness path** on node A, not a synthetic
provider; node B's P2P and chain-tip audits still enclose the scan. A reported
ready index is not executable provenance or Core E2E acceptance.

The WSP scan-only backup and pinned source checkout must already exist on
the Linux x64 host and satisfy the source/crypto/storage gates.

```sh
PYTHONPATH=src python -m tools.run_two_node_wsp_regtest \
  --wsp-source-root /absolute/pinned/wsp-source \
  --private-dir /absolute/private/disposable-state \
  --node-a-rpc-port 29554 --node-a-p2p-port 29555 --node-a-rpc-user test_node_a \
  --node-b-rpc-port 29556 --node-b-p2p-port 29557 --node-b-rpc-user test_node_b \
  --history-limit 20 --acknowledge-unverified-binaries
```

The three private passwords are prompted via an interactive TTY. No password
may appear in arguments, environment, public receipt or CI logs.
`--save-checkpoint` writes one WSP AES-GCM archive; recovery from a fresh
empty store uses `--restore-checkpoint` and requires a genuine rescan. A
partial scan reports chain_current=false rather than a stale balance.
Private history TXIDs print **only** when the operator explicitly chooses
`--history-limit`.

**Limits:** Node identity still comes from potentially forged local RPC
responses. The two endpoints could be one malicious program. This is NOT
verified WAM Core executable/loader provenance, a controlled fork/reorg,
independent process attestation or real Core E2E acceptance. Those stay
BLOCKED (#9/#82/#86/#153), as do trusted anti-rollback (#148/#151),
WSP upstream PR #3, authenticated balance, signing/broadcast and mainnet.

CI runs contract and refusal tests only, not actual WAM Core. Genuine
on-host E2E must be carried out under independently reviewed binaries and
isolated runtimes. No test synthetic peer is loaded by this application.
