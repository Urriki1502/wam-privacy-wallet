# Cross-platform existing two-node WAM Core REGTEST RPC readiness

**Status: operator-owned actual socket diagnostic — NOT a WAM Core E2E PASS.**

The wallet's already-running-node read boundaries can now be exercised on
Windows x64, macOS and Linux independently of WSP storage and GUI activation.
No binary is downloaded or launched. Require two separately configured
disposable `wamd` nodes with loopback RPC, distinct credentials/ports and
exactly one direct P2P connection. Do not use an existing WAM datadir.

From the repository root after installing dependencies:

```sh
PYTHONPATH=src python -m tools.verify_two_node_core_readiness_live \
  --node-a-rpc-port 29554 --node-a-p2p-port 29555 --node-a-rpc-user disposable_a \
  --node-b-rpc-port 29556 --node-b-p2p-port 29557 --node-b-rpc-user disposable_b \
  --acknowledge-unverified-processes
```

On Windows PowerShell first set `$env:PYTHONPATH = "src"`, then run the
`python -m ...` command without the POSIX backslash continuations.

Passwords are prompted on an interactive TTY, never accepted in flags or
environment. This exercises actual loopback RPC/P2P using strict clients:
reported regtest genesis/tips, synchronized txindex/coinstats/basic-filter
index and linked basic filter headers on **both nodes**, then revalidates
topology and tip. A moving chain, stale index, divergent hash, unsupported
filter or missing isolation report fails closed with a fixed denial.

No positive result authenticates executable bytes, loader/process identity,
WSP scanning, signer, broadcast, wallet readiness or Core E2E acceptance.
GitHub CI uses mock boundaries for positive control flow and negatives only;
actual WAM Core runs require an independently verified publisher/build,
isolated operator host and owner/DEV acceptance (#9/#82/#86/#153).
This diagnostic does not bypass `CORE_EXECUTION_REVIEW_REQUIRED`.
