# Phase 002 — Local WAM Core RPC configuration contract

**Status:** design/validation-only, no RPC connection or backend integration.

This phase introduces `LocalRegtestEndpoint`, a small immutable configuration
contract for future integration with a user-owned validating WAM Core node.

## Trust boundary

- Only the exact `regtest` network identifier is accepted.
- A *numeric* IPv4 or IPv6 loopback address is required. Hostnames, public,
  private-LAN and unspecified interfaces are rejected. No DNS lookups occur.
- The caller must explicitly provide a valid TCP port (integer, 1–65535).
  There is **no** inherited Bitcoin `18443` port or guess of the WAM RPC port.
- This module does not read cookie files, accept credentials, access wallet
  material, open sockets, perform requests, or broadcast transactions.
- The returned URL is descriptive only. Future network clients must retain
  the loopback requirement at the socket boundary; input validation alone
  does not secure an RPC client.

This is **not** a final node connection or mainnet policy. WAM's network
profile adoption and Node/RPC interoperability tests remain external gates.

## Evidence

Run the focused contract tests (stdlib only):

```sh
PYTHONPATH=src python -m unittest discover -s tests -p test_node_contract.py -v
```

Windows PowerShell uses `$env:PYTHONPATH = 'src'` first.

The GitHub Actions matrix tests Windows, macOS and Ubuntu. A PASS qualifies
only deterministic configuration validation, not connected RPC behavior,
authentication, availability, privacy or transaction safety.
