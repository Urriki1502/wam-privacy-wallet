# Phase 005 — Bounded loopback JSON-RPC (experimental)

Adds a restricted read-only HTTP JSON-RPC transport for future communication
with a **user-owned** WAM Core regtest node. It accepts only a validated
`LocalRegtestEndpoint` (numeric loopback IP and explicit port), with
caller-supplied username/password. It never looks up proxy settings,
follows redirects, reads authentication cookies, or resolves DNS names.

## Technical scope

- RPC allowlist: `getblockcount`, `getbestblockhash` and `getblockhash`
  with an explicitly bounded integer height. No send/sign/wallet commands.
- HTTP Basic credentials are explicit, validated and never included in a URL,
  repr or log. Client creates a new direct HTTP connection for every call.
- Default 3-second timeout, maximum 10 seconds. No retries.
- 1 MiB response-size cap and strict JSON-RPC response IDs/error parsing.
- All transport exceptions become stable error codes; server error bodies
  and credentials are not logged or displayed.
- No WSP scanner, wallet database, keys, GUI, consensus or chain writes.

## Verification

Ten synthetic tests use Python's local-only `ThreadingHTTPServer` on
`127.0.0.1` with a random free port. They check allowlisted calls,
parameter denial, no mutation commands, Basic auth, redirect rejection,
HTTP errors, malformed replies, body limits, redaction and timeouts.

GitHub Actions runs these tests under native **Windows x86 and x64** Python
as well as macOS and Linux. No actual WAM node or external endpoint is used.

## Mandatory next gates

1. Verify WAM Core's accepted JSON-RPC wire format, cookie authentication
   and network parameters using a trusted local regtest instance.
2. Couple this transport with `RegtestIdentityProbe` and enforce attestation
   before any WSP-1 scanner use, including reorg and stale-tip rules.
3. Review account/storage permissions, authentication lifecycle, symlink
   threats, cancellation and error hygiene.
4. Independently qualify complete 32-bit GUI/crypto packaging. The native
   32-bit RPC transport alone is **not** a Win32 wallet release.
5. Keep WSP-1 upstream branch and core frozen baselines unmodified.

**No real wallet keys, funds or mainnet are permitted by this CI.**
