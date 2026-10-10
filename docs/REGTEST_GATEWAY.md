# Phase 006 — Local RPC + WAM Regtest Identity Gateway

**Status:** Experimental, synthetic-node tests only. Not a real WAM Core node
or an authorization for scanner, wallet signing, mainnet, or funds.

## What this changes

This phase composes the previously separate:
- `LocalReadOnlyRpc`: direct loopback JSON-RPC transport, explicit auth,
  response limits, timeouts, no DNS/proxy/redirect, read-only allowlist.
- `RegtestIdentityProbe`: pinned regtest genesis, valid chain height,
  height-to-tip consistency, and stable reread of best tip + height.

`LocalRegtestIdentityGateway` constructs the transport internally rather
than accepting an arbitrary callback or unqualified URL. Each call to
`probe_identity()` **rechecks all identity conditions**. It returns only a
snapshot, not a stored `approved` boolean or access token.

## Boundaries and known limitations

- A local malicious process could still impersonate the RPC server or
  replay fake responses; genesis checks are not authentication of the Core
  binary. Actual Core regtest tests, cookie auth, and binding to the intended
  user-owned node must be qualified separately.
- Credentials remain in Python process memory and are transmitted as HTTP
  Basic credentials over loopback. Nothing reads cookie files or logs secrets.
- A chain tip can change immediately after a snapshot is returned. A later
  scanner operation **must not** use this snapshot as permanent authorization.
- No calls to a real WAM Core node, no WSP-1 wallet/scanner imports and no
  signing or transaction construction occur in this phase.
- This validates pure Python on Windows x86/x64, **not** PySide6, coincurve or
  a complete native 32-bit wallet package.

## CI contract

Ten end-to-end contract tests use a synthetic HTTP JSON-RPC server bound to
127.0.0.1. They check successful six-call identity verification, wrong genesis,
reorg/tip races, height races, mismatched best hash, invalid authentication,
malformed replies, repeat probes, and pre-connection rejection.

All four CI runners (Windows x86 and x64 CPython 3.12, macOS, Ubuntu) must
PASS on the identical PR head. Regression tests for existing node and GUI
modules remain mandatory before merge.

## Next stage

A trusted, user-owned WAM Core **regtest** node fixture would allow optional
real-node qualification, including actual authenticated RPC, binary version,
genesis, and reorg behavior. This needs the Core source/commit and a reproducible
regtest-node runner; it must not silently use a public or hosted node.
