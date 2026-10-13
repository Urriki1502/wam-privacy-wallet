# Application network privacy review — no runtime authority

Reuses unchanged `wam-privacy` main pin
`db3d2dcaa540f1129d540101813b761167d33174`,
`prototypes/network_privacy/{model,policy}.py` in the existing review module.
Upstream role, primary-count, private broadcast, OHTTP and endpoint-separation
invariants remain source-pinned. No new transport implementation is added.

The application profile is deliberately narrower: every fallback is denied,
including private broadcast and alternate chain-scan routes. Scan endpoints
reuse `LocalRegtestEndpoint`: numeric loopback only, no DNS, scoped IPv6 or
mapped-address ambiguity. Public endpoint names must be canonical ASCII DNS
labels or canonical IP literals; credential/URL syntax, case/trailing-dot and
IP spelling aliases deny before the upstream model executes. Unused PayJoin
directories cannot implicitly expand the approved operation scope.

The review requires exact explicit consent and synthetic-regtest scope.
It makes no connection and returns no endpoint, credential or routing handle.
`NOT_QUALIFIED_NO_CONNECTION` is a status, not an availability probe. All
transport/scan/sign/broadcast flags remain false. A policy recognizing Tor,
I2P or OHTTP does not demonstrate an available route; there is no direct
fallback or authorization API. Actual adapters and first-hop measurements
remain independently unqualified. Core/RPC process gates are unchanged.

Progress checkpoint: 21 application adversarial tests, unchanged 10 upstream
network-policy tests and existing GUI regression suite. Exact-head native
Wallet/CodeQL results must be observed before merge. No CORE-003 dependency,
Core execution, hosted scanner, signing or broadcast is introduced.
