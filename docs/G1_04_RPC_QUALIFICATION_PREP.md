# G1-04 — Real-core RPC and cookie qualification: PREPARATION ONLY

**Status: BLOCKED.** This PR is a reviewable, offline checklist validator.
It does NOT connect to a node or qualify any binary, genesis, cookie behavior,
restarts, reorgs, response budgets, signing or funds.

## Prerequisites before authorizing a separate live test executor

1. Independently authenticated WAM Core **publisher/release** identity, the exact
   artifact and SHA-256 bound to the reviewed Core source commit; a candidate hash
   or signed-looking string supplied by the same actor is not proof.
2. Owner-approved ephemeral two-node regtest runner using isolated fresh datadirs,
   no real wallets, no inherited secrets, no external peers, loopback P2P and RPC,
   explicit verified process handles, guaranteed stop/cleanup on failures.
3. Reviewed runtime config: confirm Core accepts all proposed G1-01/G1-03 flags.
   The current one-node `connect=0/listen=0` config is NOT a two-node config.
4. Independently reviewed read-only identity gateway, RPC 1.0 vs WSP SDK 2.0
   protocol mismatch handling, JSON response/time/size bounds and cookie rotation.
5. Native Windows x86/x64 + macOS/Linux E2E platform evidence where feasible;
   Windows x86 full GUI/crypto packaging remains a distinct, unsupported gate.

## Reproducible live test specification (not executed here)

- VALID_COOKIE_READONLY_PROFILE: fresh authenticated chain/genesis/tip/profile,
  regtest-only, unpruned, no mutation methods.
- INVALID_COOKIE_DENIED: invalid RPC credentials never accepted.
- ROTATED_COOKIE_STALE_AUTH_DENIED: previous cookie fails after restart/rotation.
- RESTART_INVALIDATES_STALE_SNAPSHOT: never reuse an earlier chain identity as
  authorization to proceed.
- UNREACHABLE_NODE_FAIL_CLOSED: localhost offline or refused connection fails.
- RPC_TIMEOUT_FAIL_CLOSED: bounded timeouts with no unconditional retries.
- WRONG_GENESIS_FAIL_CLOSED: wrong chain/genesis is rejected.
- PRUNED_NODE_FAIL_CLOSED: reject missing full-chain data for scanner use.
- CHANGING_TIP_FAIL_CLOSED: detect tip/height mutation during probe.
- OVERSIZED_RESPONSE_FAIL_CLOSED: reject oversized responses, malformed data.

For each case the eventual *live* artifact should contain only non-sensitive
result labels, software build SHA, OS/architecture, isolated-run ID and reviewed
evidence reference; **never** cookies, RPC passwords, wallet keys or raw response
bodies. Review negative-case failure logs for redaction.

## What the current code actually tests

`prepare_rpc_qualification(payload)` checks the strict inventory above and
rejects any false assertion of publisher, runner, node-execution or release
authorization. All returned cases have `BLOCKED_NO_REAL_CORE_EVIDENCE`.

Run offline: `PYTHONPATH=src python -m unittest discover -s tests -p test_rpc_qualification_prep.py -v`.

Adds **10** offline cases as an additional mandatory suite on this independent
Draft PR, for **14 suites / 116 cases per platform** based on the current
13-suite `main`. Existing GUI, platform CI, pinned Core GET-only and CodeQL
must stay green. No real-node PASS is possible in this schema.

Links: [REGTEST-E2E-001 #9](https://github.com/Urriki1502/wam-privacy-wallet/issues/9),
[G1-01 #27](https://github.com/Urriki1502/wam-privacy-wallet/pull/27),
[G1-02 #28](https://github.com/Urriki1502/wam-privacy-wallet/pull/28),
[G1-03 #29](https://github.com/Urriki1502/wam-privacy-wallet/pull/29).
G1-05 remains separate and requires successful real G1-04 qualification.
