# SCAN-WINDOW-001 — Synthetic block-window coherence (offline research)

## Purpose
Extend **Draft #64** response-shape fixtures with a bounded, deterministic
multi-block window contract. This is a **stacked** branch based on the exact
#64 head `dba9466782089673d0936c975f8443905d2fd668`, not a duplicate
attempt to merge frozen Phase 010 scanner RPC request contract #16.

The pure helper accepts a caller-supplied anchor, in-memory block sequence,
and two claimed snapshots of (height, tip hash). It checks exact types,
contiguous heights and previous-hash links, a reported tip not changing,
end-to-tip link when fully caught up, batch <=16 blocks and aggregate
transaction count <=20,000. Any failure rejects the **whole window**
without yielding an intermediate successful result. Returned status stays
`SYNTHETIC_COHERENCE_ONLY`; all chain/RPC/scanner/wallet authority flags
are fixed `false`.

## Crucial limitations
- **No actual node or chain provenance:** the fixture itself supplies the
  expected block hashes and tips. An attacker may forge internally consistent
  fixtures. Even matching before/after tip hashes cannot prove the node is
  trustworthy, prevent all reorgs, or authenticate an upstream WAM Core.
- No RPC, cookie auth, `rpc.attest()`, filesystem, SQLite, persistent scan
  cursor, WSP scanner, private keys, signing or network use.
- Block subobjects are only already-parsed Python fixtures; these checks do
  not limit raw wire bytes, JSON depth, total block size, RPC timeout, or
  upstream consensus validity. Those must be enforced *before* parsing.
- No real payments, node execution, mainnet permission or release claim.
- Frozen WSP-1 wallet #3 / scanner request #16 and held security #50/#51
  remain unchanged; WAM Core/real two-node is reserved for DEV WAM signoff.

## Regression and integration rules
- Adds **18** deterministic negative/positive tests and pins mandatory suite
  count **25→26** relative to Draft #64.
- Raises GUI full-discovery floor **298→316** on the stacked branch.
- CI reviews must combine the suites from parallel #60 and #61 additively,
  rather than overwriting one another when eventually integrated.
- Require 8/8 native Wallet CI, no skips/xfails, exact-head CodeQL Python +
  Actions and appropriate security review before merge. A stacked green CI
  neither independently qualifies #64 nor authorizes a real scanner.
- Future adapter must authenticate a local-only nonpruned full-node identity,
  bind profile/genesis, run fresh `attest()` per phase, enforce preparse
  response resource limits, exclusive writer/rollback recovery, and rerun
  adversarial E2E with independently reviewed WAM Core under DEV control.

Upstream WSP source reference: `Urriki1502/wam-silent-payments` @
`ac55f13423620252bdbf848c7e8a280c3b84721e`, `Scanner._sync`.
