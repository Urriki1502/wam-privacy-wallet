# G1-05 — Two-node reorg/recovery and scanner boundary: PREPARATION ONLY

**BLOCKED** pending independently authenticated Core binary, G1-04 real RPC
qualification, repeatable two-node runner, native scanner locking and review.

G1-05 is a future, separate live qualification stage. This Draft PR is
**strictly an offline acceptance-case catalog and validator**; its tests do
not prove scanning works on WAM Core or that a reorg, crash or restore occurred.

## Required future live scenarios

1. TWO_NODE_P2P_CONVERGENCE: verify isolated, reciprocal localhost peers,
   independent node identity and convergence under explicit height checks.
2. FORK_DIVERGENCE_DETECTED: stop trusting stale tip/snapshot when branches
   diverge, no false confirmations or already-final settlement.
3. REORG_RECONFIRMATION: prove deterministic disconnect/reconfirm outcome,
   including rollback of derived scan state, no premature authorization.
4. RESTART_RESTORE_STATE: independently restore disposable scan state and
   attest Core again after restart, never reuse previous cookie.
5. MISSING_PREVOUT_FAIL_CLOSED: missing input metadata must block processing.
6. STALE_SCANNER_TIP_FAIL_CLOSED: a changed best tip must require refresh
   before any scanning phase, no hidden remote indexer fallback.
7. ONLY_USER_LOCAL_FULL_NODE: no public DNS/hosted-scanner/cloud fallback.
8. EXCLUSIVE_SCANNER_LEASE: prove actual cross-process exclusive writer on
   Windows x86/x64, macOS and Linux, not an in-process placeholder.
9. LOCK_CRASH_RECOVERY: forcibly terminated scanner must release OS lease
   and allow re-acquisition, while keeping state integrity.
10. BROADCAST_OR_SIGNER_AUTH_DENIED: default read-only scanner cannot submit
    transactions or sign; offline PSBTv2 spends require later dedicated
    authorization and wallet security review.

## Evidence and strict separation

Run the real scenarios only in a reviewed disposable *two-node* regtest fixture
with independent publisher-verified exact Core SHA and fresh private datadirs.
Capture exact commit SHA, binary build and provenance, host OS/arch, fixture
identity, bounded redacted result codes, heights/tips before/after each phase,
reconnect/reorg/reconfirmation and OS-lock negative tests. Never store cookies,
passwords, scan secrets, private keys, user wallet DB or raw RPC bodies.

Upstream WSP Windows [lock PR #9](https://github.com/Urriki1502/wam-silent-payments/pull/9)
and wallet WSP-1 [PR #3](https://github.com/Urriki1502/wam-privacy-wallet/pull/3)
remain unmerged/review-gated. Phase 010 [#16](https://github.com/Urriki1502/wam-privacy-wallet/pull/16)
is also Draft. No Core modifications, real funds or public-node scanning.

## Offline preparation: what passes now

`prepare_reorg_qualification(payload)` checks **only** that the exact ten-case
inventory cannot be silently reduced or converted to self-reported success.
All outputs stay `BLOCKED_NO_REAL_REORG_EVIDENCE` regardless of input.

Offline test: `PYTHONPATH=src python -m unittest discover -s tests -p test_reorg_qualification_prep.py -v`.

This adds 10 cases and requires the existing mandatory CI matrix (14 suites,
**116 cases each** from the current 13-suite main). GUI, pinned Core GET-only
check and CodeQL remain mandatory. Once reviewed, a future live harness may
use this inventory as acceptance criteria, but must not mark this offline suite
as real-node qualification.

See [G1-04 qualification preparation](https://github.com/Urriki1502/wam-privacy-wallet/pulls)
and [REGTEST-E2E-001 #9](https://github.com/Urriki1502/wam-privacy-wallet/issues/9).
