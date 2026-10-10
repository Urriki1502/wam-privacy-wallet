# G1-05 — Two-node reorg/recovery/scanner readiness (OFFLINE ONLY)

**BLOCKED: no actual Core two-node test, scanner, reorg or funds.**
Ported only the five-file G1-05 source/test/CI/docs delta from historical
[Draft #32](https://github.com/Urriki1502/wam-privacy-wallet/pull/32) onto
`main@36b0b88d4ca3360cfad4407a44d9e0f232a0b506` after G1-02.
This candidate is **unmerged**; historical #32 and old independent #46 remain intact.
G1-04 [PR #45](https://github.com/Urriki1502/wam-privacy-wallet/pull/45)
is **already merged into main in its offline-only scope**. Real RPC remains BLOCKED.

## Ten future live scenarios, currently only expected outcomes

1. TWO_NODE_P2P_CONVERGENCE — attested reciprocal loopback peer convergence.
2. FORK_DIVERGENCE_DETECTED — stale-tip invalidation during fork.
3. REORG_RECONFIRMATION — rollback and reconfirmation of derived wallet data.
4. RESTART_RESTORE_STATE — cookie/snapshot re-attestation after restart.
5. MISSING_PREVOUT_FAIL_CLOSED — missing input metadata denies progression.
6. STALE_SCANNER_TIP_FAIL_CLOSED — changing tip demands refresh.
7. ONLY_USER_LOCAL_FULL_NODE — no remote hosted-scanner/indexer fallback.
8. EXCLUSIVE_SCANNER_LEASE — true cross-process native writer exclusivity.
9. LOCK_CRASH_RECOVERY — process death and safe lease reacquisition.
10. BROADCAST_OR_SIGNER_AUTH_DENIED — no hidden spend/broadcast rights.

Only `prepare_reorg_qualification(payload)` runs now: strict fixed test
inventory and immutable `BLOCKED_NO_REAL_REORG_EVIDENCE` case results.
Input mapping keys and scenario key/value types must be built-in `str`,
there is no runtime authority claim, and constructor/replace impersonation of
status or approval fields is rejected. This is a Python data integrity
test—not a cryptographic authorizer. No network/socket/process/filesystem I/O.

## Offline quality gates and future integration

Current protected `main`: **18 mandatory suites / 181 tests** per native
Windows x86/x64, macOS x64, Linux x64, including merged G1-04 offline.
This cumulative G1-05 PR adds 13 tests (historical 10 + 3 adversarial),
requiring **19/19 suites / 194 tests** per platform, 8 Wallet CI jobs,
2 CodeQL analyses and unchanged GUI. Both G1-04 and G1-05 registry entries
must remain mandatory. Rerun all checks on the exact new HEAD.
Do not merge without explicit owner approval.

## Mandatory gates before real two-node/scanner execution

- Independently authenticated WAM Core publisher binary/source provenance;
  repair verification-to-launch TOCTOU [issue #36](https://github.com/Urriki1502/wam-privacy-wallet/issues/36);
  actual native isolation and fresh datadirs.
- G1-04 real authenticated RPC/cookie/restart evidence and safe negative paths.
- Reviewed cross-process WSP Windows locking PR #9; frozen wallet WSP-1
  [PR #3](https://github.com/Urriki1502/wam-privacy-wallet/pull/3)
  and scanner contract [PR #16](https://github.com/Urriki1502/wam-privacy-wallet/pull/16)
  remain separate Drafts, not implicit approvals.
- Independent code and security review; native OS/arch host controls and
  redacted test evidence with exact artifact and SHA associations.

Readiness source/CI PASS, if achieved, remains **NOT REAL WAM CORE PASS**.
