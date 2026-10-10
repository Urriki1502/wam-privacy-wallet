# G1-04 — RPC/cookie qualification offline scenario inventory

**PREPARATION ONLY; REAL CORE/RPC REMAIN BLOCKED.** This Draft is derived from
historical [PR #31](https://github.com/Urriki1502/wam-privacy-wallet/pull/31)
against reviewed `main@aae2f35c837ab71ed2b02ccc6cc042db9e67582b`.
G1-01/03 and offline G1-02 are already merged. No historical branch rebased.

The immutable validator `prepare_rpc_qualification(payload)` checks the
complete ten-case **expectation** inventory: correct cookie; invalid cookie;
rotated cookie stale denial; restart snapshot invalidation; unreachable node;
timeout; wrong genesis; pruned node; changing tip; oversized response.
All cases retain `BLOCKED_NO_REAL_CORE_EVIDENCE` and the plan remains
`BLOCKED_VERIFIED_BINARY_AND_ISOLATED_RUNNER`.

The input schema and dictionary keys/case values must have exact built-in
string types; missing/extra or altered cases and forged permission flags are
rejected. Dataclass trust/status fields are `init=False`, rejecting direct
constructor and `dataclasses.replace` claims of PASS/authority.
**These Python object checks are not a secure provenance certificate or
capability boundary.** This module performs no RPC, file I/O, socket, spawn,
download, scanner, signer, wallet state or Core execution.

## CI and evidence rules

- Preserve all 17 existing mandatory suites / 168 test cases on each platform.
- Add 13 G1-04 deterministic offline tests; expected **18 suites / 181 cases**
  per native platform (Windows x86/x64, macOS x64, Linux x64).
- Preserve GUI Linux/macOS/Windows, pinned Core read-only GET and both CodeQL jobs.
- Check each gate on the **exact candidate HEAD**, then seek owner approval
  separately; recheck the actual `main` merge SHA if integrated.

## Future *real* RPC qualification — NOT AUTHORIZED HERE

Before a separate live runner may be designed/used, the operator must provide
independently authenticated publisher identity, release artifact/version,
reviewed binary SHA/source association; harden the verify-to-execute TOCTOU
finding [SEC-G1-EXEC-001 #36](https://github.com/Urriki1502/wam-privacy-wallet/issues/36);
prove fresh isolated disposable datadirs, loopback-only P2P/RPC, native
process cleanup, and confirm actual WAM Core option semantics (particularly
regtest `bind` and `rpcbind`). Tests will require redacted cookie/restart
logs, rejected external traffic and negative RPC responses. Do not log
secrets, use wallet funds, scan public addresses or modify WAM Core.

Linked: [G1-05 Draft #32](https://github.com/Urriki1502/wam-privacy-wallet/pull/32),
[real-node issue #9](https://github.com/Urriki1502/wam-privacy-wallet/issues/9).
Offline PASS never proves RPC/cookie rotation actually ran.
