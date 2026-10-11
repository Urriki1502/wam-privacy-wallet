# REGTEST-2NODE-PREP — isolated private workspace for approved topology

This feature materializes the **existing G1-01/G1-03 reviewed candidate topology**, not a new mock network model. `prepare_private_two_node_workspace(plan_two_node_topology((A_RPC,A_P2P,B_RPC,B_P2P)))` writes the canonical `wam.conf` previews into **two distinct disposable temporary datadirs** and deletes them on exit.

On native Linux and macOS, both node directories and their shared temporary root have permissions 0700, and the config files have permissions 0600; files are created only via `O_CREAT|O_EXCL` with `O_NOFOLLOW` where available. The prior `audit_two_node_policy()` canonical comparison rejects nonlocal binds, changed peer addresses, duplicate ports or fabricated status flags **before any filesystem change**.

This is **real OS filesystem staging**, not a fake filesystem or test fixture. It creates no socket, process, user-wallet data, RPC cookie, real credentials, transactions or network state. Output file paths are temporary, and the files are not a WAM Core launch authorization. Existing G1 config templates are still **not proven compatible** with the official signed WAM Core binary; neither P2P convergence nor peer independence is qualified.

Windows is deliberately **BLOCKED** until directory ACL and reparse-safe creation are reviewed on native Windows. Tests confirm fail-closed behavior on Windows rather than pretending POSIX chmod enforces a Windows ACL.

Cross-platform CI adds 12 tests that exercise *real* temporary directory creation/removal on native Linux/macOS, strict permissions, exact audited contents, cleanup after caller exceptions, rejection of forged topology/authority, no credential/wallet/process/socket activity and explicit Windows denial.

The Core executable-image binding gate `CORE_EXECUTION_REVIEW_REQUIRED` remains unconditional. Signed GPG archive and NOEXEC memfd checks from merged #81/#83 still apply; DEV WAM retains approval of any actual regtest executable. Finding #86 `GNU_STACK RWE` is unresolved and PR #84 ELF preflight stays HOLD.

## Next acceptance stage (not implemented here)

Once actual release and OS process-image binding are approved, build a separate strictly opt-in launcher with two audited isolated datadirs, direct kernel/OS process identity proof, controlled local P2P, local-only cookie RPC, an external-network exclusion proof, reorg/restart transcript and guaranteed cleanup. Never reuse production wallet/keys or claim mainnet readiness.
