# SEC-G1-EXEC-001 — Binary candidate read/verify identity (offline hardening)

**Status: PARTIAL mitigation only. Real WAM Core execution is still BLOCKED.**
This change is a NEW follow-up to the RPC-cookie pathname-race Draft
[PR #50](https://github.com/Urriki1502/wam-privacy-wallet/pull/50);
it does not repeat that change. It is stacked on PR #50's fixed SHA
`66d3577a40758813bf086ad78f0896abde859d67`, not directly on main.

## New failure surface

Previously `verify_binary(path, sha)` invoked `path.lstat()`, then
re-opened the pathname independently with `Path.open("rb")`, then returned
`Path.resolve()`. A replacement between lstat and the byte-read could
cause a different file to be hashed without proving it was the originally
inspected regular file. This is **distinct** from the previously improved
cookie read.

## Scoped changes

The SHA verifier now:
1. Requires an exact-form SHA256 expected digest, lstat of a regular file.
2. Uses one `os.open` file descriptor for all hashing (with O_NOFOLLOW where
   available and binary mode on Windows).
3. Checks descriptor mode, device, inode, size and mtime against pathname
   metadata before bytes are read. Checks ctime additionally on POSIX.
   Native Windows CRT fstat may expose different ctime semantics than lstat;
   this field is NOT a cross-API Windows identity guarantee.
4. Streams the hash and total byte count through that descriptor only.
5. Rechecks descriptor metadata and the pathname before returning, denying
   detected file swaps or in-place modifications with `CORE_BINARY_CHANGED`.
6. Does not disclose file bytes or paths in errors. Leaves the original
   mismatched SHA detection and no-launch-on-mismatch contract unchanged.

Four initial synthetic tests check pre-open path replacement, simulated
mid-hash metadata change, pathname reopens and repeated native stat/fstat
consistency. Two new regressions model Windows ctime disagreement while still
denying inode, device, size and mtime mutation.
The earlier cookie and all other regression tests are preserved.

When tested together with the stacked PR #50, required gates increase from
**19 suites / 196 tests** to **19 suites / at least 198 tests per native platform** (based on observed
pre-fix 196 collected cases for a 16-case harness), with the mandatory
harness minimum raised from 16 to 18. No existing suites are reduced. The two source PRs still require dependency-aware review and integration.
Do not treat a temporary main-target CodeQL vehicle (#52) as a merge candidate.

## Critical security boundary not solved

The verifier still returns a **pathname**, and `check_real_regtest()`
later launches `subprocess.Popen(path)`. Replacing or mutating that
pathname **after the last verification** can change the bytes actually
executed. A same-user attacker may also evade metadata-only checks on some
platforms. The new check is NOT an immutable snapshot, OS-enforced execution
handle, signature proof, or complete TOCTOU fix.

Windows symlink/reparse handling, ACLs, protected binary identity, macOS
signing/notarization and POSIX user isolation require separately reviewed
native security controls. Never mark issue #36 resolved, start Core,
approve signer/scanner, or claim production readiness from this patch.

**Do not merge without source review and exact-HEAD CI/CodeQL evidence.
The reviewer must not conflate the PR #50 cookie fix with this NEW binary
hash-read fix.** Live execution remains forbidden under existing project
restrictions.

## DEV WAM handoff boundary (project owner confirmed 2026-10-11)

Our scope is to build and hand over a reviewed, deterministic offline/synthetic
regtest baseline only. Actual execution against a real WAM Core daemon,
source-to-binary validation in a real environment, Core integration and any
live/production decision are entirely for DEV WAM after their independent
review and authorization. Nothing in this PR authorizes our team to run real
WAM Core. Required tests must use synthetic files, mocks and offline evidence.
