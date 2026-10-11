# SEC-G1-EXEC-001 — authentic WAM Core, isolated regtest: launch quarantine

**OWNER DIRECTION (11 Oct 2026):** real WAM Core executable for isolated
regtest behavior is the target; absolutely no mainnet/testnet fallback, real
wallet imports, real funds or real-money transactions. The final production
activation/integration belongs to DEV WAM after reviewing and accepting the
complete regtest wallet baseline. See issues #9, #36 and #62.

## Security defect being fenced
The existing `check_real_regtest` diagnostic computed an operator-supplied
binary SHA256 using a **pathname**, then launched via
`subprocess.Popen(pathname)`. A file can change between verification and
execution (TOCTOU). A matching **self-supplied** SHA does not authenticate
publisher or official WAM Core provenance. Issues #50 and #51 improve
individual descriptor read races but DO NOT solve verify-to-execute identity,
Windows ACL/reparse attack surfaces or Core release attestation.

## Implemented at this checkpoint
1. `node/real_regtest.py` adds a mandatory fail-closed
   `_require_reviewed_core_launch()` interlock after read-only digest
   validation **and before any temp datadir, socket bind or Popen call**.
   It unconditionally raises the redacted `CORE_EXECUTION_REVIEW_REQUIRED`.
   There is no environment variable, CLI opt-in or digest that unlocks it.
   This intentionally disables the previous opt-in live-Core diagnostic
   until a qualified launcher is introduced. Original subprocess-lifecycle
   tests remain meaningful: they run with mocked Popen and an individually
   patched interlock, never spawn any real Core process.
2. `node/core_artifact_staging.py` supports a bounded, isolated, non-executing
   copy of bytes from an operator-selected regular candidate. It requires an
   explicit regtest label, exact lowercase SHA256, one-link regular source,
   <=512 MiB, same-FD read with device/inode/size/mtime checks before and
   after, SHA-256 validation, rehash of the temp copy, and a disposable
   `.dat` artifact with no POSIX execute bits. Staging exits destroy the
   temp directory; paths and hashes are hidden from normal repr.
   Its evidence is **OFFLINE_STAGED_UNTRUSTED** and always carries
   `publisher_verified=False`, `execution_identity_bound=False`,
   `core_execution_allowed=False`, `mainnet_allowed=False`,
   `wallet_enabled=False`. There is NO subprocess call or launch permit.
3. **19 additional mandatory adversarial regressions**: 3 real-regtest
   launch-denial cases and 16 staged-artifact input, symlink, hardlink, hash,
   size, post-copy mutation, no-execution and cleanup cases. Existing Core
   lifecycle mocked tests and all 24 original mandatory suites remain.
   New native requirement: **25 suites**, **303 full-discovery tests**.
   Pin critical cases by exact unittest identity. Do not lower old floors.

## What is still BLOCKED, even if all CI is green
- Actual WAM Core release provenance independent of a user-supplied digest.
- An OS-qualified immutable/locked executable snapshot **with proof that
  precisely those bytes reach the kernel's process image**. A tempfile and
  read-only POSIX mode are NOT sufficient against a capable same-user or
  parent-directory attacker; Windows read-only attribute is NOT an ACL lock.
- Windows reparse/ACL behavior, path-parent replacement and exclusive
  process-open semantics.
- RPC cookie same-file-descriptor read under held security PR #50 and OS
  threat model, plus true two-node local-only isolation / regtest identity.
- Native run of an authentic, authenticated WAM Core executable; Windows,
  macOS, Linux real-regtest E2E; scanner, storage, PSBT, wallet signing.
- Production/mainnet code/transaction enablement: **forbidden here**.

The interlock cannot be removed merely because the staging hash matches.
When reviewed real-Core launch mechanics and artifact provenance are ready,
introduce an explicit platform-specific launcher under a NEW qualified
review gate, with synthetic fault injection, native CI+CodeQL and isolated
REGTEST-only true E2E. No WAM Core consensus/source change is authorized.

**PR disposition:** DRAFT security preparation from original protected
`main`. Does not modify held #50/#51, frozen WSP wallet #3/scanner #16 or
ready-for-owner-review combined application #67. Owner alone makes development
PR approval decisions; DEV WAM owns subsequent production review.

## Additive cross-boundary source/bytes qualification (11 Oct 2026)

The new `node/core_candidate_bridge.py` combines two independent,
previously separate **untrusted** review operations: strict
`provenance_intake.intake_core_artifact()` metadata schema checking and
`core_artifact_staging.stage_untrusted_core_artifact()` bounded, read-only
byte snapshotting. The bridge requires the candidate's pinned reviewed
source *claim*, release format and candidate binary SHA, requires that its
declared platform matches the actual Python host/process architecture
(including native Windows 32-bit vs 64-bit), and compares the declared SHA
to file bytes. No API parameter can override the actual runtime platform.

There is **NO trusted DEV WAM publisher public key, signed release manifest,
reproducible build attestation or approved binary digest** in this workflow;
matching the intake's repository/commit or a caller-chosen digest is NOT
proof of publisher authenticity, actual build provenance or executable
identity. Every result remains `UNTRUSTED_CANDIDATE_REVIEW_ONLY` and
`OFFLINE_STAGED_UNTRUSTED`. The unconditional real-Core launch interlock
remains intact.

The staging component additionally rejects Windows
`FILE_ATTRIBUTE_REPARSE_POINT` metadata (even when file type otherwise
appears regular), rejects custom `__fspath__` hooks and checks file identity
and SHA **again on normal exit from the review context**, rejecting a
modified or replaced staged file. This is best-effort tamper detection, not
a security boundary against same-user attackers or an OS-guaranteed snapshot.
No executable gets launched and no signed binary provenance is claimed.

**New additive gates:** 4 extra staging cases + 14 cross-module candidate
cases = **18 new tests**, pinned in **26 mandatory suites** with full GUI-host
discovery minimum **321** (26 pre-existing GUI tests). Critical cases include
host-tag mismatch before any file read, post-review same-size byte mutation,
Windows reparse flag and nonauthorizing matching metadata.
Exactly 8 native Wallet CI jobs plus 2 CodeQL analyses must pass on the
*new* exact HEAD. Old `25/303` evidence belongs only to earlier commits.

**Next trust-root requirement for DEV WAM:** provide authenticated official
release identity (trusted publisher key or independently reviewed signed
release manifest), exact candidate binary digest, source/build mapping,
platform distribution and approved regtest genesis/profile. Then design a
platform-qualified launcher binding those bytes to the process image while
preserving the deny-mainnet gate. Until then issue #36 stays BLOCKED.
