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

## Signed WAM v0.1.11 distribution verification (offline / no Core execution)

**New independent provenance anchor found:** the WAM project's HTTPS
`https://wamcoin.org/security/` publishes its release-signing fingerprint:
`4BD4 A8D3 AFD4 3F5C BCB5 00E2 3798 462F E00A DBA4`.
The official v0.1.11 release contains `SHA256SUMS` and detached
`SHA256SUMS.asc` signatures. The fingerprint is **pinned in repository
code**, never accepted from the candidate's payload or CLI options.
This origin still deserves operator/DEV review for compromise/revocation,
rather than treating a website screenshot as permanent publisher trust.

The new `node/core_signed_release.py` does the following *without running
WAM Core*: takes separately obtained local release signing key, SHA256SUMS,
SHA256SUMS.asc, exact WAM **node distribution archive** and a separately
trusted **absolute path to installed GnuPG**. It copies bounded signed
metadata to a disposable GnuPG homedir, requires exactly the WAM pinned
primary key fingerprint, imports the key only into that disposable keyring,
performs an actual local `gpg --verify` over those exact checksum bytes,
requires a cryptographic `VALIDSIG` from the pinned key and `GOODSIG`,
parses a bounded duplicate-free checksum list, and hashes the selected
nonexecuting archive through the staging layer. Invalid signature, missing
tool, wrong key, malformed checksum, unsupported version/platform, duplicate
entries or wrong binary-archive digest **fail closed**.

**Allowed v0.1.11 node archives only:**
- `wam-coin-v0.1.11-x86_64-linux-gnu.tar.gz`
- `wam-coin-v0.1.11-arm64-apple-darwin.tar.gz`
- `wam-coin-v0.1.11-x86_64-w64-mingw32.zip`

No official Windows x86 node archive or macOS x64 archive is assumed; these
native CI environments remain useful for *contract testing* only. GnuPG
itself must be a trusted, OS-verified local tool; accepting an attacker-owned
executable at a caller-selected path would undermine the signature result.
All tests use synthetic local files and mock the GnuPG protocol; **they do
not assert a live v0.1.11 signature has actually been verified on CI**.
The resulting `SIGNED_DISTRIBUTION_ONLY` receipt is *not an extracted
`wamd` binary attestation*, not a process-image proof, and not a launch
permit. Every mainnet, wallet, executable and funds permission remains false.

**Acceptance target:** 20 additional security cases in mandatory suite 27,
total >=341 full-discovery cases (26 existing GUI cases), complete native
Wallet CI 8/8 and CodeQL Python + Actions 2/2 on the exact modified SHA.
The existing unconditional Core launch interlock is **not** removed.
The actual signed distribution must still be reviewed by DEV WAM, including
revocation and source/build provenance, before considering genuine runtime.

## Signed-claimed WAM Core archive inventory — read-only review

`node/core_archive_inventory.py` is a streaming ZIP/TAR.GZ **inventory
reader**, not an extractor. It accepts a caller-provided
`SignedDistributionEvidence` receipt but explicitly does **not trust** that
receipt as proof a real WAM key signed the bytes: Python callers can construct
a lookalike receipt. It independently compares the complete archive's SHA-256
via nonexecuting staging and then inspects only the validated snapshot.

The expected canonical node entries (per WAM Core release packaging and
START_HERE) are `wam-coin-v0.1.11/bin/wamd` for Linux/macOS and
`wam-coin-v0.1.11/bin/wamd.exe` for the Windows ZIP. Nothing is written to
a destination, installed or executed. Entries are streamed in bounded chunks
to derive the exact *member-content* SHA-256, size and bounded inventory
counts; no extracted file or binary path is returned.

Fail-closed guards: strict relative portable names with exact package root;
reject `..`, `.`, absolute paths, drive prefixes, backslashes, embedded
control chars, ambiguous Unicode, casefold duplicate names, symlink/hardlink,
special files, unsupported ZIP encryption/compression, Windows/Unix symlinks,
missing or empty node, wrong archive SHA, corrupt/truncated container,
>64 members, >128 MiB single member, >256 MiB declared total expansion and
ZIP member compression ratio above 400:1. TAR metadata is processed through
Python `tarfile` and content hash reading is bounded; this is not a
complete decompression-bomb defense for untrusted arbitrarily large archives
or a substitute for a kernel-enforced sandbox.

**Non-authority explicitly enforced:** output is
`UNTRUSTED_ARCHIVE_INVENTORY`, with
`archive_signer_revalidated=False`, `extracted_binary_verified=False`,
`execution_identity_bound=False`, `core_execution_allowed=False`,
`mainnet_allowed=False`, `real_wallet_allowed=False`. Observing an ELF/PE
magic or matching an entry hash cannot assert publisher/build provenance or
safe execution.

Added **23 adversarial TAR/ZIP test cases** (incl. cross-platform archive
names, traversal, symlink, collision, budget and no-extraction/no-socket/no
subprocess tests); additive qualification floor **28 mandatory suites**,
**364 full-discovery tests** on all three GUI hosts. Real GnuPG test with
disposable synthetic key also stays mandatory in Ubuntu native CI.

**Still blocked:** actual official WAM v0.1.11 signed checksum material has
not been verified, source-to-packaged-node binding and exact OS executable
identity/TOCTOU #36 remain unqualified. All actual WAM Core launches remain
unconditionally denied. No real-money/mainnet wallet transactions.
