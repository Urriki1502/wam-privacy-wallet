# Official WAM Core successor — intake is ready, Core execution is BLOCKED

**Source reviewed (13 Oct 2026):**
- Official upstream: https://github.com/wamcoin-core-dev/wam-coin
- Core main source commit: \`609fb9ac24deba98cd7771d77c451674f1709ebc\`.
- Latest **published** release: \`v0.1.11\` (prerelease, 27 Sep 2026).
- Authenticated v0.1.11 Linux \`wamd\` member SHA-256:
  \`625609c08afef441e9dddd71330dcab1cec112d6fabe361769b9907f0efe7ab4\`.
  Static native review found \`PT_GNU_STACK RWE\` (#86). It is **not**
  accepted as the upcoming fixed binary; nothing here executes it.

The official repository documents WAM-specific RPC and REGTEST chain parameters
in \`src/wam/wam-params.h\`, \`src/wam/chainparams.cpp\`,
\`scripts/patch_upstream.py\`. Its \`scripts/regtest_smoke.py\` exercises a
RUNNING chain, and \`scripts/test/test_platform_check.sh\` uses the daemon,
CLI and miner (do not run these with unqualified binaries or on hosted mining
runners). Existing wallet \`core_source_pin.py\` and
\`compat/wam_core_source_pin.json\` enforce the older reviewed source
**without automatically approving newer Core source/release bytes**.

## When DEV sends the next official signed release

1. Independently check the official release URL/tag/source provenance, obtain
   exactly its Linux release tarball plus original **SHA256SUMS** and detached
   **SHA256SUMS.asc**, and the independently authenticated WAM publisher key
   matching fingerprint \`4BD4A8D3AFD43F5CBCB500E23798462FE00ADBA4\`.
   Confirm the publisher key trust/revocation state out-of-band. Do **not**
   derive the trusted digest from a Discord message, caller-provided hash,
   or an unsigned third-party mirror.
2. Use a separately reviewed local GnuPG binary. On a review workstation,
   with no Core process launched, run:
   \`\`\`sh
   PYTHONPATH=src python -m tools.verify_core_successor_offline \
     --archive /trusted-inbox/wam-coin-v0.1.12-x86_64-linux-gnu.tar.gz \
     --signing-key /trusted-inbox/SIGNING-KEY.asc \
     --sha256sums /trusted-inbox/SHA256SUMS \
     --detached-signature /trusted-inbox/SHA256SUMS.asc \
     --gpg-executable /usr/bin/gpg
   \`\`\`
   **v0.1.12 is an illustrative filename, NOT a published release.**
   The tool accepts future higher versions based on signed inventory and
   archive filename equality, not a hardcoded anticipated version.
3. This invokes trusted GnuPG ONLY. Existing verifier authenticates the
   detached SHA256SUMS signature with the **hard-pinned WAM fingerprint**.
   The new intake accepts only the exact matching signed Linux tarball SHA,
   rehashes bounded single-link regular archive bytes and statically inspects
   every ELF, \`GNU_STACK\`, W+X PT_LOAD, archive paths/member types, and inert
   \`share/examples/wam.conf\` without extracting or launching Core.
4. Successful output says \`SIGNED_SUCCESSOR_STATIC_ARCHIVE_INSPECTED_NO_EXEC\`,
   **not** \`CORE_APPROVED\`. It records bounded binary and config digests
   for subsequent DEV/operator review. These are not publication promises.

## Blockers requiring DEV-run acceptance — dashed until demonstrated

- \`#153\` actual **same-build** \`wamd --help\` → \`wam.conf\` option-type
  and safe network default parity on a trusted DEV build runner. The static
  sample reader does NOT check help parity.
- \`#82\` immutable **verified bytes → ELF loader/interpreter → actual process**
  identity including shared libraries, FD inheritance, filesystem/runtime
  namespace isolation and provenance-to-build mapping. No \`Popen(path)\`
  substitution, no execution permission added in wallet.
- \`#86\` non-executable GNU_STACK verified independently on the genuine
  successor binaries (and DEV documents toolchain fix).
- \`#9\` fresh isolated user/DEV-approved two-node WAM Core REGTEST E2E,
  distinct private datadirs and RPC cookies, documented payment, mempool,
  confirmations, bounded fork/reorg and checkpoint restore; only after
  executable/process trust gate and DEV review.
- \`#148/#151\` trusted monotonic **external** checkpoint freshness anchor.
  AES-GCM ciphertext integrity alone does not defeat entire-directory
  rollback.
- WSP-1 upstream PR \`#3\` remains review-gated.
- Windows/macOS native retained scanner/credential custody still requires
  platform-specific tests and code; GUI previews alone are insufficient.

No Core source/build is modified; no Core executable, miner, RPC credentials,
wallet signing/broadcast, mainnet or real funds are used by this intake.
A green mock/fixture test is a parser regression, **NOT** signed official
release acceptance or real Core E2E. The resulting receipt intentionally
sets all launch/wallet/mainnet authorities FALSE.
