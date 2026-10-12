# WAM-F6: Core source pin requalification (SOURCE ONLY, not signed binary)

## Failing CI cause

On wallet PR #90, 7/8 native Wallet CI jobs were green. The eighth `tools/check_core_source_pin.py --check-head` returned `CORE_SOURCE_BLOB_MISMATCH` because upstream `wamcoin-core-dev/wam-coin` changed one of three pinned critical files.

The previous immutable reviewed Core commit was `260bc468e5adffea7ce68d8f97fac3e27e4c50b2`. The new independently inspected Core main commit is `87ac8f0786fa5bc0796a5cba21e638911078d475`. Exact **Git blob IDs** are unchanged for `src/wam/wam-params.h` (`d798155e1964adbdb3ccc48b44dd48fcde3b1602`) and `scripts/patch_upstream.py` (`ba933c2353a4eb5672c8cf384182e223620a9952`). `src/wam/chainparams.cpp` changes from `6e7eebfec5483f99ed13849a9b22cd502781364f` to `6081d8259d16513b1857ac893d21651a1400608e`.

Direct byte-level diff analysis found **no deleted/replaced lines**: the new upstream file adds three consensus assignments (plus explanatory comments) to previously uninitialized `consensus.enforce_BIP94`: mainnet `false`, testnet `false`, regtest `true`. WAM Core upstream notes `WAM-F6`, which affects regtest's BIP94/timewarp behavior. This is a **consensus-related upstream change** and must not be silently treated as an incidental documentation-only update.

## Reviewed source-only implementation

Manifest schema v2 now pins the exact reviewed upstream commit and exact per-file Git SHA-1 blob hashes. Additional semantic gate verifies each `CMainParams`, `CTestNetParams`, and `CRegTestParams` defines precisely one scoped `consensus.enforce_BIP94` assignment with values **false/false/true**. Reject missing, duplicated, misplaced, wrong-type or changed values even if an attacker updates the manifest's blob digest. Existing genesis, network ports, RPC patch anchor and pinned WSP-1 reference checks remain mandatory.

The `--check-head` gate **still checks upstream Core main** against exact reviewed critical source blobs. If upstream changes again, CI remains RED until a *separate* source review. No relaxed drift allowance, skip, nonfatal warning, or substitute fake fixture is introduced.

**Scope limit:** This requalification attests to exact source bytes and selected C++ source semantics ONLY. It is **not** proof that the official signed WAM v0.1.11 Linux archive was compiled from this later Core commit, that BIP94 was enabled in that release, or that the binary is safe or authorized to execute. Signed-release GPG/archive authenticity and Linux NOEXEC memfd work remain independent; issue #86's genuine `GNU_STACK=RWE` finding and PR #84's ELF execution denial remain untouched. Genuine two-node startup under #36/#9 stays BLOCKED.

## Testing

The preexisting 47 mandatory CI suites are retained. Add four adversarial BIP94 tests, raising strict native full-test discovery from **733 to 737**. Preserve all Windows/macOS/Linux native matrices, source GET-only check and critical regression identities. This PR makes **no WAM Core upstream code change**, never launches `wamd` and never handles private keys or real funds.
