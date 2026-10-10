# G1-01 → G1-05 review & controlled integration queue

**Research only / do not auto-merge** — snapshot 2026-10-10.
Default branch `main@862bb7692bca9a6f66f490cf5b6bc1dfb9f69fe5` has
13 mandatory offline suites / 106 test cases per architecture.
Draft integration rehearsal [#33](https://github.com/Urriki1502/wam-privacy-wallet/pull/33)
at `9452a8e4a4f3a3a4730909c5a83acfeb1d4388c0` has
[Wallet CI 8/8 and CodeQL 2/2 PASS](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38058228303);
raw Windows x86/x64, macOS x64, Linux x64 logs show 18 suites and 156 cases
on *each* architecture. Rehearsal #33 is explicitly **DO NOT MERGE**.

## Exact source and dependencies

| Phase | PR | Exact verified HEAD | Security meaning | Review state |
| --- | --- | --- | --- | --- |
| G1-01 | [#27](https://github.com/Urriki1502/wam-privacy-wallet/pull/27) | `2f5950ed47b739b9636a79e69b2f74b19a4808f4` | Loopback two-node config **proposal** only | Draft, no approved reviewer |
| G1-03 | [#29](https://github.com/Urriki1502/wam-privacy-wallet/pull/29) | `695abaf4e3d4abdb51734b811e4ebaf39617cf28` | Pure policy shape audit, **stacked on #27** | Draft, no approved reviewer |
| G1-02 | [#28](https://github.com/Urriki1502/wam-privacy-wallet/pull/28) | `baf79d0d5e0c503515751523530ba57e4e95f187` | Untrusted Core digest/tag **metadata**, no publisher verification | Draft, no approved reviewer |
| G1-04 | [#31](https://github.com/Urriki1502/wam-privacy-wallet/pull/31) | `51cdd4b671b3d0ff3312f1e28584e8f9b3c0a8bb` | Offline RPC/auth/cookie **test inventory** | Draft, no approved reviewer |
| G1-05 | [#32](https://github.com/Urriki1502/wam-privacy-wallet/pull/32) | `f2b24275686c60bfa783625d6b891017f7151583` | Offline fork/reorg/scanner **test inventory** | Draft, no approved reviewer |

These PASS claims refer to each candidate's offline validation at its exact
HEAD, **not** real-regtest/WSP scanner/signing capability.

## Preliminary security-review findings (actionable, not audited claims)

1. **P0 — Real WAM Core binary provenance and execution bind**:
   `real_regtest.verify_binary()` computes SHA-256 on a path and returns
   a resolved path; `check_real_regtest()` later calls
   `subprocess.Popen([str(executable), ...])`. That later pathname lookup
   can see changed bytes if a third party can replace the file between
   verification and process launch (time-of-check/time-of-use risk).
   `_read_cookie()` also validates with `lstat()` before a separate
   `read_bytes()`, a potential analogous file race in a hostile workspace.
   **Do not treat a checksum match as proof of the executed artifact.**
   Before using this on untrusted hosts, design a reviewed trusted
   executable snapshot/permissions/immutability strategy that works on
   Windows/macOS/Linux and re-attests process identity where supported.
   Never just disable the SHA gate.
2. **P0 — G1-01/03 candidate configs are not tested against a real daemon**:
   a deterministic equality check proves consistency with the template,
   not Core option support or external-network isolation. Do not enable
   `listen=1` without verifying Core's actual behavior and host firewall.
3. **P0 — G1-02 cannot authenticate the publisher**: a valid-looking 64-hex
   hash, tag and pinned source commit can be asserted by an attacker; the
   candidate correctly remains `UNTRUSTED_CANDIDATE_REVIEW_ONLY`. Before
   real execution, require independently authenticated release signing and
   build/source association.
4. **P0 — G1-04/05 deliberately cannot report live test PASS**: they
   validate *negative-case inventory integrity*, not RPC cookies, a Core
   restart, reorg/recovery, real scanner exclusivity, or scan/spend
   separation. Actual tests remain **BLOCKED** on trusted Core and runner.
5. **P0 — WSP Windows locking and bridge**: upstream WSP
   [PR #9](https://github.com/Urriki1502/wam-silent-payments/pull/9)
   remains open; wallet [PR #3](https://github.com/Urriki1502/wam-privacy-wallet/pull/3)
   and scanner contract [#16](https://github.com/Urriki1502/wam-privacy-wallet/pull/16)
   are separate Drafts. Do not integrate an unlocked scanner or infer
   Windows x86 cryptography support from offline Python tests.
6. **P1 — GitHub governance**: active inspected main ruleset only enforces
   deletion and non-fast-forward restrictions. See
   [branch-ruleset owner setup](BRANCH_RULESET_SETUP.md). CODEOWNERS currently
   names the same user for every file; do not demand self-approval.

No independent security review has been completed. The findings identify
required tests/controls, not confirmed exploits.

## Controlled queue (requires independent review + explicit merge approval)

1. **Owner action**: activate required PR and status-check rules on `main`.
   Arrange at least one eligible non-author reviewer before enforcing
   independent approvals; record ruleset proof.
2. **First G1-01 #27**: review template semantics, full 14-suite baseline,
   no I/O and no authority. Only after approval recreate/merge at its final
   head, then verify post-merge `main` on all four offline architectures.
3. **Then G1-03 #29 (depends on #27)**: because #27 may be squash-merged,
   its stacked head is **not guaranteed** to be based on the new `main`.
   Rebuild from the new main using the exact **G1-03-only delta**, retain
   G1-01 code and all suite floors. Do not simply assume that retargeting
   the old stacked PR is safe. Final CI/CodeQL needed.
4. **Then G1-02 #28**: rebase/rebuild on new main, ensure old test registry
   preserved, verify offline baseline grows to **16/136**.
5. **Then G1-04 #31**: rebase/rebuild, verify baseline **17/146**.
6. **Then G1-05 #32**: rebase/rebuild, verify baseline **18/156**.
7. **After each merge**: verify actual merge commit, eight Wallet CI jobs,
   both CodeQL checks where configured, and no below-baseline test suites
   on all four offline architectures. If any gate is unavailable, stop;
   never reduce the number of required suites or reclassify BLOCKED as PASS.

| Proposed order | Required offline suite floor per platform |
| --- | --- |
| Current `main` | 13 suites / 106 cases |
| After G1-01 | 14 / 116 |
| After G1-03 | 15 / 126 |
| After G1-02 | 16 / 136 |
| After G1-04 | 17 / 146 |
| After G1-05 | 18 / 156 |

The five stages can be reordered only with a newly checked cumulative
registry; G1-03 **cannot precede G1-01**. Every real-node, release, signer
and scanner-rights gate remains `BLOCKED`. Do not merge rehearsal #33.

## Next real engineering after offline integration

- Publisher-authenticated Core binary + signed/reproducible build evidence;
  close TOCTOU/host isolation risks, verify config against real Core.
- Disposable isolated two-node regtest, RPC authentication, cookie rotation,
  restart and reorg/reconfirmation with redacted immutable logs.
- Native cross-process scanner locks on Windows, WSP-1 review, full-node-only
  read bridge; independent security review.
- Wallet encrypted key custody, storage/backup/crash consistency,
  scan/spend separation, PSBTv2 signer/consent, privacy protections,
  Windows/macOS release packaging, independent audit.

Until independently proven, **experimental — NOT production-ready.**
