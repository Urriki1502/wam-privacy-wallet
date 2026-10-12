# SEC-G1-EXEC-001 (#36): verified bytes -> executed image, acceptance contract

**Status: BLOCKED — non-executing design only.** Related: #82, #84, #86, #9. No wallet/Core execution authority arises from this document.

## What is already established

- Exact official signed Linux v0.1.11 archive and `wamd` member hashes, checked using native GnuPG and archive inventory; independently signed artifacts, not a reproducible-source-to-build proof.
- Actual Linux `MFD_NOEXEC_SEAL` review buffers, strict write/grow/shrink/seal requirements, `F_SEAL_EXEC`, SHA-256, device/inode pinning, descriptor-use and post-close lifetime defenses. These buffers are **intentionally NOT executable**.
- The generic `real_regtest.py` path SHA preflight is also **non-authorizing**; the original `subprocess.Popen(path)` path would admit verify-to-exec substitution. The unconditional `CORE_EXECUTION_REVIEW_REQUIRED` gate must remain.

## Separate trust decisions (none inferred from another)

1. **Publisher / provenance:** independently pinned release signing fingerprint; authenticated archive and member hashes; key revocation and current release status; source commit/build toolchain association.
2. **Security policy:** ELF program headers accepted (no W+X `PT_LOAD`, no unreviewed executable `PT_GNU_STACK`); loader and transitive dynamic libraries verified; approved host/kernel and container/user/network isolation. Current signed v0.1.11 ELF requests GNU_STACK RWE: **HOLD #84/#86**.
3. **Immutable execution candidate:** a distinct future, explicitly authorized execution-capable kernel object, with bytes rehashed after population and immutable seal enforcement. **Do not attempt to turn an existing `MFD_NOEXEC_SEAL` review descriptor into an executable image**. Never use a mutable pathname fallback.
4. **Actual OS launch binding:** Linux design must use an independently reviewed descriptor-directed syscall (e.g. `execveat(fd, "", argv, envp, AT_EMPTY_PATH)` / `fexecve`) and prove which kernel-backed file description the child receives; do not make `/proc/self/fd/N` a mutable pathname substitute. Address `FD_CLOEXEC`, interpreter resolution, dynamic linker and transitive `DT_NEEDED` files, inherited FDs, env, kernel namespaces, PID reuse and all error/cleanup paths.
5. **Observed child identity:** pin process to a PID handle (e.g. `pidfd` on Linux), and verify process image/loader provenance using OS-supported means and launch-time binding evidence. A post-launch `/proc/<pid>/exe` or command-line observation *alone* does not prove byte-for-byte launch identity; document residual races.
6. **Regtest isolation:** disposable two-node datadirs, strict independent RPC credentials/cookie handles, 127.0.0.1 RPC and peer scope, explicit peer restrictions, no inherited user HOME/keys/proxy, no wallet/signing/broadcast/mainnet, controlled stop/cleanup. Do not silently broaden network authorization.
7. **Scope and governance:** DEV WAM signs off on revised official Core binary/build policy; project owner explicitly approves opt-in regtest-only executor. Windows/macOS execution paths remain denied pending independent native security binding, not inferred from Linux.

## Required verification before moving any execution interlock

- Native Linux tests first use a **harmless synthetic executable fixture that is not WAM Core**, with controlled path swap, identical-bytes swap, fd reuse, library/interpreter tampering, mutation after hash, PID reuse, premature close and process cleanup.
- Demonstrate unchanged verified fd reaches kernel launch; negative tests must fail closed, with no fallback `Popen(path)`.
- Genuine signed Core binary remains **NOEXEC / static observation only** until signed new release or documented approved build-policy exception and all prior gates pass.
- Separate exact-HEAD Linux/Windows/macOS CI + CodeQL/security review; no CI skips, suppressed failures, lowered floors, or mock evidence mislabeled as actual Core process.
- Only then owner + DEV WAM approval for isolated live two-node regtest (#9); capture source/release/loader/child identity artifacts and redacted proof logs.
- **Never** infer wallet production, mainnet, signing, broadcast or fund-use authorization from a passing regtest test.

## Explicit decision

`#36 BLOCKED` and `#9 BLOCKED` until ALL required binding, publisher/build, ELF hardening, runner containment and DEV/owner approvals exist. Signed-bytes + sealed NOEXEC memory are prerequisites, **not the executed-image proof**.
