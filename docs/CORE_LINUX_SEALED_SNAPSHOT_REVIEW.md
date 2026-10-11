# CORE-LAUNCH research — Linux immutable snapshot (nonexecuting)

**Status:** Linux kernel proof-of-primitive only; no WAM Core process or
execution permit. \`CORE_EXECUTION_REVIEW_REQUIRED\` remains unconditional.

This phase tests whether a disposable, operator-chosen regtest artifact can be
copied from the existing bounded file-integrity staging gate into Linux
\`memfd_create(MFD_ALLOW_SEALING | MFD_CLOEXEC)\`, and permanently sealed with
\`F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL\`.
Those kernel-enforced seals forbid subsequent writes, growth/shrink, or
removing the seals while the review descriptor is held. The code verifies the
fd's digest and seal bits before and after the review context and closes the
descriptor on exit. No subprocess, \`execve\`, \`fexecve\`, \`/proc/self/fd\`
path, actual binary load or wallet secret is involved.

**This is NOT a real Core release provenance or safe launch proof.** An
operator-supplied matching SHA256 is untrusted. Linux memfd sealing does not
authenticate DEV WAM's release key, link the archive to a reproducible source
build, prove the identity of a future running process, bind dynamic libraries,
authorize actual network behavior, nor replace the Windows ACL/reparse and
macOS immutable-snapshot reviews.

API: \`sealed_linux_regtest_review(source, claimed_sha256, network="regtest")\`
accepts only explicit regtest, native path types, and a bounded 128 MiB
candidate. It returns *review-only* metadata; no execution-capable path or
process is published. Linux uses **actual kernel sealing calls** in native CI.
Windows x86/x64 and macOS intentionally fail closed and are tested as such.
There are no test skips and no substituted OS locking implementations.

## Gates before real two-node WAM Core

1. Independently verify official signed v0.1.11 archive with the pinned
   release signer, then authenticate exact node member bytes and approved
   source/build mapping. The existing HTTPS/GnuPG path is a separate gate.
2. Prepare OS-specific verified-bytes-to-executed-process binding review.
   Linux kernel seals are *one ingredient*; linking a future process launch to
   precisely the sealed fd, executable format, runtime libraries and host
   isolation remains unimplemented. Never infer that a sealed review object
   grants a Core launch permit.
3. Resolve Windows ACL/reparse/executable image and macOS integrity/quarantine
   semantics separately. The Linux-only primitive must not silently fall
   back to a normal temporary file on unsupported platforms.
4. Preserve isolated private datadirs and keyless, no-peer regtest setup,
   two independent nodes, RPC cookie descriptor safety, local P2P/reorg,
   and no real funds/network. Only DEV WAM-approved binary/runner may be
   used in the later genuine-Core E2E qualification.
