# Linux kernel-enforced network/exec syscall denial for WSP offline signer CI

This CI-only extension runs actual source-pinned WSP `wam_sp.offline_signer`
inside a **different Linux Python process**, adding a Linux kernel
`seccomp-BPF` filter in THAT child before it imports or runs the signer.

The child uses `PR_SET_NO_NEW_PRIVS`, requires installed `libseccomp.so.2`,
denies socket/socketpair/connect/bind/listen/accept/send/receive syscalls,
new process creation/exec and ptrace, and confirms the kernel rejects a
real `socket(AF_INET, SOCK_STREAM)` attempt with `EPERM`. The independent
probe separately checks a child actually has a loaded network filter;
any unavailable library or denied filter installation fails the native
CI (no skip, no weakening of other tests).

The existing source-pinned disposable synthetic-chain workflow must still:
- create genuine WSP AES-GCM intent,
- exercise DECLINE with no signed artifact,
- exercise explicit SIGN using upstream CLI and a test-only keyring,
- validate actual upstream Schnorr/BIP352 and independent PSBT-intent
  matching, and reject signature tampering.

Expected markers:
`WSP_OFFLINE_SIGNER_KERNEL_NETWORK_DENIED` from the network probe child;
`WSP_SIGNER_CHILD_SECCOMP_NET_EXEC_DENIAL_PASS` from the native test.

**Precise boundaries:** Blocking network and exec syscalls **does not**
isolate the filesystem, procfs, memory, TTY, ptrace from all existing
processes, or host RPC reachable through inherited descriptors. The child
starts with `close_fds=True` and explicit PTY stdio, but this is not a
complete signer production sandbox. libseccomp package provenance and
Linux process-image attestation are still unqualified. The parent CI
provisions the disposable keyring and therefore handles test secrets.
No official signed WAM Core is started, no live two-node WAM Core E2E
or wallet executable acceptance, no broadcast, mainnet or real funds.

The signing app runtime remains unchanged and **cannot launch the signer**.
This is test-only; OS isolation and full WAM Core acceptance #9/#82/#86/#153,
recovery rollback #148/#151 and WSP upstream PR #3 remain on HOLD.
