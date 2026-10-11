# CORE-EXEC-082 step 1/2: actual signed WAM Linux member into NOEXEC memfd

This phase joins merged #79/#81 **real publisher-signed release verification** and merged #80 **real Linux kernel sealing**. It does NOT introduce a WAM Core launcher or grant any executable/wallet authority.

## Exact authenticated Linux release pins

- Archive: `wam-coin-v0.1.11-x86_64-linux-gnu.tar.gz`
- Archive SHA-256: `bd010ed615ab8063d5c12aa61236311ece7e9d19896d9541dacba1888dd9987a`
- Node member: `wam-coin-v0.1.11/bin/wamd`
- Node SHA-256: `625609c08afef441e9dddd71330dcab1cec112d6fabe361769b9907f0efe7ab4`
- Release signer pinned in code: `4BD4A8D3AFD43F5CBCB500E23798462FE00ADBA4`
- Source: genuine official release review CI #38148529648 (read-only, no Core launch).

On Linux only, `sealed_signed_linux_wamd()` calls **real native GnuPG validation** of the detached signature with the pinned key, performs bounded archive inventory, stages and hashes the exact signed archive, streams *only* the approved `wamd` TAR member to kernel `memfd_create(MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL)`, rehashes the bytes and seals the descriptor against writes, growth, shrinkage and seal removal. A second kernel seal/byte audit is mandatory both before and after exposing temporary review evidence. The descriptor is always closed and has no execution API.

**Fail closed:** wrong or untrusted asset, unsigned/checksum mismatch, wrong node member SHA or metadata, unsupported OS/kernel flags, ZIP or directory confusion, member-size mismatch, noexec flag unsupported, tampering, shortened stream and seal errors. Windows/macOS have no fallback.

## Genuine-release CI path

The official release workflow downloads the actual signed WAM v0.1.11 Linux archive (no extraction or execution), runs the existing genuine GnuPG/archival verifier, then **independently re-verifies the signature** for the NOEXEC memfd operation. It asserts the pinned node hash, kernel seal status, explicit NOEXEC observation and permanent false execution/mainnet/wallet authority. Unit CI uses only synthetic adversarial fixtures and patches the hash pins inside tests; those fixtures are not release authenticity evidence.

This is still **NOT an execution-image identity proof**. The memfd is deliberately non-executable, cannot be used as a shortcut launcher, and may not be promoted to permission for `execveat`, `Popen` or `/proc/self/fd`. A separate, reviewed kernel-to-process identity design plus DEV WAM approval is needed for **regtest-only** Core execution. The unconditional `CORE_EXECUTION_REVIEW_REQUIRED` interlock remains unchanged. It does not validate source-build reproducibility, signer revocation, dynamic loader or library linkage, P2P isolation, wallet signing or actual two-node Core consensus/reorg operation.

## Non-overlapping next slices

1. Produce a reviewed Linux FD-bound launch design with official source/build mapping and no mutable path handoff, without unlocking Core execution prematurely.
2. Windows ACL/reparse and macOS code-sign/quarantine equivalent process identity work, separate from Linux memfd.
3. DEV-approved disposable two-node WAM Core regtest startup with strict isolation, live RPC and controlled reorg E2E. No mainnet, actual funds, reused wallets, or private keys.
4. Only then integrate frozen WSP scanning + durable storage recovery and retire remaining operational mock outputs, retaining adversarial fixtures.
