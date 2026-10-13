# Separated WSP-1 offline signer — boundary before operator release

**Existing, actual upstream source:** `wam_sp.offline_signer`, reviewed source
candidate `ac55f13423620252bdbf848c7e8a280c3b84721e`. The upstream CLI reads
an encrypted keyring and an encrypted request only on a local interactive TTY;
it reconstructs transaction intent before manual signing and writes a
create-once PSBT. This code is **NOT** reimplemented by the wallet application.

This PR adds a Linux-only **handoff inspector** for already-encrypted keyring
and request files: no network, no subprocess, no key import, no passwords,
no signer launch, no account creation. It verifies regular single-link
private files on a 0700 parent using descriptor/path identity checks and
SHA256, output absence and exact upstream commit. Its receipt grants zero
signing, broadcast or mainnet rights. The application cannot silently sign.

This is **not completed signer integration**. The future approved separate
process must verify pinned executable/dependency integrity, quarantine its
environment, prove no network access, independently review recipients,
fees/change/PSBT exact bytes, and use disposable REGTEST keys only. Windows
and macOS OS-specific private-file and signer isolation remain unqualified.
WSP PR #3, Core #9/#82/#86/#153, anti-rollback #148/#151 remain HOLD. No
WAM Core execution, no mainnet or real funds.

The user may review this interface while the upstream signer approval and
true WAM Core regtest E2E are still outstanding.
