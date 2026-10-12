# Actual HPKE public-fixture integration, external review HOLD

The Selective Disclosure box in the architecture reaches the application through
`review_public_disclosure_fixture(role, scope, consent)`. It accepts only the
fixed `incoming` or `audit` public experiment, explicit consent and synthetic-
regtest scope. It cannot accept a seed, key, note, memo, ciphertext, executable
path or real-wallet state. It returns a frozen scalar receipt, never decrypted
contents or a capability.

The Rust adapter links the original `wam-privacy-halo2-prototype` directly via
Git revision `db3d2dcaa540f1129d540101813b761167d33174`. No encryption/key policy
is copied or changed. Cargo.lock freezes registry checksums and exact Git source.
The crate's existing RFC9180 HPKE ciphersuite is used, rather than the Phase7 toy
recognition model. The adapter derives only published test seeds. The upstream
bundle internally derives its hierarchy, but the adapter neither requests a
spend-authority handle nor invokes a signer. The bundle is dropped before the
selected viewing operation. Its public test values never represent real funds.

Each run encrypts and opens the selected fixture view, requires randomized
encapsulation, and checks 14 rejection categories: wrong viewing keys, both
cross-role substitutions, all five AAD fields, recipient/audit ciphertext flips,
truncation, trailing data and unsupported version. Source pin, role, native
pointer width, exact count and every false authority flag are checked by Python.
Malformed native requests and extra command-line arguments return no output.

The installed worker has a fixed own-package path. Its generated local manifest
checks bounded bytes and pointer width before execution. **This manifest is
unsigned local-build bookkeeping, not authentication, a secure loader, race-
free binary binding or an external review.** It does not solve trusted runtime
or anti-rollback requirements. Build output and manifest are ignored by Git;
an ordinary installation without a separately built worker fails closed.
No binary distribution, release, disclosure of real data or signed attestation
is created by this PR.

Native CI verifies 46 upstream raw Rust/Cargo blobs before building and runs only
the original eight note-encryption tests, three own adapter tests and eight
actual application/native tests. The matrix executes Linux x64, macOS x64,
Windows x64 and Windows x86, with actual Python width checks. Additional twelve
unit tests are protocol/negative evidence only and do not prove real HPKE.
The original wallet/GUI/CodeQL gates are kept and floors increase additively.

Local macOS arm64 validation: 3 adapter tests, 8 actual native/application tests,
12 protocol/negative tests, the original 8 upstream note-encryption tests and
1235 full wallet discovery cases pass. Other architecture results must be
reported separately as they finish.

wam-privacy Phase15C/15D independent reviews, Phase15E remediation closure and
Phase15F maintainer handoff remain pending. The receipt forcibly records
external_review_complete/runtime_authenticated/spend_authorized/sign_allowed/
broadcast_allowed as false. Wallet #9/#82/#86/#153, trusted anti-rollback
#148/#151, upstream WSP review and CORE-003 scope exclusion remain unchanged.
