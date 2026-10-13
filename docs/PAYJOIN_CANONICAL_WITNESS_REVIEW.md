# PayJoin final witness encoding follow-up

The pinned WSP public signature verifier can validate the mathematical
signature in a 65-byte final witness whose final byte is DEFAULT=0. That does
not establish canonical wire encoding. A native adversarial fixture reproduced
this gap in the wallet's newly integrated read-only PayJoin profile.

The application now checks final signature shape BEFORE the existing public
verifier: DEFAULT signatures are exactly 64 bytes; 65-byte signatures require
explicit ALL=1. Other forms deny. This is the same narrow sighash profile as
the pinned WSP signature-map decoder; unknown modes are not silently expanded.
Reference: [BIP341 key-path signature validation](https://bips.dev/341/#taproot-key-path-spending-signature-validation).
This reference is a specification, not evidence of WAM Core acceptance.

One new native case reuses a mathematically valid public fixture signature and
appends an explicit zero byte. Before the fix: exactly this case FAIL (no denial)
with all prior cases passing. After the fix: 34/34 native PSBT/PayJoin/Qt cases
PASS locally. Real WSP parser/public verifier and unchanged privacy validator
are exercised, but transactions and keys are disposable synthetic fixtures.
No operational signer, Core process, funds, broadcast or upstream edit occurs.

Source pins remain WSP `ac55f13423620252bdbf848c7e8a280c3b84721e` and privacy
`db3d2dcaa540f1129d540101813b761167d33174`. Ownership, inclusion, Core
compatibility and all operational acceptance remain unqualified.
