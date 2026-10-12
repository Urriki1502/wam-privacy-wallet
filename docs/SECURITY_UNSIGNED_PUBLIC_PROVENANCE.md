# Actual WAM Security pure provenance helper, no assurance upgrade

`review_public_assurance_fixture(scope, consent)` executes original pure APIs
from `wam-security` at `c9b1ce872c2b0b65276883d4e210b6a2f7c96467` in a fixed,
fresh isolated Python worker. It verifies the four raw package/helper blobs
before imports and rejects cached bytecode. The optional `assurance` dependency
uses that exact Git commit. No upstream code is copied, patched or forked.

Only a constant public artifact is created in a disposable private directory.
No caller artifact path, manifest, statement, key, identity, executable or real
wallet data is accepted. The original `create_provenance`, `verify_subjects` and
`provenance_digest` generate and validate their own synthetic statement. Caller
names never reach `verify_subjects` file lookup. The worker denies network and
process audit events as instrumentation; it is not an OS/hostile-code sandbox.

The statement records the three fixed research module pins. Its wallet source
commit is deliberately the all-zero **synthetic fixture** value; its builder and
build type explicitly say unqualified public preview. This is not a wallet
build attestation, a signed publisher identity, SLSA level, SPDX certification,
Core binary verification or an independent audit. Neither the existing security
Core pin nor its native wallet/signing harness is adopted or executed.

Only digest, bounded counts and fixed untrusted evidence cross into the app.
Fresh child imports keep mutable helper objects out of Qt. Consent/scope denial
precedes child execution. Malformed output, private errors, timeouts, extra
fields and any true publisher/runtime/release/sign/broadcast flag are denied.
All five authority flags remain false even after success.

Public deterministic digest vector:
`0700a9000944f1188eebafb4448823f11c6df8723feb6f0cedd6ff1243eb7424`.

Native CI checks five raw Git blobs (helper closure plus original tests), runs
three unchanged upstream provenance tests and eight actual native/application
cases on Linux, macOS, Windows x64 and Windows x86. Twelve unit cases provide
only protocol/negative evidence. Local native 11/11 and full discovery pass;
other architectures are recorded only after their exact-head CI completes.
The existing mandatory gates and floors are preserved and increased additively.

No Core process, real keys/funds, signer, broadcast or mainnet. CORE-003 remains
excluded. Wallet #9/#82/#86/#153, trusted anti-rollback #148/#151, WSP upstream
review and privacy external review are unchanged. An unsigned digest cannot
satisfy any of these holds or authorize a release.

## Repository CodeQL language gates

GitHub default setup now includes actions, Python and Rust. Final qualification
must inspect every observed CodeQL language result on the exact PR head, including
Rust when present, rather than inferring success from an earlier Python-only
configuration. This is static analysis, not external review or runtime approval.
