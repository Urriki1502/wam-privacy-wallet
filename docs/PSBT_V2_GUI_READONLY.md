# Unsigned PSBTv2 review in the read-only desktop application

The diagram's PSBTv2 component now reaches Application Layer and Privacy UI
through `MainWindow.review_unsigned_psbt_fixture`. This explicit API accepts
only the parser's synthetic-regtest scope and fresh consent. It does not expose
an import, sign, export or send button. Startup does not execute the worker.

The existing single-writer presentation controller validates the exact frozen
receipt, bounded primitive counts, source pin and four false authority flags.
Only counts, fixed experimental wording and the source fingerprint are shown.
Raw PSBT bytes, scripts, outpoints, amounts, source paths and parser handles are
not retained in Qt or presentation state. A supplied DTO remains untrusted;
display/schema tests are not evidence of actual parser execution.

A denied input or withdrawn consent clears prior evidence before evaluation.
An omitted receipt, stale revision, forged authority or renderer failure cannot
leave an accepted parse in managed state. All wallet/sign/send gates stay closed.
This is not full PSBT/BIP compliance, real PayJoin validation, chain validation,
ownership proof, runtime attestation or a custody feature.

Native CI checks out WSP `ac55f13423620252bdbf848c7e8a280c3b84721e`, preserves raw
Git blob bytes and executes 21 original native parser cases plus two actual
parser-worker-to-Qt cases on Linux, Windows x64 and macOS. The 32-bit dependency
build remains unqualified and fails closed before a worker is started. Its green
denial test must not be reported as a successful native parser qualification.

Local validation: 23/23 source-pinned parser/Qt cases, 86 GUI cases and 1201 full
discovery cases passed. The mandatory lifecycle floor increased from 10 to 14;
full-discovery floor from 1006 to 1016, with six additional required GUI identities.
Original mandatory gate identities and floors were preserved.

WAM Core is neither started nor modified. CORE-003 remains out of scope. Wallet
#9/#82/#86/#153, trusted anti-rollback #148/#151 and upstream WSP review remain
external holds; this preview cannot satisfy them or authorize signing.
