# Actual scanner-only x64 qualification, public synthetic peer

The existing complete Linux scanner/backup/checkpoint/recovery workflow remains
unchanged and required. Its Linux-specific filesystem gates are not relaxed.
A separate native scanner-only proof reuses the existing public RPC fixture
handler and unchanged pinned WSP Scanner/Store APIs on Linux, macOS and Windows
x64. It never calls the guarded backup/checkpoint APIs on a new platform.

Each process verifies the whole source closure before imports, actual pointer
width, installed source location and exact dependency versions. Eight fixed
proof identities cover refusal before RPC without consent, real Scanner.sync
and SQLite writes, public BIP352 receive matching, replay without duplication,
real scanner-to-Qt receipts, mutation RPC denial before the wire, SQLite reopen
requiring reattestation and synthetic reorg undo. No mock scanner or store is
accepted as this evidence. All app authority flags remain false.

The fixture uses known public integer scalars, not real keys or funds. The
upstream `core.send` function derives a BIP352 output for the test; it neither
signs a transaction nor broadcasts. The scanner legitimately calls
`core.prepare` to aggregate public inputs. Instrumentation permits that exact
API while still denying signer.prepare, sign/finalize/broadcast and signer or
wallet/keyring construction. Instrumentation is not an OS/hostile-code sandbox.

Actual Windows x86 Python must deny before source qualification, WSP/Qt import
or execution because the pinned dependency build remains unqualified. Its green
denial job is not native scanner or Qt success. No pin downgrade, mocked
success, new production permission or backup/recovery platform qualification.

Local macOS arm64 executes all eight actual proof identities successfully.
Native CI must separately confirm macOS x64, Windows x64 and Linux x64 on each
exact PR head. WSP pin remains ac55f13423620252bdbf848c7e8a280c3b84721e;
upstream review, wallet #9/#82/#86/#153 and trusted anti-rollback #148/#151 stay
held. CORE-003 is excluded; no WAM Core, signer, mainnet or transaction broadcast.
