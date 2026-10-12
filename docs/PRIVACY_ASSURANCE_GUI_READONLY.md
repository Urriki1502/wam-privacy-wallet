# Coin policy, viewing and unsigned provenance in one read-only GUI

The diagram's Wallet Privacy & PayJoin, Selective Disclosure and Independent
Assurance paths now reach the existing single-writer application presentation
controller. The Privacy page has scrollable, wrapped status cards; startup
neither executes a review nor imports an upstream engine. There are no new
payment, file-import, disclosure/export, signing or send actions.

Explicit application methods require fresh consent and synthetic-regtest scope.
Coin policy runs the unchanged pinned normalized-input model. Viewing runs only
public HPKE fixtures. Provenance runs only a constant artifact in a fresh worker.
Accepted DTOs display fixed source fingerprints, bounded counts/role and untrusted
wording. No coin/recipient identifiers, amounts, seeds, keys, note contents,
transaction bytes, source paths, native handles or full statements are retained.

All three receipt validators reject foreign classes, nonprimitive fields,
contradictory counts/warnings, forged pins/evidence and true authority flags.
Provenance additionally requires the actual deterministic public fixture digest,
not just an arbitrary well-shaped hash. These checks cannot attest DTO origins.
Unit DTO tests remain schema/display evidence; actual native tests exercise
workers and Qt together with exact source pins.

Consent denial, scope rejection, a new replacement without prior evidence,
stale revisions and renderer failures clear the entire managed view. The offline
integration summary now includes scanner/unsigned PSBT/new review indicators and
rejects any of those indicators in an initial, cleared or rejected state. Its
status is always REVIEW_ONLY_UNTRUSTED, with all six authority grants false.

Validation: 98 GUI cases, 18 lifecycle cases, 34 integration-summary cases and
1266 full-discovery cases locally. Floors remain additive: 80 mandatory suites,
full floor 1081, twelve new mandatory GUI identities. Actual source-to-Qt tests
include HPKE native 10 cases and security native 13 cases on x64 Linux/Windows/
macOS. Native Windows x86 HPKE (8 cases) and security (11 cases) remain in their
existing native matrices; there is no Windows x86 Qt qualification claim.
PSBT Windows x86 stays explicitly unqualified and denied before child execution.

Upstream pins: privacy db3d2dcaa540f1129d540101813b761167d33174,
security c9b1ce872c2b0b65276883d4e210b6a2f7c96467,
WSP ac55f13423620252bdbf848c7e8a280c3b84721e. WSP/external crypto reviews,
wallet #9/#82/#86/#153 and trusted anti-rollback #148/#151 remain holds.
No Core execution/change, CORE-003 work, real funds/keys, signer or broadcast.
