# Input-backed PayJoin proposal review

Application Layer → Wallet Privacy & PayJoin in the approved V1 diagram.
`review_synthetic_payjoin_proposal` runs the existing byte-pinned wam-privacy
Phase 4 validator at `db3d2dcaa540f1129d540101813b761167d33174` on bounded,
strictly shaped normalized **synthetic** transactions with explicit local
computation consent. No validator is forked or recopied.

The fixed context permits no output substitution, sender fee contribution or
receiver batching. Existing upstream input preservation, metadata, protected
change, absolute fee and value-flow rules run directly. Canonical lowercase
synthetic txids, exact ints/bools, tuple bounds (128 inputs / 256 outputs),
strict field allowlists and destination bounds guard the application seam.
Credential/PSBT/seed fields and injected result claims are rejected.

The immutable scalar-only receipt never contains transactions, destinations,
amounts, outpoints or caller annotations. `psbt_verified`, `ownership_verified`,
`sign_allowed` and `broadcast_allowed` are always false. Normalized caller
ownership/UTXO annotations are not authenticated. There is no PSBT parser,
network transport, signer invocation or operational PayJoin support in this
slice. The existing fixed fixture demo remains a research demo.

16 application adversarial tests and **16 actual unchanged upstream tests**
run with exact source/test/init Git blob checks on the four native architectures.
The existing native privacy test runner is shared. Mandatory suites 75; full
GUI discovery floor 971; no earlier floor or negative test is removed.

Opening PSBTv2/signer research by owner request does not grant sign/broadcast
permission. The existing WSP pin already contains PSBTv2 decode and a signer
in the same upstream `psbt.py`; it must be reviewed at that pin before a new
read-only parser boundary. Do not import `offline_signer` into scanner paths,
upgrade source pins implicitly, or pass arbitrary callback/provider objects.
CORE-003 excluded and all #9/#82/#86/#153, #148/#151 and WSP review blockers
remain unchanged. No upstream modification or production-ready claim.

## Main integration base

Network review PR #155 merged at
`743a450a2ed4e50c4151057611e49fb233ab4bb0`. This slice is now based
on that main commit; exact-head native/GUI/CodeQL qualification is required
after retargeting. Earlier stacked-branch checks do not qualify the main PR.

## Primitive map boundary follow-up

A shared `synthetic_input_shape` guard requires exact dict, bounded field count
and exact str keys before key-set comparison. This rejects in-process
str-subclass equality callbacks and oversized maps before source verification.
Two additive adversarial regressions raise network/PayJoin floors to 15/17
and full GUI floor to 978; upstream source bytes remain unchanged. This does
not provide hostile-code isolation or any operational authorization.
