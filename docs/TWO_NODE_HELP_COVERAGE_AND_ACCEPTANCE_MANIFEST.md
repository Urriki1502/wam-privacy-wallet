# Two-node help coverage and Core acceptance evidence

`inspect_two_node_help_coverage` reuses the existing G1 plan/policy, versioned
schema and deterministic serializer. Every proposed option name must appear in
bounded captured daemon help. Missing names, duplicate help entries, malformed
plans, non-loopback bindings and forged operational flags deny. The receipt
binds both unchanged configs with a length-prefixed pair digest and the help
capture digest. It never invents, drops or silently substitutes Core options.

This is option-name coverage only. It cannot establish value semantics,
network scoping, source/build provenance, same-image capture or actual
configuration acceptance. Tests use explicitly labeled help fixtures. There
is no approved v0.1.11 help capture or generated signed wam.conf parity; #153
stays OPEN until DEV provides exact-build evidence and qualified release bytes.
Existing ephemeral datadir/cookie/port isolation and cleanup are reused, not
reimplemented. No RPC credential values are added to the coverage receipt.

The authentic signed-release readiness CLI now emits evidence schema 1:

| Evidence | Classification |
| --- | --- |
| Authenticated signed archive/member | PASS after actual verification |
| v0.1.11 GNU_STACK RWE policy | FAIL; execution remains blocked |
| Immutable executed process identity | BLOCKED |
| Same-build help/config parity | BLOCKED |
| Independent monotonic checkpoint anchor | BLOCKED |
| Actual Core startup/shutdown/cleanup, read-only RPC, payment observation, reorg, restart, checkpoint restore, rescan | NOT RUN |

A clean static ELF could only change the static ELF gate to PASS; it must not
change any real Core scenario. Errors before signed-byte qualification emit no
manifest. The real official-release workflow preserves only the public redacted
JSON manifest as a GitHub artifact, named with exact wallet SHA, for 14 days.
Signature/member/static evidence is distinct from runtime acceptance.
No Core process, production credentials, signer or broadcast is enabled.
#82/#86/#9/#148/#151 remain separately blocked/open as appropriate.

Sprint checkpoint: source base is #187 merged main
`182c0927ab9aec957e63b6365e634a42a3bc3128`. Unit C adds seven coverage
tests and two manifest-status tests, preserving all 83 mandatory suites.
Focused 28 help + 7 readiness + 18 schema + 13 workspace tests PASS locally.
All unrelated local full-suite /proc limitations remain recorded in the main
sprint checkpoint; exact-head GitHub native and official release CI pending.
The existing help/example CLI accepts optional `--two-node-ports RPC_A P2P_A
RPC_B P2P_B` and rejects capture changes before emitting coverage.
