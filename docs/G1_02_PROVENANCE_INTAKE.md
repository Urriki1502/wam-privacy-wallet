# G1-02 — Untrusted WAM Core provenance candidate intake

**REVIEW ONLY; not release authorization.** The only input is a Python
dictionary of descriptive metadata. `intake_core_artifact(payload)` creates a
frozen, non-authorizing record with every trust/execute/release flag false.
It performs **zero filesystem, network, subprocess, registry or WSP calls**.

Only the exact pinned Core repository and inspected source commit from
`compat/wam_core_source_pin.json` are accepted. Candidate source-to-binary
equivalence, independent publisher signing, and authentic release attribution
are deliberately **NOT proven** by a source SHA, checksum or version string.
An adversary can enter a fake-but-formatted checksum. The validator does
not and cannot promote proof status. If a new source commit is to be reviewed,
that requires a separate pinned-source review, not silent fallback.

The platform and claimed tag fields are descriptive, not packaging tests.
No publisher proof is checked online, and no official binary is used here.
[REGTEST-E2E-001 #9](https://github.com/Urriki1502/wam-privacy-wallet/issues/9)
stays BLOCKED.

Run: `PYTHONPATH=src python -m unittest discover -s tests -p test_provenance_intake.py -v`
This adds 10 deterministic tests as the 14th mandatory suite atop the current
13-suite CI (expected **116 collected cases per architecture**); preserve
Windows x86/x64, macOS/Linux x64, GUI, GET-only Core source and CodeQL.

G1-03 is a separately reviewed stacked Draft PR based on G1-01. G1-04
and G1-05 require operator-supplied independently authenticated Core provenance
and real two-node regtest evidence before any runtime work.
