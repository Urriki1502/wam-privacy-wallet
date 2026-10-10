# G0–G1 combined test rehearsal — DRAFT / DO NOT MERGE

This rehearsal combines the exact source objects from the independent
review Draft PRs #20–#24, against `main` `356a27c87fc3c7aad9ea0058f332ce1ec0c6a133`.

Exact source PR HEAD commits:
- #20 `68198ef30ef1a635b29b3119ac6e78d042876c33`
- #21 `a6f226ade0cccd782f25594df3c5756732409e78`
- #22 `e8ee558403b24828c44eca58def29417057ac0f3`
- #23 `ec1161ca6d28b9fb81a6b12b5f46a03097e87daa`
- #24 `3c34ae98592412d14417a714e4868bdc9052d0d5`

All 8 original offline test suites plus the **four** new suites
(`test_reuse_manifest.py`, `test_app_diagnostic_boundary.py`,
`test_security_gate_ledger.py`, `test_regtest_artifact_preflight.py`)
run on four Python architecture legs. CI now also fails if a required
suite file is missing (unittest discover alone can exit successfully when
nothing matches). Existing three-platform GUI, pinned Core GET-only,
and external CodeQL workflows remain unchanged.

No WAM Core changes, no real node, keys, wallet state, scanner or signer
integration. Phase 010 PR #16 and WSP PR #3 are intentionally excluded;
their test registration and independent review must be preserved if later
integrated. Individual PRs must still be reviewed and requalified before
merging. Do not merge this rehearsal, even if all CI checks pass.
