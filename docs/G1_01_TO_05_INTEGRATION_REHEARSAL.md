# G1-01 → G1-05 combined offline integration rehearsal — DO NOT MERGE

**Scope:** five independently reviewed *candidate* offline G1 feature/test/document branches
at exact source commit SHAs listed below. This rehearsal is a **Draft PR**,
not an authorized promotion to main, not a mainnet build or release.

| Stage | Source PR | Head SHA | Expected new tests |
| --- | --- | --- | --- |
| G1-01 | #27 | `2f5950ed47b739b9636a79e69b2f74b19a4808f4` | `test_two_node_topology.py` 10 |
| G1-02 | #28 | `baf79d0d5e0c503515751523530ba57e4e95f187` | `test_provenance_intake.py` 10 |
| G1-03 | #29 | `695abaf4e3d4abdb51734b811e4ebaf39617cf28` | `test_two_node_policy.py` 10 |
| G1-04 | #31 | `51cdd4b671b3d0ff3312f1e28584e8f9b3c0a8bb` | `test_rpc_qualification_prep.py` 10 |
| G1-05 | #32 | `f2b24275686c60bfa783625d6b891017f7151583` | `test_reorg_qualification_prep.py` 10 |

- All G1 source, standalone docs and test blobs are inserted **verbatim by Git blob SHA**.
- G1-03 depends on G1-01; their shared inherited three original G1-01 blobs
  were independently checked for exact SHA equality before composing the tree.
- The only harmonized files are `tools/ci_contract_gate.py` and
  `tests/test_ci_contract_gate.py`: five additional suites and corresponding
  self-test registry assertions; no CI matrix/GUI workflows removed.
- Expected run is **18/18 mandatory offline suites, 156 cases per OS architecture**
  (106 existing + 50 new), 8 Wallet jobs, 2 CodeQL jobs. These totals are
  planned acceptance metrics, **not success claims until exact-head logs PASS**.
- No WAM Core binary is fetched, imported or launched; no credentials, real
  wallet keys, scanner runtime, signer, broadcast, mainnet or source changes.
- G1-04/G1-05 are **offline case inventories**, NOT real node/reorg evidence.
- #3, #16, #25, upstream WSP lock #9 and Core repo remain untouched.

**Do not merge even if green.** Independent review must first close the
security concerns and confirm release blocker statuses remain truthful.
Future individual PR merges require a fresh CI run against the updated
base and verified case-count registry, not reliance on this rehearsal.
