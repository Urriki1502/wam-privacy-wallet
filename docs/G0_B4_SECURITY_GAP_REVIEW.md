# G0-B4 — Security gap and integration review

**Research-only threat ledger, not an audit certificate or production authorization.**
The [security blocker ledger](../compat/g0_security_gate_ledger.json)
is a machine-readable inventory of current review requirements. Its
[offline schema check](../tools/check_security_gate_ledger.py) ensures that
the documented high-risk blockers cannot accidentally be labelled PASS
or that mainnet/operational/release permissions are not enabled. It **does not**
assert that a blocked condition has actually been fixed or independently
verify external artifacts. Status must be revised in a separate reviewed
PR with evidence and a changed ledger policy once the release process is
qualified; bypassing this check is not acceptance.

## Findings and traceable requirements

| Risk | Trust boundary / failure mode | Evidence | Next proof |
| --- | --- | --- | --- |
| P0 CORE-REAL-E2E | Local RPC responses are only synthetic/point-in-time; compromised node or wrong binary may impersonate | [Issue #9](https://github.com/Urriki1502/wam-privacy-wallet/issues/9); \`node/real_regtest.py\` | Independently sourced SHA-256-verified Core executable, isolated two-node WAM regtest, restart and reorg |
| P0 WSP-DEPENDENCY-REVIEW | Scanner lock on Windows / upstream engine import is review-gated | [Wallet PR #3](https://github.com/Urriki1502/wam-privacy-wallet/pull/3); [WSP PR #9](https://github.com/Urriki1502/wam-silent-payments/pull/9) | Native exclusive-lock concurrency/crash cases and upstream independent review |
| P0 SCANNER-RPC-BRIDGE | WSP scanner expects \`attest\`, \`getblock(hash,3)\`, mempool RPC; Wallet diagnostic transport has a narrower allowlist | [Issue #15](https://github.com/Urriki1502/wam-privacy-wallet/issues/15); [Draft #16](https://github.com/Urriki1502/wam-privacy-wallet/pull/16) | Fresh attestation, typed bounded response, wrong chain/cookie/host rejection and reorg/race tests |
| P0 SCAN-SPEND-SEPARATION | Legacy NodeService constructs broadcast-capable SDKChain; scanner must never inherit mutation authority | \`docs/THREAT_MODEL.md\`, [G0-B3 draft #22](https://github.com/Urriki1502/wam-privacy-wallet/pull/22) | Independent scanner-only capability facade with denial of \`sendrawtransaction\` |
| P0 WALLET-STATE-RECOVERY | New Wallet lacks durable application state, rollback-safe journal and recovery proof | \`docs/RELEASE_POLICY.md\` | Crash/fault injection, one-writer, reorg and restore-then-rescan |
| P0 SIGNER-APPROVAL | No trusted UI-to-signer transaction approval binding in new Wallet | \`docs/RELEASE_POLICY.md\` | PSBT input/output/fee policy and anti-replay assertions, independent review |
| P1 WIN32-RELEASE-QUALIFICATION | Python x86 contract PASS is not x86 Qt/crypto/native packaging | [Issue #5](https://github.com/Urriki1502/wam-privacy-wallet/issues/5) | Native Windows x86 GUI/crypto wheels and installation/runtime/regtest proof |
| P1 PR-BRANCH-GOVERNANCE | Active observed ruleset had only deletion and non-fast-forward constraints; classic protection not verified | \`docs/OPEN_SOURCE_CHECKLIST.md\` | Verify actual required PR and CI review rules; do not rely on voluntary Draft practice |
| P1 DEPENDENCY-RELEASE-SUPPLYCHAIN | Public history, transitive licensing, binary attestations and SBOM unfinished | \`docs/OPEN_SOURCE_CHECKLIST.md\` | Full-history secret audit, dependency provenance and independent release review |
| P1 PRIVACY-POLICY-REVIEW | First-hop seed peer metadata, PayJoin and selective disclosure unqualified | \`docs/THREAT_MODEL.md\` | Measurable network/privacy/adversarial tests with fail-closed policy |

## Dependency-ordered sequence

- **G1**: verified Core regtest + trusted read-only RPC before scanner.
- **G2**: reviewed Windows lock + WSP scanner contract; wallet state/reorg/restore.
- **G3**: transaction construction, PSBT and signer approval/replay.
- **G4**: wallet privacy, network paths, PayJoin, disclosure.
- **G5**: independent review, release signing, reproducible packaging and operator readiness.

No G2 operational scanner or G3 signer integration can rely on a green
synthetic G1 unit suite as a substitute for real Core evidence. If a
prerequisite cannot be observed, record **BLOCKED** rather than SKIPPED/PASS.
The Wallet is experimental; no real wallet, mainnet or funds are permitted.

## Scope and test

Run: \`python -m unittest discover -s tests -p test_security_gate_ledger.py -v\`.

The matrix adds six checks on Windows x86/x64, macOS x64 and Linux x64;
existing security and GUI checks remain. This PR does not import WSP,
contact a node, inspect user files, or alter WAM Core.
