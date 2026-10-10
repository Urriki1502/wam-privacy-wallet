# G0-B1 — Source reuse qualification (research only)

**Status:** REVIEW ONLY. This is not WSP-1 adoption, production integration,
source attestation, a security audit, or permission to use real funds.

The [immutable candidate manifest](../compat/reuse_candidates.json) pins
reviewed candidate source paths by both commit SHA and Git blob SHA. The
[offline validator](../tools/check_reuse_manifest.py) fails closed if a
candidate is unpinned, an unapproved repository is added, or anyone
accidentally flips the manifest into a supposed integration approval.
It does **not** fetch upstream files or prove upstream trust; a future
integration gate must compare actual fetched bytes and independent licenses.

## What is reusable, and what is blocked?

| Component | Source | Decision / reason |
| --- | --- | --- |
| Silent Payments API | `wam_sp/api.py` | **REVIEW_GATED**; facade keeps scan and spend roles separate |
| Local scanner | `wam_sp/scanner.py` | **REVIEW_GATED**; native locks, real node, reorg recovery |
| SQLite wallet state | `wam_sp/store.py` | **REVIEW_GATED**; crash, migration, rollback and writer lease |
| Offline signer | `wam_sp/offline_signer.py` | **BLOCKED**; user approval and PSBT input/output/fee security |
| WSP backup | `wam_sp/backup.py` | **REVIEW_GATED**; restore and rescan fault tests |
| WSP RPC | `wam_sp/rpc.py` | **BLOCKED**; scanner API is not the wallet's diagnostic read-RPC |
| UI unlock session | `wam_silent_wallet/services/session_service.py` | **REVIEW_GATED**; Python zeroization is best-effort only |
| Legacy node service | `wam_silent_wallet/services/node_service.py` | **BLOCKED**; default port 18443 conflicts with wallet's pinned WAM regtest RPC 29554 |

**Source identities reviewed:** WSP-1 Windows-lock candidate
`ac55f13423620252bdbf848c7e8a280c3b84721e` (upstream PR #9,
unmerged); Silent Wallet `44e749a5c8fde82f672d0bc9d11e43af4e52c673`.
MIT LICENSE files exist in both repositories. Separate provenance and
transitive third-party license review remain mandatory.

## Separation requirements

- WSP-1 wallet PR #3 and Windows-lock upstream PR #9 remain review-gated;
  do not merge or load their code into production.
- Local scanner must not receive spending keys or signing authority.
- Wallet State must have real cross-process exclusive writer lease and durable
  rollback on restart/reorg; never replace native locking with a no-op.
- Diagnostic `LocalReadOnlyRpc` accepts only profile/identity calls. Do not
  expand its allowlist to `getblock` or `sendrawtransaction` as a shortcut.
- Existing WAM Core profile pin: 29554 regtest RPC and genesis
  `b88f3d262f285e38e184f50bf3eea1c8e615486ae67d3d9eaf0976fbd6d3d30d`.
  A port number alone is not node or publisher attestation.
- Real two-node regtest, cookie rotation, Windows native lock and
  independent review remain **BLOCKED** until reproducible evidence exists.

## Qualification scope

`python -m unittest discover -s tests -p test_reuse_manifest.py -v`

Run it on native Windows x86/x64, macOS x64 and Linux x64 via the consolidated
offline CI matrix. The test rejects unpinned SHAs, duplicate/missing
roles, unexpected formats, untrusted repository references, path traversal and
claims of integration approval. It performs **no network I/O** and imports
**no WSP-1 modules**.

**Next separate review:** G0-B2 inspect Silent Wallet application services and
propose narrow adapter interfaces without copying unsafe defaults.
