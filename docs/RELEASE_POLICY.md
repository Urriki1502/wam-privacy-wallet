# Release and security qualification policy

**Current release status: NOT PRODUCTION READY.** This repository's MIT license permits open-source use and redistribution of rights-owned content but does not represent a security warranty, maintainer endorsement or authorization to transact real funds.

## Types of deliverables

- **Research / scaffold:** synthetic code, GUI shell, API contracts, offline tests and test evidence. May be made public; no real-funds permission implied.
- **Developer preview:** only after documented installation and testnet boundaries; no warranty or security support guarantee.
- **Production candidate:** only after all gates below, explicit maintainer approval and external review; never inferred from CI alone.

## Mandatory gates before production claims

1. Frozen provenance: exact source commits, dependency hashes, software bill of materials and license compliance.
2. Functionality: wallet creation/import, address discovery, local scan, transaction-building, signer approval, broadcast and recovery verified end-to-end.
3. Security: scan/spend separation; authenticated consent; bounded RPC; strong key handling; anti-replay, anti-rollback, crash consistency and exclusive Windows-safe database lease.
4. Privacy: real first-hop/seed peer threat model, network path measurement, no hidden hosted scanning, negative disclosure tests, PayJoin policy validation.
5. Compatibility: target Windows/macOS platforms and native dependencies exercised on real runners/environments, including restart and fault injection.
6. Chain integration: approved WAM network profile and validated local WAM Core; no consensus or supply-rule modification.
7. Assurance: independent code review, external security audit, reproducible build/evidence, testnet operational history, reviewed release signing.
8. Operator readiness: clear security notice, backup/recovery instructions, incident-response contact and rollback/update procedure.

## Branch and release controls

All code changes use PR review and final-HEAD CI. Document current failures instead of weakening a security gate. Do not automatically merge Draft PRs, change frozen upstream baselines, publish mainnet binaries, sign releases or claim approval based solely on an Actions green badge.

CORE-003 shielded consensus research is outside the wallet V1 release gates, not an invitation to change WAM Core.
