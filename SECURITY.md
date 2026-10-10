# Security policy

**Status: experimental; not production-ready.** Do not use this wallet with real WAM funds, production credentials, seed phrases, private keys or live wallets. Passing CI does not establish safety for production use.

## Reporting a vulnerability

Please **do not** disclose exploitable details, private keys, RPC credentials, wallet backups or a working exploit in a public issue, discussion or pull request.

1. Use GitHub's private vulnerability reporting feature in the repository's **Security** tab if the owner has enabled it.
2. If private reporting is unavailable, contact the repository maintainer (`@Urriki1502`) privately to arrange a secure channel **before** sharing sensitive details.
3. Include affected commit SHA, platform, reproduction conditions, impact, and a minimized synthetic test case. Do not send real wallet material.

There is no guaranteed response-time SLA or security bounty program.

## Scope and assumptions

- All real-funds use, mainnet transactions and release signing are **out of scope** until a separate security review, maintainer acceptance and documented release process.
- WSP-1 imports, network profiles, signer/PSBT, scanner state, storage, wallet RPC, backups and disclosure capabilities require explicit threat-model review.
- A user-owned, locally validated full node is the intended trust boundary. A local node does **not** eliminate network metadata leakage: WAM-operated seeds, reachable peers and first-hop observers can see connection information.
- Any scanner single-writer lease must be a real cross-platform lock, not a no-op fallback on Windows.
- Do not load untrusted PR code with repository write tokens or secrets. External contributors must not receive production credentials through CI.

## Supported versions

No production or security-supported release exists. Development branches, prototype GUI, test harnesses and research adapters are not security-supported products.

## Coordinated handling

We welcome responsible reports, confirm the affected code and reproduce with synthetic/offline tests, develop a narrowly scoped fix on a reviewable PR, rerun security gates, and disclose details after mitigation and agreement with the reporter. Do not promise that external vulnerabilities are fixed merely because a test is green.
