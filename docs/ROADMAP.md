# Public roadmap — WAM Privacy Wallet

**The project is experimental.** These are engineering milestones, not shipping dates or promises of production safety.

## Verified repository history at open-source launch

- **Merged:** Phase 001 GUI shell; Phase 002 local endpoint contract; Phases 004–009 regtest identity, bounded read-only RPC, gateway, verified Core regtest harness, Core profile gate and source drift pin.
- **Open Draft:** [Phase 003 / WSP-1 provenance and public API gate](https://github.com/Urriki1502/wam-privacy-wallet/pull/3). Do not merge or claim integration completion without a separate review.
- **Not delivered:** real-funds wallet, signer security review, production WSP-1 integration, external audit, signed releases or approved mainnet profile.

## Workstreams

### A. Open-source foundation — documentation and governance
MIT licensing and provenance verification; contributor/security/release policies; reproducible CI; protected `main`; private vulnerability reporting; dependency review. Public repository visibility is **not** an acceptance gate for production.

### B. WSP-1 / wallet core
Review fixed WSP-1 commit pins, scanner/signer separation and network profiles. Implement local scanner integration, PSBT authorization boundaries, wallet discovery, crash-safe state and recovery; validate Windows file locking, restart and reorg paths. Keep Phase 003 isolated until qualification.

### C. Privacy above consensus
Scoped wallet policy, approved PayJoin behavior, local selective disclosure, authenticated consent and network route privacy. Explicitly model the user node's first-hop exposure to WAM-operated seed peers. Do not introduce a hosted scanner as a default dependency.

### D. Security and assurance
Signer replay/rollback protection; durable wallet journal; bounded RPC failure behavior; concurrency and negative/adversarial testing; independent clean-clone qualifications; external security review and observable testnet operations. Preserve independent research freeze SHA evidence.

### E. Release engineering
Platform packaging for supported Windows architectures and macOS, secure update and release signing, reproducible builds, SBOM/license inventory, testnet use and operator documentation. Enable real-funds use only after all [release gates](RELEASE_POLICY.md) pass.

## Explicit exclusions

No WAM Core consensus changes, shielded/Halo2 activation or inflation-unverifiable supply scheme. CORE-003 remains published research, not the implementation roadmap. No mining or coin-price promises.

## How to contribute

See [CONTRIBUTING](../CONTRIBUTING.md). Propose the smallest independently testable change. Clearly state current coverage, unmet dependencies, security boundaries and limitations. Avoid auto-merging frozen or Draft PRs.
