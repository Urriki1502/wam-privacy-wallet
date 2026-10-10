# Threat model — WAM Privacy Wallet (draft)

**Status:** review document for experimental software. Controls in this document are **requirements and assumptions**, not proof of completed implementation. No mainnet anonymity, signing integrity or production-security guarantee is claimed.

## Scope and protected assets

- User scanning secrets, spending keys, recovery material, wallet state and transaction history.
- WSP-1 identifiers/scan results, address linkage, PSBT details and signer approvals.
- WAM Core network/chain identity, RPC authentication and trusted node responses.
- Consent receipts, disclosure scope, replay/revocation state, audit evidence and wallet databases.
- Software provenance, signed release artifacts, CI credentials and maintainer accounts.
- Sensitive connection metadata (IP, peer association, timestamps, transaction broadcast timing).

## Trust boundaries

1. **GUI/consent to wallet policy:** a remote request or untrusted widget must never mint approval for spending or disclosure.
2. **Wallet to signer:** policy ALLOW alone is never signing authority; approvals, PSBTs, destinations, amounts and fees must be independently verified.
3. **Wallet to WSP scanner:** local scan and spend secrets must remain separated; scanner results cannot be treated as authenticated signer intent.
4. **Wallet to local WAM node:** require an authenticated loopback, independently verified chain/network profile, bounded responses and fail-closed error handling.
5. **Local node to P2P:** a user's full node still reveals some connection metadata to peers and bootstrap infrastructure; local validation does not remove first-hop visibility.
6. **Workspace to dependencies/CI:** pull requests, fetched artifacts and upstream code cannot access production secrets or bypass frozen-source provenance controls.

## Adversaries

| Adversary | Potential observation or action | Required controls / current gap |
| --- | --- | --- |
| Passive chain observer | Correlate visible outputs, times and transaction patterns | Wallet/coin-selection design review; no complete privacy guarantee |
| First-hop P2P peer / WAM-operated seed node | Observe IP, connection timing and potentially correlated relays | Explicitly model **WAM Core-operated seed infrastructure**; measure actual peer/broadcast behavior, avoid implying a seed always observes every tx |
| Global or regional network observer | Correlate traffic, timing and peers | Private-route policy and network tests; real transport integration unqualified |
| Compromised or faulty local Core node | Misreport RPC data, chain profile or state | Authenticated loopback, profile/source pin, independent validation and typed RPC bounds; no production qualification |
| Compromised scanner, wallet UI or storage | Link payments, tamper approvals or roll back state | Separation of scan/spend authority, nonrollback state, trusted UI and crash consistency remain release blockers |
| Malicious PayJoin partner | Input/output manipulation, fee change, metadata probing | Strict transaction validation, approval binding and adversarial integration tests are required |
| Malicious dependency, CI contributor or release actor | Supply-chain compromise, credential theft, counterfeit binaries | Immutable pins, minimal CI permissions, lockfiles, provenance and reviewed release signing |
| Implementation bug or concurrent process | Double-use, replay, incorrect lock semantics, partial write | Windows-safe real file lease, fault injection, durable journal and independently reproducible tests |

## Critical nonclaims and open security gates

- **WAM-controlled seeds are in scope** as potentially observable first-hop infrastructure. Validate actual topologies, not only conceptual observer fixtures.
- **No hosted-scanner fallback** may silently substitute for the user's own full node.
- Cross-platform scanner locking must provide **real** exclusion on Windows (`msvcrt.locking`, `LockFileEx` or a reviewed cross-platform library); a no-op is unsafe.
- Crash-consistent signer/replay journals, storage rollback resistance, key custody, trusted UI consent and reliable recovery are not production-qualified.
- WSP-1 runtime integration and network-profile acceptance remain review-gated; [PR #3](https://github.com/Urriki1502/wam-privacy-wallet/pull/3) is not merged.
- CORE-003 shielded consensus research is out of V1 scope and is **not authorized** by this wallet.
- Offline fixtures, synthetic regtest identities and passing tests are insufficient evidence for real-wallet security.

Update this threat model as components gain implementation and evidence. Each new feature PR must identify which threats it mitigates and which are still unaddressed.
