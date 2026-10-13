# WAM Privacy Wallet V1 — approved diagram to implementation map

**Status: architecture control baseline, NOT an operational wallet.** The user-approved diagram is the functional V1 scope. The machine-readable [traceability manifest](ARCHITECTURE_V1_TRACEABILITY.json) records **14 nodes, 19 directed interfaces** and mandatory HOLD conditions. `tools/architecture_v1_gate.py` checks the fixed statuses in CI; it **cannot** grant Core launch, wallet signing, broadcast or mainnet authority.

## Reading the diagram correctly

**Existing implementation and independent qualifications do not equal integration into `wam-privacy-wallet`.** Source from `wam-silent-payments` and `wam-silent-wallet` is separately maintained; `wam-privacy` implements research models; `wam-security` independently verifies security. Their README claims must be requalified at pinned revisions and scoped interfaces before use in this application. Do not copy entire modules, modify upstream repositories, or downgrade controls for green CI.

| Diagram box | Current evidence boundary | Proposed integration exit criteria |
| --- | --- | --- |
| User / UI | PySide6 navigable offline shell on `main` | Reviewed session + consent state; no misleading live-account display |
| Application Layer | Offline lifecycle, presentation DTOs, policy readiness | Strict scanner/signer/RPC adapters with bounded cancellation, no injected wallet authority |
| WSP-1 / Silent Payments | Pinned `wam-silent-payments` API candidate; app [PR #3](https://github.com/Urriki1502/wam-privacy-wallet/pull/3) Draft | Signed/pinned source & license check, public API and network profile review, independent tests |
| Local Scanner | External `wam_sp.scanner`; no production app scanner | Separate scan-only capability, real OS single-writer lock (including Windows), restart/reorg/rescan and local node test |
| PSBTv2 / Signer | External offline signer only | Independent approval tied to inputs, destination, amounts, fee; explicit operator consent; no auto-sign |
| Backup / Recovery | External authenticated recovery, app synthetic previews | Authenticated restore into a new DB, rollback/replay and crash consistency; sensitive-state redaction |
| Wallet Privacy & PayJoin | Pinned privacy validator + exact PSBTv2 read-only WSP review; ownership/Core unqualified | Fee/output invariants on real regtest constructs; no silent direct fallback |
| Selective Disclosure | Selected WSP history local export + private Qt APIs; no reusable authorization/proof | Trusted selection/save UX, scoped consent qualification; reusable authorization/proof only under a separate protocol |
| Network Privacy Policy | Pinned policy + strict application fallback/endpoint review; no actual private transport | Measured first-hop P2P and hardened actual route enforcement; failure never falls back to public direct broadcast |
| WAM SDK / RPC | Fixed local loopback read-only RPC, topology and P2P observer | WAM-profile-reviewed bounded scanner read interface; all required methods explicit, no write/broadcast in read-only adapter |
| User-owned WAM Core Full Node | Official signed v0.1.11 verified **without execution**, GNU_STACK RWE blocker | DEV-approved binary, immutable executed-image/process+loader binding, isolated genuine two-node regtest (#9) |
| WAM Security assurance | External `wam-security` frozen evidence baseline | Immutable reviewed SHA for every reused invariant/test, independent review and reproducible evidence |
| CI / release verification | 8/8 native Wallet CI and official read-only archive checks | Additional feature gates, secure packaging, SBOM/reproducibility, independent release approval; **no mainnet** |

## Three parallel streams; gated independently

**A — Core/security:** continue #36 executable-to-process identity, dynamic linker and DSO attestation; hold #84/#86 until DEV resolves official executable-stack policy. #9 genuine two-node E2E is blocked until approved. Never touch WAM Core consensus/upstream source.

**B — Wallet engine:** static-review and qualify the existing `wam_sp.api.SilentWallet`, `Scanner`, offline PSBT signer and recovery as separate boundaries. Adopt reviewed version and source SHA only. Start with scan-only, **no spend secrets**, then controlled signer in separately approved phase. A successful API stub/mock never qualifies funds operation.

**C — Privacy application:** review `wam-privacy` PayJoin, privacy route and selective disclosure research against the application's UI and policy semantics. Hook only non-authorizing status views first; allow operational adapters only when a dedicated security review and real regtest evidence exist.

## Critical gates — none may be inferred away

- [#36](https://github.com/Urriki1502/wam-privacy-wallet/issues/36): actual signed WAM Core image-to-executed-process and loader/DSO proof **OPEN** (synthetic Linux tests already passed).
- [#84](https://github.com/Urriki1502/wam-privacy-wallet/pull/84): strict official ELF acceptance **DRAFT/HOLD**.
- [#86](https://github.com/Urriki1502/wam-privacy-wallet/issues/86): official v0.1.11 `GNU_STACK RWE` upstream DEV review **OPEN**.
- [#9](https://github.com/Urriki1502/wam-privacy-wallet/issues/9): genuine two-node WAM Core regtest **BLOCKED**.
- [#3](https://github.com/Urriki1502/wam-privacy-wallet/pull/3): app WSP-1 review **DRAFT**, must not merge automatically.

**Release definition:** a working desktop wallet is **not** established by Qt navigation, mocked scanner, valid ELF static report, external upstream capability, synthetic kernel process tests or green CI. V1 acceptance requires actual integrated behavior and explicit review of each trust boundary. Real keys, transactions and mainnet remain out of scope for current baseline.

## Privacy integration evidence categories

The three privacy boxes now map to their application review boundaries in the
machine-checked manifest. This is review integration, not operational acceptance.
All 14 nodes, 19 edges, WSP/Core/ELF HOLDs and false authority flags are retained.
The legacy `privacy_readiness.py` DTO continues to describe conservative
operational readiness; it does not activate the new review APIs.

| Component | IMPLEMENTED | TESTED | INTEGRATED | ACCEPTED | BLOCKED |
| --- | --- | --- | --- | --- | --- |
| PayJoin | Pinned PSBTv2 parser + unchanged validator + canonical receiver public verification | Native synthetic transaction cases and adversarial application boundary | Fixed read-only application worker | Operational: NO | Authenticated sender ownership, chain/UTXO inclusion, WSP/Core compatibility and consent qualification |
| Network policy | Unchanged source policy + strict no-fallback/canonical endpoint profile | Source and application negative tests; Qt regression | Existing application/Qt policy review | Operational: NO | Actual Tor/I2P/OHTTP runtime route and first-hop evidence |
| Local selected disclosure | Scope/field allowlist, exact-byte one-use approval, cancellation/expiry | Real WSP SQLite/Qt with synthetic chain; adversarial policy | Existing private-history Qt preview/export APIs | Operational: NO | Trusted selection/save UX, persistent consent qualification; no proof protocol implemented |

Exact source SHAs, PR/CI evidence and next tasks:
[Privacy Integration Sprint](PRIVACY_INTEGRATION_2026_10_13.md).
CORE-003 research stays excluded and upstream sources are untouched.
