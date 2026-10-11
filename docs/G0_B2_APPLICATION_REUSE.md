# G0-B2 — Safe Application Layer candidate (review only)

**No GUI wiring, wallet unlock, scanner activation, transaction signing or node connection in this PR.**

## Legacy source review
- `wam-silent-wallet@44e749a5c8fde82f672d0bc9d11e43af4e52c673`:
  - `src/wam_silent_wallet/main_window.py`: UI controls directly construct/call
    mutable node/session/wallet services; **ADAPT**, never copy wholesale.
  - `src/wam_silent_wallet/services/session_service.py`: Python passphrase
    bytearray zeroization is best-effort, not an approved signer boundary;
    **REVIEW_GATED**, no keys in GUI models.
  - `src/wam_silent_wallet/services/node_service.py`: imports WAM SDK and WSP
    adapter but starts with `http://127.0.0.1:18443` default;
    **BLOCKED as drop-in** because wallet Core source pin specifies regtest
    RPC port **29554** and user-owned, verified chain identity.
  - `src/wam_silent_wallet/services/wallet_service.py`: requires
    independent key-custody, signer and recovery review prior to reuse;
    **REVIEW_GATED**, no runtime import here.
- Existing wallet `node/` contract already has `VerifiedCoreProfile`
  and ephemeral chain-identity checks. Do not duplicate RPC/auth code.

## Proposed narrow read-only boundary

`application.node_status.node_overview(profile)` converts an existing
`VerifiedCoreProfile` **in memory** to an immutable, minimal GUI display
record. It deliberately does not expose an endpoint, credential, RPC callback,
node client, signer capability or wallet state.

- The snapshot is explicitly **diagnostic-only**: merely holding a Python
  `VerifiedCoreProfile` cannot prove the Core binary or confer authorization.
- Invalid/malformed profile objects are denied before displaying.
- A **review-only offline Node page integration** may render an externally
  supplied, exact `NodeOverview` as an UNVERIFIED point-in-time diagnostic;
  it never constructs or retains a Core profile, node connection or RPC client.
  The Overview still reports DISCONNECTED and no wallet is loaded. This is
  neither a real node lifecycle nor Core attestation: stale snapshots, real
  concurrency and trusted-source qualification remain separate release gates.
- Do not feed a stale snapshot into Scanner, Signer or a policy decision.
- No silent hosted scanner fallback or auto-approved mainnet mode.
- WSP-1 PR #3, Phase 010 PR #16, real Core E2E issue #9 and Win32 release
  gate remain independent and blocked where applicable.

## Offline tests
`python -m unittest discover -s tests -p test_app_diagnostic_boundary.py -v`

Positive, adversarial and immutability checks run under native Python 3.12
Windows x86/x64 and x64 macOS/Linux. Full GUI discovery remains unchanged.
This PR must pass the exact HEAD matrix and independent review before merge.

## Reuse sequence
1. Confirm the legacy services' public APIs, unsafe defaults and transitive deps.
2. Adapt **only immutable, non-authorizing snapshots** before connecting UI.
3. Prove authenticated Core regtest and scanner role separation independently.
4. Adopt real session, wallet DB, PSBT and backup services only after
   threat-model updates, adversarial tests and maintainer review.
