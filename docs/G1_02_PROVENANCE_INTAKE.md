# G1-02 — WAM Core provenance **candidate** intake (OFFLINE)

**Status: untrusted metadata / no execution permission.** This module is a
strict input-shape validator, **not** an artifact authenticator, identity
verifier or reproducible-build attestation.

## G1 integration baseline

Current protected `main` after G1-01/G1-03 integration:
`65356c96081d92b7c63572923245bdd11d12f070`.
Five reviewed PRs (#27, #29, #38, #40, #42) have been merged; the
16-suite/155-case mandatory CI baseline remains intact. This port uses
a fresh branch from that main, **not** a forced rebase of the original
historical Draft [PR #28](https://github.com/Urriki1502/wam-privacy-wallet/pull/28).

`intake_core_artifact(payload)` only accepts exactly nine fields and
returns a frozen, descriptive `CoreArtifactCandidate`. It requires:

- `schema=wam-core-candidate-intake/v1` as an **exact built-in string**;
- exact repo `wamcoin-core-dev/wam-coin`, inspected pinned source commit
  `260bc468e5adffea7ce68d8f97fac3e27e4c50b2` and strict field types;
- lower-case SHA-256 **shape**, a bounded claimed release version and a
  specified OS/architecture label; these are **untrusted user claims**;
- `publisher_proof=NOT_VERIFIED` with all approval/real-regtest flags false;
- rejection of extra/missing fields, alias types, malformed digests, forged
  authority, or unknown/reinterpreted platforms.

`compat/wam_core_source_pin.json` and the read-only upstream GET gate
anchor *source inspection* only. Neither the source SHA nor the submitter's
binary SHA-256 binds an artifact to an independent publisher, signing identity,
reproducible build, or the bytes an OS later executes. The returned frozen
dataclass is **not a capability token**; no downstream component may treat it
as trusted authorization without a separately reviewed provenance proof.

## Execution boundaries

**No file, network, process, download, cookie, registry, WSP scanner,
signer, Core daemon, wallet or funds.** This stage never validates live
binary flags or authorizes regtest, RPC, reorg, signing, release or mainnet.

This port adds **11 deterministic adversarial provenance-intake tests**
(10 original + exact-type regression). CI requires **17/17 suites, at least
166 collected test cases per native architecture**: Windows x86/x64, macOS
x64, Linux x64. GUI on three OS, pinned Core read-only check and CodeQL
Python/Actions remain mandatory. These numbers refer to offline tests only.

```sh
PYTHONPATH=src python -m unittest discover -s tests -p test_provenance_intake.py -v
```

## What is still BLOCKED

1. Independently authenticated publisher/release artifact identity and exact
   binary digest; association to the pinned source commit and target OS.
2. Execution integrity against SHA verification-to-launch TOCTOU and cookie
   races (see [SEC-G1-EXEC-001 #36](https://github.com/Urriki1502/wam-privacy-wallet/issues/36)).
3. Isolated two-node Core binary review, actual RPC, cookie/restart
   and reorg behavior [REGTEST-E2E-001 #9](https://github.com/Urriki1502/wam-privacy-wallet/issues/9).
4. WSP-1 Windows cross-process locking, scanner integration and external
   security/release review.

**PASS for metadata-input validation never means publisher or binary PASS.**
