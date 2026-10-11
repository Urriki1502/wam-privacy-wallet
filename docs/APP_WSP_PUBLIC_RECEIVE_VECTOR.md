# Receive page — pinned PUBLIC WSP-1 reference (offline only)

**Status:** experimental, non-payable preview. **This screen never generates or displays a receive address.** No seed, private/scan/spend key, wallet profile, scanner, signer, RPC, transaction or real WAM Core binary is loaded.

## Source pin & licensing

This change uses exactly one **public synthetic address** from the WSP-1 wallet's published test vector, but deliberately **does not vendor the full fixture** (which contains private test keys and transaction data).

Upstream repository: [Urriki1502/wam-silent-payments](https://github.com/Urriki1502/wam-silent-payments). Pinned commit: `ac55f13423620252bdbf848c7e8a280c3b84721e`.

| Evidence | Git blob SHA | Usage |
| --- | --- | --- |
| `tests/vectors/wsp1-wallet.json` | `67c77f1c60ed574d81e20147689d9fafc8797991` | Only the published public test address is copied to the Application as an internal fixed fixture. **No seed/private keys/transaction data are copied.** |
| `src/wam_sp/codec.py` | `ec28511113f055ce587f3bfabcd97608a3dfed56` | Pure Bech32m codec vendored **byte-identically** into `research_models/wsp_public/codec.py`, verified with its raw Git blob SHA before import. |
| `LICENSE` (upstream MIT) | `50da6efafc4194c21855e184b49b1667d0d96b4b` | Original MIT attribution preserved verbatim in `research_models/wsp_public/LICENSE`. |

`.gitattributes` pins the vendor codec to LF on Windows, macOS and Linux to avoid checkout normalization changing its Git blob bytes.

**Independent public sample SHA-256:** `5a0f212b2e6153242f68576d3b7e7649e17dbfe98a8235448849e59870dfaaf4`. The application compares the public fixture against this hardcoded complete digest in addition to the fixed source pin, before decoding. This is a deterministic regression guard, **not** source-signature verification.

## Narrow application boundary

`application.receive_vector.inspect_pinned_public_vector()` uses only a **fixed public synthetic example**. It accepts no arbitrary user address, no other HRP, no mainnet/testnet, and no alternate SHA/version. After verifying the pinned codec source bytes, it only decodes/validates the public Bech32m checksum and expected 66-byte public payload shape.

It returns an immutable, slots-only `ReceiveVectorPreview` with:
- fixed `WSP-1` / `regtest` labels;
- `PIN_RECORDED_UNATTESTED` provenance (recorded source pin is not cryptographic source authentication);
- `PUBLIC_SYNTHETIC_FIXTURE` category;
- a **16-character SHA-256 fingerprint**, not the test address;
- `receive=scanner=signer=BLOCKED`.

The Qt Receive screen initially says `NO PUBLIC SAMPLE · NO ADDRESS GENERATED`. Only the **explicit offline demo method** `run_fixed_public_receive_demo()` can show the truncated fingerprint. The UI never displays the original address, does not provide a copy button/QR, and continues to show `NO WALLET LOADED` / `DISCONNECTED · NO RPC`. Reset clears it immediately.

All failures produce the fixed code `APP_RECEIVE_PUBLIC_VECTOR_DENIED` (Qt: `APP_GUI_RECEIVE_VECTOR_DENIED`) without quoting user data. A Git blob SHA check does **not** prevent every local file TOCTOU/module-cache attack; it is research-source evidence, **not production code attestation**.

## Scope / gates

- Native Python 3.12 mandatory suite: `test_app_receive_public_vector.py` has **12 adversarial tests**; **24 mandatory suites** in total, preserving the prior 23 suite floors.
- GUI full discovery: **284 cases minimum** (previous 267 plus 12 native and five GUI tests), preserving all four pinned GUI and six critical non-GUI test IDs.
- Native CI: Windows x86/x64, Ubuntu x64 and macOS x64. GUI: Windows, Ubuntu and macOS. Pinned GET-only and both CodeQL contexts remain required.
- **No WAM Core process, wallet/key derivation, payment generation, scanner, signer, backup or mainnet.** This demo MUST NOT be used to request real funds. Do not treat a passing checksum as authorization or a wallet receive capability.

PR #3 (WSP-1 engine) and PR #16 (scanner) remain **FROZEN**; #50/#51 security reviews remain **HOLD**. Their integration and any operational Receive feature are separate DEV WAM acceptance tasks.
