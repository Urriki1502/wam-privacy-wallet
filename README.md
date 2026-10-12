# WAM Privacy Wallet

**Community open-source project • MIT License • Experimental software • NOT production-ready**

A proposed cross-platform, privacy-focused WAM desktop wallet. Its intended architecture is a user-operated, locally validating WAM Core full node, local WSP-1 scanning, explicit signer/consent boundaries, and modular wallet/network privacy controls. This repository does **not** authorize changes to WAM Core consensus.

> **Do not use this software with real wallet keys, seed phrases, production credentials or funds.** Current tests, GUI screens and regtest checks are not proof of wallet-security readiness or mainnet support. No production release, independent audit or mainnet acceptance is claimed.

## Project status

| Area | Status / evidence boundary |
| --- | --- |
| Phase 001 — Qt/PySide6 GUI shell | Merged; offline navigation and placeholders, not a functional wallet |
| Phase 002 — Local regtest endpoint contract | Merged; fail-closed local configuration |
| Phase 003 — WSP-1 pinned engine interface | **Open Draft PR [#3](https://github.com/Urriki1502/wam-privacy-wallet/pull/3)**; not merged or accepted |
| Phase 004 — Regtest chain identity | Merged; read-only synthetic/contract verification |
| Phase 005 — Loopback read-only RPC | Merged; bounded read-only transport, not spending authority |
| Phase 006 — Local regtest gateway | Merged; coupled chain-identity and read-only RPC checks |
| Phase 007 — Opt-in verified Core regtest harness | Merged; requires separately verified local environment |
| Phase 008 — WAM Core profile gate | Merged; fail-closed read-only profile checks |
| Phase 009 — WAM Core source pin | Merged; source identity/drift evidence, not consensus approval |
| Application scanning (#134–#139) | **Merged**; actual pinned WSP-1 Scanner.sync and SQLite, encrypted scan-only import and Qt scalar receipt exercised against a synthetic localhost regtest-shaped RPC peer in native Linux CI; no WAM Core execution or usable wallet |
| BIP352 receive/replay/reorg → Qt (#140) | **Merged**; pinned native WSP scanner and test SQLite detect P2TR payment, reject replay and undo reorg with nonauthorizing Qt metrics |
| Linux encrypted scan-only backup (#141) | **Merged**; private create-once WSP AES-GCM scan-only ciphertext saved/reloaded across test lifecycles; no production account vault |
| Retained WSP-1 SQLite scanner (#142) | **Merged**; real upstream SQLite schema/account identity, scanner lock, restart and reorg verified against synthetic local RPC. SQLite metadata is **not encrypted** |
| Genuine encrypted SQLite checkpoint restore (#143) | **Merged**; upstream WSP AES-GCM Store export/restore verified including authentication, foreign-account denial and post-fork undo |
| Persistent encrypted checkpoint archive (#144) | **Merged**; Linux create-once private ciphertext-on-disk file with no-clobber publication, upstream restore authenticated in native CI; **no anti-rollback/version rotation** |
| App encrypted checkpoint recovery → Qt (#145) | **Draft**; source-verified WSP restore from two private encrypted files to transient scanner+read-only Qt preview; no operational restore button or Core E2E |

The WSP scanner-to-Qt testing above uses real upstream library code but **synthetic blockchain/RPC inputs**. It does not support creating or storing a real user wallet, operational scan buttons, real receive addresses, balances, signing, broadcast or mainnet. An authenticated WAM Core runner, durable scan-key custody and native release qualification remain blocked/review-gated. Original frozen WSP source review [#3](https://github.com/Urriki1502/wam-privacy-wallet/pull/3) is still not approved for production.

The words *merged* and *CI passed* establish repository change status only; they **do not** establish wallet functional completeness, protocol correctness, signer safety or production acceptance.

## Architecture

```text
User
  -> Desktop GUI / consent boundary (Qt / PySide6)
      -> wallet application / policy
          -> WSP-1 adapter (currently review-gated)
             -> local scanner / address derivation
             -> backup and recovery
             -> separately authorized PSBT / signer boundary
          -> PayJoin policy / selective disclosure (future, review-gated)
          -> network privacy (future, review-gated)
          -> loopback-only WAM RPC profile / identity gate
              -> user-owned, locally validating WAM Core full node

Separate: wam-security assurance, upstream research modules
Excluded: shielded/Halo2 consensus changes or hosted scanner requirement
```

**A locally operated full node is a privacy improvement, not an anonymity guarantee.** WAM-operated bootstrap seeds, network peers and first-hop observers may still see connection metadata. See [THREAT_MODEL](docs/THREAT_MODEL.md).

## Local development (no real funds)

Requires Python 3.12. The GUI uses optional PySide6. From the repository root:

```sh
python -m pip install -e ".[gui]"
python -m compileall -q src tests
python -m unittest discover -s tests -v
python -m wam_privacy_wallet
```

On headless Linux, set `QT_QPA_PLATFORM=offscreen` for Qt smoke tests. In Windows PowerShell: `$env:QT_QPA_PLATFORM = "offscreen"`. These commands exercise available scaffold/GUI and Python tests; integration cases that require a validated Core installation or native dependencies have separate prerequisites and **must not** be represented as fully tested merely by this command.

The CI workflows cover the available Linux, Windows and macOS matrices with varying scopes. Check the exact HEAD SHA, job logs and required checks on each PR. A green workflow does not qualify real-funds operation.

## Repository boundaries

- [wam-silent-payments](https://github.com/Urriki1502/wam-silent-payments): upstream WSP-1 engine, to be integrated only with reviewed SHA/version pins.
- [wam-silent-wallet](https://github.com/Urriki1502/wam-silent-wallet): separate wallet implementation and reference materials.
- [wam-privacy](https://github.com/Urriki1502/wam-privacy): independent wallet/network privacy research; freezes and Draft PRs stay independent.
- [wam-security](https://github.com/Urriki1502/wam-security): independent assurance and regression research.
- [wam-sdk](https://github.com/Urriki1502/wam-sdk): separate SDK/research resources.

No license from this repository automatically covers external dependencies or third-party assets. Review upstream licenses and authorship before any copy or redistribution.

## Roadmap and contribution

See [ROADMAP](docs/ROADMAP.md), [ARCHITECTURE](docs/ARCHITECTURE.md), [WSP-1 integration boundaries](docs/WSP1_INTEGRATION.md), [RELEASE_POLICY](docs/RELEASE_POLICY.md), and [CONTRIBUTING](CONTRIBUTING.md). Keep each feature on its own PR with exact-head CI and explicit security review. Do not merge WSP-1 PR #3 or alter WAM Core as part of this documentation launch.

Report sensitive vulnerabilities privately per [SECURITY](SECURITY.md). Public Issues and PRs must not contain keys, real RPC credentials or wallet backups.

## License

Released under the [MIT License](LICENSE): Copyright (c) 2026 Urriki1502 and contributors, for work the respective copyright holders are authorized to license. Contributions must comply with the repository's licensing and attribution policy. Open source **does not mean** production-ready, officially endorsed by WAM Core, or safe to transact with real funds.
