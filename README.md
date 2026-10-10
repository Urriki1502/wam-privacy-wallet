# WAM Privacy Wallet

**Status:** Experimental GUI shell only — no wallet functionality or production code.

WAM Privacy Wallet is a proposed cross-platform desktop application for **macOS** and **Windows**, using a modular, non-consensus architecture. This repository is intentionally independent of the existing WAM research and security repositories.

> **Safety boundary:** Experimental development only. Do not use this scaffold with real keys or funds. Mainnet support, security audit and release approval have not been established.

## Planned architecture

```text
User
  └── Desktop GUI shell (Qt / PySide6; navigation only)
        └── Application Layer
              ├── WSP-1 / Silent Payments adapter
              │     ├── Local scanner
              │     ├── PSBTv2 / signer boundary
              │     └── Backup / recovery
              ├── Wallet privacy + PayJoin policy
              ├── Network privacy policy
              ├── Selective disclosure (review-gated)
              └── WAM SDK / RPC adapter
                    └── User-owned, locally validated WAM Core full node

Independent: WAM Security → regression checks and release assurance
Separate R&D: Shielded / Halo2 (NOT part of this wallet's V1 scope)
```

## Repository boundaries

| Repository | Responsibility |
| --- | --- |
| `wam-privacy-wallet` | Independent desktop application and cross-platform integration |
| `wam-silent-payments` | WSP-1 protocol engine; future pinned dependency |
| `wam-silent-wallet` | Existing GUI implementation for reference and reviewed reuse |
| `wam-privacy` | Privacy research and separately qualified modules |
| `wam-security` | Independent security assurance and release gates |

The original repositories must **not** be modified as a side effect of work here. No code has been copied into this scaffold.

## Scope and release policy

- **In scope for future V1 work:** local-node operation, Silent Payments, safe signing and recovery, privacy-aware wallet policy, selected PayJoin/network privacy, and reviewed selective disclosure.
- **Out of scope:** shielded pool, Halo2 consensus activation, changes to WAM consensus, hosted scanner dependencies, and mainnet claims before maintainers approve the required WSP network profile.
- **Security baseline:** pin dependency commits, preserve scanning/spending key separation, validate Windows locking/RPC interoperability, and require independent review before any production release.

## Experimental GUI preview (Phase 001)

The next development stage provides an offline, navigable **PySide6 / Qt 6** desktop shell with Overview, Receive, Send, Privacy, Node and Recovery pages. Every page is a static placeholder: **it cannot read wallet files, generate addresses, connect to a node, sign or broadcast transactions**.

Install optional dependencies and launch on macOS/Windows:

```sh
python -m pip install -e ".[gui]"
python -m wam_privacy_wallet
```

To run the headless GUI smoke tests use `QT_QPA_PLATFORM=offscreen` (PowerShell: `$env:QT_QPA_PLATFORM = 'offscreen'`). The `gui-shell-ci.yml` workflow runs all tests on Ubuntu, macOS and Windows with Python 3.12. It is **not** a wallet security or platform packaging qualification. See [docs/GUI_SHELL.md](docs/GUI_SHELL.md) for the exact boundary.

## Foundation CI

`.github/workflows/scaffold-ci.yml` checks only Python syntax, scaffold metadata and a minimal import contract on **ubuntu-latest**, **macos-latest** and **windows-latest** (Python 3.12).

**Passing scaffold CI does not mean wallet code is correct, secure, cross-platform, or production-ready.** Functional, integration, signing, crash-consistency and release checks will be added in their own reviewable phases.

Local scaffold verification:

```sh
python -m compileall -q src tests
PYTHONPATH=src python -m unittest discover -s tests -p test_scaffold.py -v
```

On Windows PowerShell, use `$env:PYTHONPATH = 'src'` before running the second command.

## Development approach

Each change is a small, reviewable PR. Run local tests, push the exact revision, inspect GitHub Actions by commit SHA, then merge only after the required gates pass. No concurrent code-writing agents or unreviewed production integration. See [docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Licensing

**License selection is deferred.** No LICENSE file has been added. Before importing third-party or repository code, verify attribution and license compatibility. A missing license does not grant permission to reuse third-party code.
