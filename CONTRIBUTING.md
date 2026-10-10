# Contributing to WAM Privacy Wallet

Thank you for helping build an open-source WAM wallet. Contributions must be reviewable, reproducible and honest about what is—and is not—implemented.

## Before you start

- Read [README](README.md), [architecture](docs/ARCHITECTURE.md), [roadmap](docs/ROADMAP.md), [threat model](docs/THREAT_MODEL.md), and [security policy](SECURITY.md).
- Discuss large designs or protocol changes in an issue before coding. Never send vulnerabilities or credentials to public issues; follow SECURITY.md.
- Work on a small feature branch, and open a PR against `main`. No force-push to protected history.
- Never modify WAM Core consensus or a frozen upstream baseline as a side effect of a wallet PR.
- For dependencies from `wam-silent-payments`, `wam-privacy` or WAM SDK, use explicit commit/SHA pins and check the applicable license and attribution first.

## Development setup

Python 3.12 is the current project baseline. A GUI development environment requires optional PySide6:

```sh
python -m pip install -e ".[gui]"
python -m compileall -q src tests
python -m unittest discover -s tests -v
```

On Linux CI, headless GUI tests use `QT_QPA_PLATFORM=offscreen`. On PowerShell, set `$env:QT_QPA_PLATFORM = 'offscreen'` for headless tests. Local availability of a full node or native dependency must never be assumed in a unit test. Opt-in network/regtest integration requires a separate verified WAM Core profile and must be skipped or fail closed when prerequisites are absent.

## Pull-request requirements

1. Describe scope, threat boundaries, modified files and unsupported scenarios.
2. Link an issue when applicable, report the exact commit HEAD SHA, commands and test results.
3. Add positive, negative and regression tests for behavioral changes; cover Windows x86/x64 and macOS when platform-sensitive.
4. Keep the default permissions minimal; never print credentials, seed phrases, request signing material or persistent wallet contents in logs.
5. Identify third-party code provenance, licenses and any generated files or binary artifacts.
6. Do not describe research checks, synthetic stubs, mock adapters or GUI smoke tests as production security assurance.
7. Require maintainer review, successful applicable CI checks and explicit merge approval. Green CI alone does not authorize integration or release.

## Branch and review boundaries

The WSP-1 adapter PR remains independently review-gated. Do not silently merge, cherry-pick or repurpose experimental WSP, wallet-security or WAM Core work. Prefer a security issue via private reporting for vulnerabilities. All code changes are subject to the MIT license in [LICENSE](LICENSE); contributions must be authored by you or appropriately licensed for redistribution.

## Code of conduct

By participating, you agree to [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
