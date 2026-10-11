# WAM Core v0.1.11 — nonexecuting official-release evidence CLI

## What is real (not a mock)

`tools.verify_core_release_offline` consumes **actual operator-provided signed release files** via **real GnuPG**. It does not contain a synthetic-success switch. It validates:

1. The signed release `SHA256SUMS.asc` over `SHA256SUMS`, with the fixed WAM primary signing fingerprint from [wamcoin.org/security](https://wamcoin.org/security/).
2. The complete archive SHA-256 against the digest contained in those authenticated checksum bytes.
3. The binary member inside the TAR.GZ or ZIP archive *without extracting or running it*, including canonical file identity, size, member hash and archive path-safety checks.
4. It emits a stable JSON evidence document containing the release archive and node-member digests. **All executable, wallet and mainnet permissions remain false.**

Only signed v0.1.11 node archives on the pinned Linux x64, Windows x64 or macOS arm64 list are accepted. Use genuine signed files; do not paste credentials or wallet data.

## Operator command (example on Apple Silicon)

First obtain and verify the actual release files from the official channel. GnuPG is an independently reviewed local executable; `gpg` is NOT downloaded or chosen from an arbitrary archive by this program. All five inputs must be absolute local file paths.

```sh
PYTHONPATH=src python -m tools.verify_core_release_offline \
  --archive /private/tmp/wam-review/wam-coin-v0.1.11-arm64-apple-darwin.tar.gz \
  --key /private/tmp/wam-review/SIGNING-KEY.asc \
  --checksums /private/tmp/wam-review/SHA256SUMS \
  --signature /private/tmp/wam-review/SHA256SUMS.asc \
  --gpg /opt/homebrew/bin/gpg
```

The example paths are illustrative, not proof that a real file exists there. The command **does not download anything**, open network connections or launch WAM Core. Failure prints a fixed denial code without file paths or credential values. The output remains review-only, even when the detached signature is genuine.

## What remains blocked

- Verifying a signed distribution archive does not prove the installed, extracted executable bytes are the ones the OS launches; see #36 (TOCTOU, OS-native restrictions and publisher release/build identity).
- This command never enables `check_real_regtest`. Actual WAM Core two-node regtest under #9 still needs the DEV-reviewed binary and isolated configuration.
- The read-only scanner bridge merged in #70 uses actual loopback sockets but its CI server is a deterministic protocol fixture, **not** genuine WAM Core. Its summaries carry no scanner/signer authority.
- Native CI unit tests for this command include synthetic records and patched verification boundaries to check denials, not official-release evidence. The preexisting native Linux GnuPG E2E uses a temporary synthetic signing key. Neither proves the official archive has been fetched or verified in CI.

## Next migration gate

Obtain real signed release files and preserve the exact source URL + SHA evidence, run the offline command, review the node-member digest, then design/verify host-specific immutable execution binding. Only after acceptance may the controlled two-node **regtest** harness be considered for opt-in execution. Never use mainnet, real wallet keys, transaction signing or WSP-1 frozen branch merges here.
