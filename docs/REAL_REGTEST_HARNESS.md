# Phase 007 — Verified WAM Core regtest identity harness

**Status: actual WAM Core execution remains BLOCKED / UNVERIFIED.** Automatic CI validates the harness safety properties only.

## Operator prerequisites

1. Obtain the official WAM Core v0.1.11 executable, or an explicitly reviewed successor.
2. Independently verify the release's signed SHA256SUMS manifest against the trusted release-signing key. A SHA256 checksum alone is NOT publisher authentication.
3. Calculate the SHA256 of the extracted daemon executable itself (not the release archive) and pass this value explicitly.
4. Use an authorized test environment; never point this tool at a real/mainnet wallet or an existing WAM datadir.

Official security guidance: https://wamcoin.org/security/

## Manual opt-in run

macOS/Linux:

    PYTHONPATH=src python tools/verify_local_regtest.py --wamd /absolute/path/to/wamd --sha256 <64-char-daemon-sha256>

Windows PowerShell: first set PYTHONPATH to src, then run:

    python tools/verify_local_regtest.py --wamd C:\path\to\wamd.exe --sha256 <64-char-daemon-sha256>

The tool will refuse an unverified executable, create its own private temporary datadir and configuration, allocate loopback-only ports, start ONLY a foreground regtest process, authenticate via the test datadir's cookie, run the existing read-only gateway identity check, stop only the child it launched, and clean up.

A real manual PASS means a verified executable responded to WAM regtest genesis, block height and tip consistency checks in one isolated session. It **does not** qualify transaction scanning, signing, two-node reorgs, wallet recovery, consensus or production.

A malicious binary can fabricate its RPC responses. Publisher signature verification, external source review and validation of the chosen binary remain mandatory. Pre-execution hash checking does not eliminate file-replacement races.

## What automatic CI proves

The automated workflow runs ten fail-closed contract tests on CPython 3.12:
- native Windows x86 and x64,
- macOS x64,
- Ubuntu x64.

Tests use ONLY synthetic bytes or mocked process creation; they verify SHA matching, symlink rejection, private regtest configuration, cookie handling, secrets redaction, early exit, timeout cleanup and denial-before-execution. **No WAM Core binary is downloaded or executed by CI.** Do not report its green result as real-node qualification.

Native Win32 harness CI does NOT verify a 32-bit WAM Core executable, PySide6 GUI or cryptographic runtime.

## Remaining gates

- Trusted manual Core binary/digest check and real one-node identity evidence.
- Two-node regtest, deep reorg and WSP-1 scanner/recovery checks (REGTEST-E2E-001 issue #9).
- Maintainer review of WSP-1 Windows scanner locking PR #9.
- Windows x86 complete GUI and crypto packaging issue #5.
- No real keys, funds, mainnet or production claims.
