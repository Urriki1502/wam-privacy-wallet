# WAM Privacy Wallet — native REGTEST desktop preview packaging

**Status: UNSIGNED DEVELOPER GUI PREVIEW — NOT AN OPERATIONAL REGTEST WALLET.**

The workflow `regtest-desktop-preview-build.yml` packages the actual PySide6
REGTEST workspace using native CPython 3.12 and PyInstaller on four host targets:

| Target | Runner | Output artifact |
|---|---|---|
| Linux x64 | ubuntu-24.04 | wam-regtest-gui-linux-x64 |
| Windows x64 | windows-2022 | wam-regtest-gui-windows-x64 |
| macOS Intel x64 | macos-15-intel | wam-regtest-gui-macos-x64 |
| macOS Apple Silicon | macos-15 (arm64) | wam-regtest-gui-macos-arm64 |

The checkout is a real commit; Qt is installed and frozen natively on each
runner, with no mock application backend. A real executable is invoked with
`--help` and `--mode regtest --self-test-ui` as independent smoke checks.
The second starts a real Qt window/event loop, checks the nine-view REGTEST
shell remains blocked for wallet authority and exits cleanly. This is not
WAM Core E2E or real WSP scanning. The inspector rejects Core binaries, wallet DBs,
credentials and escaping symlinks, and writes a SHA256 manifest. Each package
is uploaded as a short-lived **CI artifact**, never as a release.

After extraction on the matching OS, start the console executable with
`--mode regtest`. Windows: `WAM-Privacy-Wallet-REGTEST.exe --mode regtest`;
macOS/Linux: `./WAM-Privacy-Wallet-REGTEST --mode regtest`.
The nine-view GUI explicitly displays BLOCKED/REVIEW_ONLY where applicable.
Do not enter any real wallet seeds, production RPC credentials, or funds.

The package intentionally does **not** include or launch WAM Core. It does
not claim live wallet operation, scan-account custody, E2E, signed/notarized
release, executable reproducibility, approved signer, or broadcast.

## Real REGTEST acceptance gate (future separate qualification)

A functional desktop REGTEST wallet requires (a) signed and OS-attested Core
binary/process mapping, loader/DSO and config review (#82/#86/#153);
(b) real isolated two-node WAM Core E2E (#9); (c) reviewed WSP-1 engine
and scan-only custody (#3); (d) wallet receive, scan, real UTXO, signer,
REGTEST-only broadcast, restart/reorg/recovery with approved anti-rollback
disposition (#148/#151); (e) native Windows/macOS/Linux end-to-end tests
and independently reviewed distribution signing/notarization.

No gate is considered passed because a packaging job is green.
Adversarial synthetic fixtures remain in tests only; never a runtime fallback.

## Native macOS app and disk image previews

macOS uses PyInstaller's windowed onedir mode to produce a real `.app`, alongside
the existing terminal executable. [PyInstaller 6.16 documents this native bundle
mode](https://pyinstaller.org/en/v6.16.0/usage.html#building-macos-app-bundles).
The app is named `WAM-Privacy-Wallet-EXPERIMENTAL-REGTEST.app` and has the
`org.wam.experimental.regtest` bundle identifier. Its own executable is inspected
for excluded Core/secret files and smoke-tested with `--help` and a real
Qt window/event-loop exit before distribution. This is not Core/WSP E2E.

A fresh staging folder holds that app and an explicit experimental notice.
Native macOS `hdiutil` creates and verifies a compressed `.dmg`; a `.app.tar.gz`
preserves executable modes and framework symlinks for standalone extraction.
The image/archive names include EXPERIMENTAL, REGTEST and the native architecture.
A separate non-authorizing manifest records their SHA256 values and app inspection.
The artifact upload includes these formats on native Apple Silicon/Intel runners;
Windows/Linux keep their existing package forms. No cross-compilation claim is made.

The app/disk image is a GUI preview only. PyInstaller's ad-hoc signing does not
constitute publisher identity, Developer ID signing or notarization. A disk-image
checksum/verification is container integrity, not operational acceptance. All
existing Core, custody, recovery, signer, broadcast and mainnet holds remain.
No release is published and no Core binary is bundled or executed.
