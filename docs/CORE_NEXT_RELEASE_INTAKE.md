# Next WAM Core release candidate intake (non-executing)

This is a **preflight for a future DEV WAM signed Linux release**. The latest
official v0.1.11 binary remains blocked on GNU_STACK RWE (issue #86). DEV has
reported a fix for the three RandomX assembly objects missing .note.GNU-stack,
and planned an automatically generated `share/examples/wam.conf` matching
`wamd --help`. Neither change is verified on a newly signed artifact yet.

## Dependency order

1. Obtain official *new* Linux tarball, detached signature, SHA256SUMS and
   publisher key from the approved HTTPS/release origin. Independently
   authenticate actual publisher key fingerprint/revocation and detached
   signature first. Do not trust a hash merely typed by an operator.
2. On the signed SHA256SUMS-confirmed Linux tarball, run the no-exec reader:

   ```bash
   python -m tools.verify_core_next_release_candidate \
     --archive /absolute/path/wam-coin-vNEW-x86_64-linux-gnu.tar.gz \
     --expected-sha256 <independently-authenticated-64-hex-digest>
   ```

   The reader verifies the exact archive digest again, scans every regular
   file under `bin/` for ELF64/x86-64 and an explicit non-executable
   `PT_GNU_STACK`, rejects RWX LOAD segments, symlinks and suspicious tar
   members; checks `share/examples/wam.conf` exists and does not activate
   any option by default. No files are extracted or executed.
3. In DEV's official build/release pipeline, regenerate `wam.conf` from the
   same binary's actual `wamd --help` and compare option inventory with a
   deterministic, exact-build check. This repository cannot certify help
   parity without an independently verified official binary and build
   evidence. The reader's receipt therefore always contains
   `help_parity_verified=false`.
4. Independently verify source revision / RandomX submodule patch, signed
   release-to-source mapping, loader/DSO identity, sealed executable image,
   and isolated real two-node regtest per #82 / #9. Only after DEV-approved
   platform binary and the owner's security gate may a separate opt-in
   real-regtest workflow be developed.

## What this checker does not do

- No GPG/provenance validation in the checker itself; it is designed for
  already separately authenticated release bytes. The reported SHA is
  only equality against caller-supplied expectation.
- No `wamd --help` execution, no dynamic link loading, no Linux Core
  process, no network or subprocess invocation.
- No assurance that the example lists all options or safe values for each
  network; only its path, bounded UTF-8 encoding and inert/non-active nature
  are audited statically.
- No signing, spending, broadcasting, mainnet, real funds or wallet enablement.
  The receipt explicitly keeps every execution and operational flag false.
- Windows and macOS binaries are not covered by the Linux ELF checker.

Issues #86, #82 and #9 remain OPEN until separately satisfied by actual
DEV-signed replacement builds and qualified real-regtest evidence.
