# Source-pinned unsigned PSBTv2 read-only review

Architecture: Application Layer → PSBTv2 research, with no signer capability.
`review_synthetic_psbt_v2` requires explicit synthetic-regtest scope and local
computation consent, exact bytes up to 1 MB, and an absolute pinned source root.
It invokes only a fixed isolated Python worker, never a caller command/provider.
The installed application must have the exact upstream WSP checkout installed
editably; absent/unqualified dependencies fail closed. No downloader or installer
is exposed by the application API.

The worker reuses the packaged full-source checker at
`ac55f13423620252bdbf848c7e8a280c3b84721e`, checks actual dependency versions
and module origin, denies preloaded WSP modules and any cached source bytecode,
and imports the unchanged parser only after qualification. Git toplevel path
spelling is compared as a canonical filesystem path on Windows; every source
blob still uses unchanged raw byte hashes (no source-byte normalization).

The narrow unsigned profile reuses actual upstream `Reader`, `_read_map`,
`_count` and `PSBT.decode`. It accepts v2 only, frozen maps, witness UTXO/outpoint/
sequence fields and ordinary output amount/script fields. It rejects v0,
keypaths, signatures/finalized witness, proprietary/unknown/SP fields,
modifiable flags, malformed/duplicate/noncanonical/trailing/oversized data and
negative synthetic fee relationship. No PSBT parser or cryptography is copied.
This is not full BIP370/375, consensus validation or an operational PayJoin PSBT
profile. In particular, the unsigned profile cannot attest receiver-finalized
PayJoin inputs or input ownership.

The worker audits Python network/process/write events and profiles signing,
finalization, wallet construction and broadcast calls for hard denial. These
are denial instrumentation, **not hostile-code/OS/native isolation**. Mutable
upstream objects stay in the child. Output is a bounded JSON protocol converted
to an immutable counts-only receipt; no bytes, scripts, outpoints, amounts,
source path, signature, key or callback reaches GUI. Ownership, chain, signing
and broadcast authority stay false. Matching source is not publisher/runtime
attestation or hardened key custody. Real secrets/funds, Core and mainnet remain
out of scope.

## Actual native and denial evidence

- 21 actual-source regressions on Linux/macOS/Windows x64, using upstream unsigned
  fixture encoding with a fixed public curve point and no secret/key generation
  or signer. Includes actual transitive source tamper and cached-bytecode denial.
- 16 parent protocol tests + 10 worker denial tests are unit-only; mocked child
  PASS tests protocol shape, **never parser integration**.
- Existing full-source tests grow 10→12 for canonical-vs-foreign Git path spelling.
- Mandatory suites 77; full GUI floor 1006; all prior tests/gates preserved.

**Windows x86 remains UNQUALIFIED / FAIL-CLOSED.** Exact `coincurve==21.0.0`
and `cryptography==50.0.0` currently provide no win32 wheel in their official
PyPI release metadata. The additional actual x86 job proves denial without
installing dependencies/importing WSP/spawning a parser; its green result is
not native parser qualification. A separately reviewed reproducible 32-bit
source build or qualified dependency proposal is needed before enabling it.
Do not replace pinned versions or lower Windows x86 wallet gates to hide this.

All #9/#82/#86/#153, #148/#151, WSP upstream review and Win32 release gates stay
unchanged; CORE-003 excluded. No upstream modification or production claim.
