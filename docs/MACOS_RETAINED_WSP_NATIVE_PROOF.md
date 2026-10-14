# macOS native WSP-1 retained scanner integration proof

**EXPERIMENTAL / public fixtures / synthetic RPC peer only — NOT Core E2E.**

This adds one native Apple-host integration runner:
`python -B -m tools.ci_macos_retained_wsp_native --source-root <exact WSP checkout>`.

A fresh Python process independently verifies the full pinned WSP-1 source closure
(`ac55f13423620252bdbf848c7e8a280c3b84721e`), exact dependency versions and
import origin. It uses existing upstream WSP `ScanAccount`, `export_scan`,
`import_scan` and `Scanner` on a **disposable public fixture account**.

It composes native create-once macOS encrypted backup custody, private 0700
directory and 0600 SQLite file, live *local socket* synthetic RPC, and actual
WSP BIP352 scanner/storage. The matrix records: authenticated scan-only import,
real native SQLite synchronization, public fixture BIP352 detection, process
restart/re-authorization without duplicate replay and fork/reorg rollback.

**Not established:** any genuine WAM Core execution, signed process identity,
true blockchain ownership, live Core-based payments, private SQLite encryption,
race-free sqlite fd handoff, anti-rollback, GUI Receive/Balance activation,
transaction signing/broadcast or production release. The source-qualified
application runtime still explicitly denies macOS retained wallet activation.
No gating change is made to `SourceQualifiedScanRuntime._platform`, Qt, or
WAM Core. Real Mac REGTEST E2E must separately qualify these boundaries;
no synthetic regression can substitute for that evidence.
