# Retained WSP application session — disposable REGTEST review

This adapter integrates the original WSP `import_scan`, `Scanner`, SQLite Store,
incremental `sync`, `sync_mempool`, and scan-account `payment_code` APIs. It does
not generate accounts, construct a seed-bearing Keyring, sign, broadcast, launch
Core, or activate an operational GUI backend. Core gates #9/#82/#86/#153 and the
WSP upstream review remain held. Trusted checkpoint anti-rollback #148/#151 is
not replaced or qualified by a successful retained scan.

The upstream revision is `ac55f13423620252bdbf848c7e8a280c3b84721e`. All 34 pinned
package/metadata blobs, package origin, absence of preloaded WSP modules and
bytecode, and coincurve 21.0.0 / cryptography 50.0.0 / pycryptodome 3.23.0 are
checked before the first WSP import. Raw source and dependency checks are review
evidence; they are not authenticated publisher provenance, a production secure
loader, an OS sandbox or a race-free runtime identity binding. Reopening in the
same explicitly qualified runtime rechecks source bytes/dependencies and uses
the original bound API references. Hostile Python state or same-UID malware
remain outside this experimental boundary.

`SourceQualifiedScanRuntime(source_root, user_consented=True)` requires the exact
scope `disposable-regtest-review` and Linux x64. `runtime.open(private_dir,
password, user_consented=True)` reuses the existing encrypted scan-only backup
reader and private retained DB checks. Existing scan-only ciphertext is supplied
by the caller; the adapter accepts no seed or spending-key role. A successful
open means the original upstream authenticated scan import and Store identity
checks succeeded. The runtime/session never retains a separate password or
decrypted account tuple. The original scanner retains its scan-only accounts;
Python does not promise memory zeroization.

`session.scan(rpc, user_consented=True, max_blocks=1, include_mempool=False)` uses
the existing bounded scan coordinator. The supplied RPC must be the exact
scanner-only localhost REGTEST adapter. Native scanning and SQLite remain under
the original upstream file lease and transaction. A partial batch keeps the
session open and returns `chain_current=False`, progress height/metrics, and
`None` for confirmed UTXO counts, amounts and history. It never presents stale
balance data as a current scan. A current chain allows scalar Store projection;
all amounts are explicitly unqualified local reports. Mempool data is absent
until a new actual `sync_mempool` succeeds. A reopen cannot display persisted
mempool records or balance before a fresh scan.

`session.receive_code(user_consented=True, account_index=0)` calls the original
scan-only payment-code API and original decoder. Only the draft `wamrtsp` REGTEST
namespace is accepted. It grants no wallet or spend authority. No account IDs,
txids, public tweaks, scan secrets, upstream objects or passwords leave the
scalar projection. A code is public address information, not an operational
wallet readiness receipt.

One operation may execute at a time. `cancel()` is a thread-safe stop request;
the owner must finish its operation and close. Concurrent close requests cancel
but refuse to close native SQLite during active work. Operation errors and
cancellation poison and close the session. Close is idempotent; a failed close
remains a failure and permits an explicit cleanup retry. Reopen creates a fresh
scanner with `ready=False` and requires fresh RPC attestation. A GUI controller
must also reject results from cancelled/stale session epochs.

The private backup and retained storage guards remain Linux-only. macOS,
Windows x64 and Windows x86 persistence are denied before source/dependency
reads or WSP imports. The independently qualified scanner-only cross-platform
tests do not qualify retained custody or filesystem durability on those systems.
SQLite metadata is unencrypted. This adapter is for disposable test accounts;
no real user accounts, secrets, funds or production recovery claims are allowed.

## Evidence

The 18 offline tests are denial/lifecycle faults or scalar DTO protocol checks.
They do not supply mocked good engines as integration evidence. The integration
PR must add this 18-case floor while preserving all existing mandatory floors.

The Linux native CI runner `tools.ci_qualified_scan_session` verifies 14 exact
case identities with actual pinned WSP/AES-GCM/SQLite and public test accounts:
consent/wrong-password refusal, scan-only open/receive, initial scan, retained
partial-batch progress without a balance, incremental payment detection,
duplicate replay, mempool projection, redacted/no-authority receipt, reopen and
fresh attestation without cached mempool, cancellation/close/reopen, AES-GCM
tamper refusal, Store account mismatch, reorg/history reconciliation and cached
runtime refusal. A profile guard rejects signer/finalizer/broadcast APIs.

The RPC peer in that test is explicitly synthetic and belongs only to the test
runner. No fake peer or fixture backend is installed in the application. These
tests demonstrate the reusable application seam, not genuine Core E2E, WSP
upstream approval, consensus validity, authenticated balances or release readiness.
