# Actual pinned WSP scanner lease across native processes

The additive `tools.ci_wsp1_scanner_process_lock` proof uses unchanged upstream
`Scanner._lease`, `Scanner.sync`, SQLite and `file_lock` at exact source
`ac55f13423620252bdbf848c7e8a280c3b84721e`. Each fresh Python process verifies
the full source closure, exact dependency versions and installed package origin
before importing WSP, then enforces the existing deny-signing profile.

For both normal holder exit and forced holder termination, an acknowledged
pipe message proves the holder already owns the actual OS lease. A second
process invokes actual `Scanner.sync` and must receive `SCANNER_BUSY` without
calling its failure-only RPC sentinel or changing the SQLite tip. After the
holder exits, a fresh process scans one public synthetic block through the
existing bounded localhost HTTP adapter, closes/reopens SQLite and requires a
fresh RPC attestation before becoming ready again. The persistent lockfile is
preserved; process death releases the OS lock rather than deleting the file.

All pipe reads and child waits have bounded timeouts. Readiness comes from
messages after acquiring the lease, without sleeps or process-start timing
assumptions. Parent cleanup kills only its own disposable Python children.
Fixtures use known public scalars, disposable SQLite directories and a local
synthetic peer. No WAM Core executable, real wallet, seed, signer or broadcast
is used. Error output is fixed and does not echo paths or child diagnostics.

Run on the qualified native host using the pinned editable source installation:

```sh
PYTHONPATH=src python -B -m tools.ci_wsp1_scanner_process_lock --source-root /ABSOLUTE/PINNED/WSP/SOURCE
```

The workflow adds this six-case proof to the existing native Linux, macOS and
Windows x64 scanner matrix. The original eight scanner/BIP352/replay/reorg/Qt
cases remain unchanged and independently required. Windows x86 denies before
source reads or imports; native Windows lock proof is qualified only by the
actual exact-head Windows runner. A macOS ARM64 result does not qualify native
Windows or macOS Intel execution.

This proves cross-process exclusion and automatic lease release on those
tested OSes. It does not qualify retained application account custody,
encrypted backups/checkpoint durability, trusted anti-rollback, source loader
sandboxing or resistance to malicious same-UID/OS compromise. Linux-only
retained application guards stay held on macOS/Windows. #9/#82/#86/#153 and
#148/#151 remain blocked; synthetic RPC success is not actual Core E2E.

Source/dependency/origin negative fixtures explicitly model 64-bit refusal paths
so native Windows x86 can test those layers independently. They import no WSP
and confer no 32-bit qualification. The actual 32-bit pre-source refusal and
native Windows x86 scanner denial job remain unchanged.
