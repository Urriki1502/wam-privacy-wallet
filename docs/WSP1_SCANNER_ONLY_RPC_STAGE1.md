# WSP-1 scanner-only RPC session — Stage 1

Status: LOCAL REGTEST READ-ONLY CONTRACT; not an operating wallet or authenticated WAM Core.

## Contract

- `integrations.wsp1_scanner_only_rpc.Wsp1ScannerOnlyRpc` exposes WSP-1 `Scanner.sync` RPC interface (`attest()` and `call(method, params)`) without importing upstream scanner code or opening a wallet DB.

- Explicit exact-type localhost endpoint and RPC auth, no DNS/proxy/cookie discovery, Core process launch or ambient credentials.

- `attest()` probes reported regtest genesis, tip, height, headers and no-prune status. Every subsequent read is bracketed by fresh probes. Observed profile change poisons the session; self-consistent malicious localhost RPC can still lie, and this is not Core-binary authentication.

- Allowlist: getbestblockhash, getblockcount, getblockhash([height]), getblock([hash,3]). ONLY explicit `include_mempool=True` adds getrawmempool([]) and getrawtransaction([txid,1 or 2]). Bounded responses; no raw hex/full-node write/wallet methods.

- Existing identity-only `LocalReadOnlyRpc` remains unchanged. Legacy scanner diagnostic `_ScannerOnlyWire` still denies getrawtransaction unless a new dedicated WSP session explicitly opts in.

- Reject malformed params, bool/number confusion, duplicate/invalid identifiers, wrong chain and untrusted responses; errors are fixed and redacted.

## Independent gates still required

1. Review exact pinned WSP-1 scanner/source API (#122), preserving WSP-1 freeze #3.

2. Implement application scan-session orchestration with explicit consent, single-writer lease, bounded cancellation/work, recovery/reorg checks and guaranteed cleanup; only then may adapter be passed to Scanner.sync.

3. Live two-node WAM Core regtest (#9) remains BLOCKED until binary acceptance (#84/#86), process identity/loaders (#82) and user/developer approval.

4. GUI must label snapshots LOCAL_RPC_OBSERVED_UNTRUSTED, not wallet/scan qualified. No sign/broadcast/PayJoin/real keys.

Tests use disposable real HTTP loopback fixture only; no upstream WAM Core/WSP-1 source edits.
