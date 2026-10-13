# WAM Privacy Wallet — Real Core integration checkpoint

This is the durable checkpoint for the October 13, 2026 integration sprint.
GitHub is authoritative; actual required checks must pass on the current PR
head and base before merging. Work credits are not exposed in this environment.
No daemon, mining, block generation or real Core execution is permitted here.

## Live baseline

- Wallet start main: `66161a021a9782f03cbb14fd33a7e4be7ee3db9b`.
- PRs #170–#183 are merged. #182: `f29208926b07a41c381fd9ceea2a403da63a4a5f`;
  #183: `9cd6397bbe771167dcb377839e8d44c80c403895`. #186–#193 are also merged.
  Their working implementations are reused, not recreated.
- WSP main: `7b28bbf9606b9496e9c70b5ffb8dad689f049985`; scanner source pin:
  `ac55f13423620252bdbf848c7e8a280c3b84721e`.
  Upstream WSP PR #3 remains OPEN/DRAFT/HOLD at
  `396f444e3a5f1b8f3105144c6fa8dd7e465e7fae`, unmerged.
- Privacy pin/main: `db3d2dcaa540f1129d540101813b761167d33174`;
  security pin/main: `c9b1ce872c2b0b65276883d4e210b6a2f7c96467`.
- Core current main: `c85259102a366caf62ea82837775f9bd47af1efc`.
  Latest official release remains v0.1.11, a prerelease published September 27.
  Its tag points to `8a3f4fe4f1d804c378f795d4cc281ec5125f75f3`.
  The October 13 Core treasury/bounty documentation change is not a binary
  or launcher remediation. No newer qualifying release was observed.
- Signed Linux archive SHA-256:
  `bd010ed615ab8063d5c12aa61236311ece7e9d19896d9541dacba1888dd9987a`.
  `wam-coin-v0.1.11/bin/wamd` SHA-256:
  `625609c08afef441e9dddd71330dcab1cec112d6fabe361769b9907f0efe7ab4`.
  Publisher fingerprint: `4BD4A8D3AFD43F5CBCB500E23798462FE00ADBA4`.
  Previously observed genuine GPG/static NOEXEC evidence remains applicable
  only to its exact bytes. GNU_STACK is RWE; archive has no `wam.conf`.
  Publisher trust/revocation and secure process acceptance remain unqualified.
- Wallet #9, #82, #86, #148, #151 and #153 remain OPEN.

## Dependency map

| Component | Existing application path | Remaining dependency |
| --- | --- | --- |
| RPC identity | `LocalReadOnlyRpc` → `LocalRegtestIdentityGateway` | Responses describe a local peer; they do not prove executable provenance |
| Real scanner | `live_regtest_scanner` → source-qualified `ScanAccount`/SQLite → `Wsp1ScannerOnlyRpc` → pinned WSP Scanner | Private-host execution and external qualification logs |
| Two nodes | `two_node_wsp_session`, topology/P2P/ancestry readers | Secure Core launch, synchronized indexes, genuine fork scenario |
| GUI | Native Qt scan/history workflows from #180–#183 | Explicit local consent; no signer or broadcaster |
| Checkpoints | Upstream encryption + schema-3 authenticated metadata + atomic journal | Qualified independent monotonic anchor; #151 stays OPEN |
| Launch | Signed release, immutable Linux snapshot and process evidence, strict ELF gate | #82/#86: RWE denies launch; unconditional review interlock retained |
| Configuration | Versioned two-node schema and help/example parity | DEV options are compatibility evidence, not official generated-file parity |

The frozen upstream scanner supplies BIP352 cryptography and input eligibility.
Wallet RPC code validates the boundary without deriving spending keys or
substituting a second cryptographic implementation. Legacy mock peers remain
negative-test fixtures; the real application path has no synthetic fallback.

## DEV compatibility evidence

The operator supplied independent v0.1.11 source-tarball regtest observations:
getblock verbosity 3 prevouts; getblockfilter; scanblocks; scantxoutset;
getrawtransaction; gettxout; getdescriptorinfo; deriveaddresses; synchronized
txindex/coinstatsindex/basic block filter index; generatetoaddress.
Regtest HRP is `wamrt`. The observed coinbase has 47.5 miner, 2.5 treasury and
zero-value witness commitment outputs. Ordinary inputs need spent prevouts;
coinbase inputs do not. A wallet must be explicitly created for bootstrap.

These are DEV-provided compatibility observations, **not wallet E2E PASS**.
DEV's source-built executable is a different artifact from the signed release
binary; compatibility cannot authorize that executable or clear #82/#86.

## Completed unit: WAM transaction and JSON boundary

- Both existing loopback HTTP transports use one strict UTF-8 JSON decoder:
  exact Decimal money; duplicate keys, non-finite/extreme numbers and excessive
  nesting refused. Response sockets close even on size/auth/parse denial.
- The existing WSP adapter validates full transaction/input/output structure
  before scanner storage. Confirmed ordinary inputs require valid prevouts.
  Coinbase is classified separately and output count/reward split is variable.
  Provided malformed mempool prevouts fail; genuinely omitted prevouts retain
  the pinned scanner's real parent RPC lookup. No synthetic data is inserted.
- Canonical hashes, outpoints, scripts, witness bounds, exact atom amounts,
  sequential outputs and supply bounds are checked. Script address/type labels
  carry no authority; upstream determines silent-payment eligibility.
- Existing source-pinned scanner/SQLite/Qt regression fixtures now include
  DEV-shaped WAM coinbase outputs and explicit prevout values. They remain
  synthetic, not consensus-valid or captured real transactions.
- 28 additive tests: 22 new shape/JSON, four actual loopback adapter, two
  identity-transport tests. Mandatory suite count rises 84 → 85; full floor
  1387 → 1415. No previous required case or gate is removed.
- Local focused suites: 22/22 shape, 25/25 scanner RPC, 16/16 identity RPC PASS.
  Mandatory offline run: all suites except the previously documented native
  `/proc` identity restriction pass. Work Qt integration encountered SIGBUS;
  genuine pinned scanner/SQLite/checkpoint steps reached PASS before Qt.
  This is not full-suite PASS. GitHub CI evidence will be recorded separately.

## Acceptance boundaries

| Capability | Classification |
| --- | --- |
| WAM RPC shape and exact monetary parsing | OFFLINE TEST PASS |
| Existing pinned WSP application integration | IMPLEMENTED; offline native regression only |
| Real wallet/Core regtest E2E | LOCAL ACCEPTANCE PENDING / NOT RUN |
| Signed v0.1.11 secure launch | BLOCKED: #82/#86 RWE and execution review |
| Official generated wam.conf parity | OPEN: #153 |
| Encrypted checkpoint/local integrity | IMPLEMENTED; OFFLINE TEST PASS |
| Independent anti-rollback | BLOCKED: #151 lacks qualified external anchor |

No production signing, broadcasting, mainnet authority or independent
anti-rollback acceptance is granted by this checkpoint.

## GitHub checkpoint: first unit merged

[PR #194](https://github.com/Urriki1502/wam-privacy-wallet/pull/194), exact head
`6991896b93aa0b6c92236aadf3d52157f0853987`, merged as
`15656f884976227a016d3572ab5aebeb2a5053b6` after all 17 applicable checks passed
and the current main/base and clean mergeability were rechecked.

- [Wallet CI](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38386135404):
  eight required jobs PASS, including 1466/1466 full discovery on Linux
  (also passing full discovery on Windows/macOS).
- [Pinned native WSP CI](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38386135353):
  five jobs PASS; actual frozen scanner, SQLite, encryption and Qt with a
  **synthetic RPC peer**, not WAM Core execution.
- [CodeQL](https://github.com/Urriki1502/wam-privacy-wallet/actions/runs/38386129890):
  actions/python/rust and aggregate PASS.

The local Work SIGBUS and `/proc` restriction were not bypassed; actual GitHub
native regression evidence passed independently. Main now contains the change.

## Completed unit: separate read-only index/filter integration

- Reuse one bounded HTTP/JSON transport behind existing separate allowlists;
  identity and scanner clients do not acquire diagnostic/write privileges.
  Requests use timeouts, response limits and zero automatic retries.
- `CoreRegtestReadinessRpc` checks strict WAM regtest/genesis, equal header/block
  heights, and all three required synchronized indexes before/after reads.
  It rejects stale, malformed, wrong-network or changing observations.
- BIP-158 BASIC parser validates canonical CompactSize, incremental Golomb-Rice
  values/range, zero padding, byte/element bounds, and BIP-157 header chaining.
  Official CC0 Bitcoin BIP vectors verify serialization and header byte order;
  they are not WAM chain or RPC qualification evidence.
- `scan_public_scripts` exposes only consented, bounded `scanblocks start`
  with 1–16 public raw scripts over at most 64 blocks. No key descriptors,
  status/abort privilege, negative-result shortcut or automatic retry. Matched
  block hashes are checked against live header/height observations.
- `scan_existing_regtest` and its CLI gain `--require-synchronized-indexes`.
  The optional readiness check runs before source/store access and after scan.
  It is a reported peer-consistency check, not secure binary authentication.
  Full WSP block scanning remains unchanged; filters cannot skip SP blocks.
- 39 additive offline tests: 18 filter, 21 actual loopback readiness/timeout/
  authentication/drift/scanblocks/application-denial cases. Mandatory suites
  rise 85 → 87; full discovery floor 1415 → 1454.
- Existing pinned native application CI gains two fresh-worker cases using the
  real application entrypoint and frozen WSP scanner. Both reached PASS locally:
  synchronized-index scan, and stale-index denial before scanner/database work.
  The native suite now requires 21/21 identities; Work Qt still SIGBUS later.
  Mandatory offline execution again has only the documented `/proc` suite
  failure. Full native GitHub CI for this unit is pending until observed.

Primary format references:
[BIP-158](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki),
[BIP-157](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki),
[CC0 vectors](https://github.com/bitcoin/bips/blob/master/bip-0158/testnet-19.json),
[Bitcoin RPC reference shape](https://github.com/bitcoin/bitcoin/blob/v28.1/src/rpc/blockchain.cpp).
WAM-specific runtime compatibility remains the separately provided DEV evidence;
private-host local acceptance has not run.
