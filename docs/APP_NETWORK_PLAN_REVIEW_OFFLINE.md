# Input-backed offline network policy integration

Application Layer → Network Privacy Policy in the approved V1 diagram.
`review_synthetic_network_plan` evaluates caller-supplied, bounded synthetic
endpoint plans through the existing byte-identical wam-privacy validators at
`db3d2dcaa540f1129d540101813b761167d33174`; no new policy copy or fork.
It verifies the existing four source blobs before import. Source identity is
not publisher authentication or independent security approval.

Explicit `synthetic-regtest` scope and `consent=True` allow local computation
only. Exact primitive types, bounded tuple/dicts and strict schema prevent
credentials, policy overrides, callbacks and loose bool/int coercion. Default
upstream policy denies remote scan, encrypted direct broadcast, direct fallback,
public role reuse and async PayJoin without a distinct OHTTP directory. The
receipt retains no host, port, credentials or route telemetry. All operational
permissions and transport verification remain false. Input annotations may be
forged; PASS is only a model evaluation, not actual route/endpoint verification.

14 application regressions include upstream rejection cases and negative
fault-injection tests. Fault-injected exceptions prove denial only. Four native
CI architectures additionally authenticate and execute the **actual unchanged
10 upstream Phase 5 regressions**, including their package init and test blob.
All old suites and floors are preserved; mandatory suite count 74, full GUI
floor 955. Existing native WSP CI is unaffected.

## Next small integration slices

1. Input-backed normalized PayJoin review using existing pinned validator,
   bounded synthetic values, strict policy and consent; never a PSBT parser or
   ownership proof. Native exact-source Phase 4 tests.
2. PSBTv2/signer API research now in scope by owner request: verify source
   closure, parser and denial invariants, keep scan/spend separation. Do not
   execute a signer or broadcast without separately scoped authorization.
3. Wallet policy and selective disclosure require a separate source/API review;
   no fabricated implementation status or arbitrary disclosure callback.

wam-security main inspected at `c9b1ce872c2b0b65276883d4e210b6a2f7c96467`.
Its wallet native harness starts Core and creates/signs disposable wallets;
that API is incompatible with this no-Core/no-signing slice, so is not executed
or copied. Its documented response-loss and watch-only invariants remain
requirements for later separately authorized runtime work.
wam-silent-payments main is `dcf1aecc00a64bfad3151fa202c3e07d47d83e69`;
wallet's established scanner pin stays `ac55f13423620252bdbf848c7e8a280c3b84721e`.
No upgrade of that pin or upstream modification occurs here.

CORE-003 excluded. #9/#82/#86/#153 remain blocked/open as appropriate;
#148/#151 trusted anti-rollback stays unsupported/review-required, and WSP
upstream review gates stay unchanged. No Core launch, network transport,
scanner enablement, real keys/funds, signer, broadcast, mainnet or release claim.

## Primitive map boundary follow-up

A shared `synthetic_input_shape` guard requires exact dict, bounded field count
and exact str keys before key-set comparison. This rejects in-process
str-subclass equality callbacks and oversized maps before source verification.
Two additive adversarial regressions raise network/PayJoin floors to 15/17
and full GUI floor to 978; upstream source bytes remain unchanged. This does
not provide hostile-code isolation or any operational authorization.
