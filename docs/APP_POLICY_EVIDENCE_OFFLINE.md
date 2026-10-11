# Application Policy Evidence — Offline Read-Only Port

**Scope:** purely synthetic/normalized WAM privacy research evidence, never an operational PayJoin, route selection, scanner, signer, wallet, RPC or transaction.

## Source provenance — research snapshots, not imported dependencies

Upstream repository: [Urriki1502/wam-privacy](https://github.com/Urriki1502/wam-privacy), pinned commit:
`db3d2dcaa540f1129d540101813b761167d33174`, MIT License.

| Research source | Exact pinned Git blob |
| --- | --- |
| `prototypes/network_privacy/policy.py` | `3d24c9a9a010220503e6c81251da7c42309a63a0` |
| `prototypes/payjoin_safety/validator.py` | `598596a8bde118204b3baf69bb53a884c6dad21a` |

Only their **redacted result schemas** are used as interface references. The application never imports upstream modules and does not execute those validators. Therefore a caller-provided `result=PASS` is forgeable and **must not be trusted as proof that the corresponding algorithm ran**.

## Narrow synthetic interface

`application.policy_evidence.inspect_synthetic_policy_evidence(network, payjoin)` consumes two exact-field dicts representing local mock results. It rejects unexpected fields, non-boolean booleans, non-integer counts, missing keys, unsafe routing summaries, direct fallback, output substitution, and unknown result statuses.

The accepted route-summary subset is deliberately more restrictive than all possible policy options: scanning remains `local`, mock broadcast is `tor` / `i2p` / `ohttp`, no direct fallback, and asynchronous PayJoin requires `ohttp`. PayJoin mock result requires at least one receiver input, at most 128, with no output substitution. No underlying endpoints, credentials, coin ownership, transaction bytes, PSBTs or fees are inspected or retained.

An accepted mock produces only an immutable **`MODEL_PASS_UNTRUSTED`** snapshot with `MODEL_ONLY_NO_AUTHORITY` and all `scan/sign/send` capabilities **BLOCKED**. Even a forged all-PASS dict results in **no authority**. The Qt Privacy panel can render this as `SIMULATED MODELS · UNTRUSTED · NOT AUTHORIZED` and reset it, without changing wallet, node or Privacy Readiness state. Rejected inputs produce a fixed redacted error, never raw caller data.

## Validation and limitations

- Python 3.12 native mandatory suite: `test_app_policy_evidence.py` >=12 tests, **22 mandatory suites** total.
- GUI full discovery minimum: **257 cases** (existing 241 +12 pure unit tests +4 Qt GUI regressions).
- Preserve original suite floors, four GUI pinned IDs, six critical non-GUI pinned IDs, all 10 required protected contexts, CodeQL Actions/Python and pinned GET-only.
- No automatic mainnet release or runtime enablement. Tests validate an **untrusted synthetic display boundary** rather than cryptographic, route, PayJoin BIP compatibility, WAM network compatibility or real transaction safety.
- The WSP-1 wallet PR #3, scanner PR #16 remain FROZEN, G1 security #50/#51 remain HOLD, #52 CLOSED unmerged; none is a dependency executed by this patch.
