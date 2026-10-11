# Pinned offline privacy research model snapshots

These four files are byte-identical copies from
[`Urriki1502/wam-privacy`](https://github.com/Urriki1502/wam-privacy)
at commit `db3d2dcaa540f1129d540101813b761167d33174`, MIT licensed.

| Original relative path | Exact upstream Git blob SHA |
| --- | --- |
| `prototypes/network_privacy/model.py` | `efba5aa0f4cd7d57615dfde47206e7e0dde8d865` |
| `prototypes/network_privacy/policy.py` | `3d24c9a9a010220503e6c81251da7c42309a63a0` |
| `prototypes/payjoin_safety/model.py` | `8e3e8be096a66fc960f75a56f1ac34daa9306017` |
| `prototypes/payjoin_safety/validator.py` | `598596a8bde118204b3baf69bb53a884c6dad21a` |

**Cross-platform checkout:** GitHub's Windows runners may use
`core.autocrlf=true`, converting LF to CRLF and causing a false integrity
failure when checking working-tree bytes. An explicit `.gitattributes` rule
sets `text eol=lf` for these **four files only**. CI asserts those exact rules
exist and still verifies raw source bytes against the unchanged Git blob SHAs;
the SHA integrity gate is not disabled, normalized or bypassed.

Copied under `src/wam_privacy_wallet/research_models/` without modifying
their source bytes. `application.synthetic_policy_demo` independently computes
the Git blob hash of each copy **before any research model is imported**. A
mismatch aborts with a fixed error. Identical Git blobs establish source
identity, **not** upstream publisher authenticity, a security audit or WAM
protocol correctness.

`run_fixed_synthetic_privacy_demo()` runs only the two pure-function
validators with hard-coded mock values. It accepts no input, opens no socket,
performs no WAM Core RPC, creates no user wallet, and never signs or broadcasts.
It discards underlying normalized fake transaction/endpoint data and passes only
redacted outputs through the existing, strict
`application.policy_evidence.inspect_synthetic_policy_evidence` gate.
The result is `MODEL_PASS_UNTRUSTED` and `MODEL_ONLY_NO_AUTHORITY`,
with scan/sign/send BLOCKED. Qt renders this only via an explicitly invoked
method, never automatically on app startup. It cannot substitute for runtime
WSP signer, real PSBT parser, local scanner, PayJoin transport or real-node
qualification.

No changes are made to frozen WSP PR #3/#16 or held security PR #50/#51.
Future runtime/production adoption is NOT approved by this isolated research
demo. Recheck this pinned evidence and license before upgrading the source.

## Original upstream MIT License notice

```text
MIT License

Copyright (c) 2026 Urriki1502

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
