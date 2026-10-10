# G1-03 — Two-node candidate configuration audit (review-only)

**Stacked on G1-01 Draft PR #27; not targeted at main.** The audit takes the
already non-executing G1-01 `TwoNodePlan` and checks it against an exactly
reconstructed policy candidate. It rejects a single change to host, port,
peer, config line, safety status or release flag. Its evidence object is
immutable and never authorizes network, scanner, signer or real funds.

## Boundaries

- No sockets, filesystem, subprocess or WAM Core source modifications.
- Never starts a node, reserves ports, reads/writes cookies or wallet files.
- The G1-01 candidate previews could be unsupported by actual WAM Core;
  **a successful offline audit is NOT evidence of binary support or security**.
- G1-02 independently validates untrusted binary *metadata*, not provenance.
  G1-04/05 real-node validation stays BLOCKED pending independent verified
  publisher identity, WAM Core binary/sha, isolated launcher and review.
- Do not merge frozen WSP-1 PR #3, Phase 010 #16, upstream locking PR #9
  or the no-merge combined rehearsal #25.

## Acceptance

Thirteen adversarial tests cover valid canonical plans, false or forged inputs,
port ranges/collisions, remote/DNS hosts, peer rebinding, injection of unsafe
config lines, removed/reordered lines, authorization escalation, immutability,
and proof of no I/O. Register as mandatory suite **#15** on the stacked branch;
expected **129 collected test cases** in each of 4 offline architecture legs
(14 prior suites / 116 cases from PR #27 + 13 newly added cases). GUI tests
on macOS/Linux/Windows x64, pinned Core source GET-only check and both CodeQL
checks remain mandatory.

`PYTHONPATH=src python -m unittest discover -s tests -p test_two_node_policy.py -v`

Do not merge stacked G1-03 to main without separate G1-01 review and rebase.

## Strict dataclass field types (G1-03 hardening)

An earlier version relied on `candidate == canonical` after validating the
four RPC/P2P ports, but Python dataclass equality treated values like
`False == 0 == 0.0` as equivalent. It also accepted a numeric-equivalent
`peer_p2p_port` and `str` subclasses as exact strings. These are **schema
violations** even when an ordinary equality check returns True.

The policy gate now requires exact `bool` types for every plan authority
field, exact built-in `int` for all node ports, and exact built-in `str`
for all node strings and the top-level status **before** comparing to the
canonical proposal. Missing dataclass slots fail closed with the original
redacted `G1_POLICY_PLAN_INVALID` code. Three regression tests cover all
five authority flags and coercion cases; the mandatory suite minimum increases
from 10 to 13. This does **not** attest to actual WAM Core daemon flags or
make real-regtest safe to execute.
