# Desktop GUI — inspect two existing WAM REGTEST nodes (untrusted)

In the existing Windows/macOS/Linux Qt REGTEST workspace, choose
**Node Connection**. Enter the explicitly configured localhost RPC/P2P ports,
the two distinct disposable RPC usernames/passwords, select REGTEST,
consent to local inspection, and affirm **Core binary NOT authenticated**.
Only then does "Probe two existing REGTEST nodes" enable.

This operation runs the existing real HTTP/P2P `TwoNodeP2PReadOnlyAudit`
and `LocalRegtestIdentityGateway` in a Qt worker thread. It samples
genesis, height and tip before/after topology inspection. It checks that the
two localhost endpoints report the same chain and exactly one P2P peer with
the expected inbound/outbound direction. Cancellation and window-close
poison queued results; only a matching GUI lifecycle revision can render
an immutable, non-authorizing `LiveNodeGuiEvidence`.

No test double is an application backend, no node is launched, no DNS,
public RPC host or port default fallback is allowed. GUI never persists RPC
passwords or displays them in status messages; Qt/Python strings cannot be
guaranteed cleared from process memory and this is **not secure long-term
credential custody**.

No address, txid, funds, UTXO amount, signer, broadcast, private seed or
wallet state is shown or activated by this diagnostic. A reported chain and
peer topology from localhost does **not** authenticate the actual WAM Core
binary, prove process independence or network namespace isolation.
Core #9/#82/#86/#153, anti-rollback #148/#151, upstream WSP #3 remain HOLD.

CI Qt tests patch the diagnostic function to exercise GUI lifecycle and
privacy denial only; these mocks are NEVER a positive Core E2E claim or a
runtime fallback. Genuine WAM Core two-node E2E remains unqualified, as
does Windows/macOS native retained scanner storage and signed desktop
release. Readiness and operational-wallet gates remain unchanged.
