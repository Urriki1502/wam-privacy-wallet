# Consent-gated input policy review in the read-only GUI

The approved V1 diagram's UI → Application Layer → Network Privacy Policy /
Wallet Privacy & PayJoin path now has an explicit programmatic desktop seam:
`MainWindow.review_offline_policy_inputs`. It composes the two direct pinned
synthetic reviewers, then renders only the existing untrusted/no-authority
policy vocabulary through the existing single-writer presentation controller.
No new startup execution, buttons, wallet actions, RPC or signer capability.

Before evaluation it invalidates and clears the previous presentation. Denied
consent, bad network plan or rejected PayJoin proposal cannot leave a prior
model PASS, scanner receipt or receive fingerprint visible. It retains no
endpoints, transaction dicts, credentials, amounts or destinations in Qt.
Source provenance remains explicitly **PIN_RECORDED_UNATTESTED**; source byte
identity plus executed model rules do not authenticate caller annotations,
transport, PSBT or transaction ownership.

Five native Qt regressions exercise real pinned model evaluation, denied
consent after success, independent network/PayJoin rejection, clearing prior
scanner/receive evidence and render failure invalidation. Mock render failure
is denial evidence only. GUI required identities are additive; full discovery
floor 976, mandatory offline suite count stays 75. Modifying the GUI also
triggers existing genuine source-pinned WSP Scanner/SQLite synthetic-regtest
CI; that runner remains no-Core/no-signing.

This is still an offline engineering seam; it is not a user-facing operational
wallet workflow. CORE-003 excluded; all Core, WSP and trusted anti-rollback
blockers stay unchanged. PSBTv2/signer API research remains open but no signer
is invoked or enabled by this preview. Upstream repositories stay unchanged.
