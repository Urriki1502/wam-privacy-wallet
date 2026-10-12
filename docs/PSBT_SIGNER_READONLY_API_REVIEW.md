# PSBTv2 / signer research boundary (not operational approval)

Owner requested opening this branch on 12 October 2026. Scope here is
source/API inspection and preparation of a read-only parser boundary.
No signer, broadcast, Core or real keys/funds are run. This document is not
runtime qualification, protocol acceptance or authorization to spend.

## Exact source inventory

Existing wallet WSP pin stays `ac55f13423620252bdbf848c7e8a280c3b84721e`,
from still-open upstream Windows lease PR #9; no implicit update to WSP main
`dcf1aecc00a64bfad3151fa202c3e07d47d83e69`.

| Pinned upstream path | Git blob SHA | Observed seam |
| --- | --- | --- |
| src/wam_sp/psbt.py | 62bf278fe3eadcb173363780f9cb3e71e31be422 | PSBT.decode / Reader / Tx, shares class with sign/finalize |
| src/wam_sp/adapters/psbt_document.py | cc0e7c91ef35b09d93ad735b4ec6860a2c8ba0f4 | Document.decode / validate, unresolved SP output workflow |
| src/wam_sp/wallet.py | cc1fc58f7a4499687ed7228a8876f2e56e60728e | Signer.prepare/sign and Wallet.broadcast; out of operational scope |
| src/wam_sp/offline_signer.py | 45100e327abafd9758f6ba0d00efb78e65f0e241 | TTY entrypoint, signs and writes file; never import into scanner |

Inventory was obtained from the immutable Git tree/source, without importing
or invoking WSP. File identity is not independent review or evidence of
correct runtime behavior.

## Boundary to implement and qualify next

Reuse `tools.wsp1_full_source_closure` plus established native pinned WSP CI
before any import; no alternate PSBT parser or cloned signing implementation.
Directly evaluate upstream decode on synthetic unsigned bytes only, after
explicit local-computation consent and scope checks. Keep decoded objects
internal; return only immutable bounded redacted counts/no-authority status.
No caller-provided module, callback or source pin. Do not expose parser objects,
mutable maps, keys, signatures, transaction contents or callable handles to GUI.

The pinned parser supports v0 and v2; a wallet **v2-only review** must explicitly
deny v0 rather than implying that upstream decode enforces v2 exclusively.
Its limits are MAX_BYTES=1,000,000, MAX_INPUTS=128, MAX_OUTPUTS=256. It rejects
truncation, duplicate/conflicting maps, noncanonical compact lengths, invalid
modifiable flags, unsupported sighash and unresolved output fields. Those
source observations must be confirmed by genuine native decoder tests.
Unknown fields survive upstream parsing; preservation is not acceptance for
signing, disclosure or telemetry. Existing signatures/keypaths and signer-only
metadata need a separate strict application rejection/allowlist decision.

Do not invoke `PSBT.sign`, `PSBT.finalize`, `PSBT.finalized`, `Signer`,
`SilentWallet.export_signing_request`, `Wallet.broadcast` or `offline_signer`.
Do not treat `Document.validate` structural completeness or normalized PayJoin
annotations as proof of ownership, chain inclusion, consent to spend or valid
signatures. Never convert unresolved output parse placeholders into signable
transactions.

Native regression acceptance needs actual exact-pinned decode, unsigned v2
roundtrip and negative v0/truncation/duplicate/oversize/secret-metadata cases,
no signing methods invoked, no retained bytes in GUI/logs, and all native
Wallet/GUI/CodeQL gates. Synthetic fault injection proves denial only.

## Outstanding decisions / blockers

The exact read-only allowed-field profile and decoded-source loader remain
unimplemented in this branch. Operational signer approval remains separate.
WSP upstream #9 and wallet #3/#16 remain review-gated. CORE-003 excluded;
#9/#82/#86/#153 and trusted anti-rollback #148/#151 retain their state.
No Core modification, mainnet, production readiness or security-audit claim.

## Implemented unsigned boundary on current main

Main `76a1dab675905ef0b2b5bc5e3a9b25c61d6a3055` includes PR #161/#162 and the
combined read-only GUI in #165. The application calls the original source-pinned
unsigned decoder in a fixed isolated worker; native decoder-to-Qt evidence and
adversarial field/source checks are recorded in the merged docs/workflows.
Windows x86 PSBT stays unqualified. Receipt origins are not runtime attestation.

This research branch is rebased onto that main. It contains documentation only;
no signer constructor, signing request, approval grant, private spend-key input,
finalization or transaction broadcast has been added or executed. Opening the
branch does not revoke SIGNER-APPROVAL or any Core/upstream/rollback gate.
