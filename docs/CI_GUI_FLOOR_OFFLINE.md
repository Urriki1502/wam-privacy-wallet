# CI-GUI-FLOOR — V5 offline review handoff (stacked on PR #53)

Scope: synthetic/offline WAM Privacy Wallet only. No real Core executable, live node, wallet funds, signer, scanner, or production. DEV WAM reviews and approves any later Core integration.

## Baseline and stacked change

- Protected main base SHA: 540a3685bf142907611f3853adea900df7718e18. PR #53 head: 125ce38af4b35ff14d06cab18f72f8fddf476e07.
- 19 mandatory offline suites: 194 native tests on protected main, 198 after four synthetic cases in PR #53. Complete GUI discovery: 198 on main, 202 after #53.
- GUI Gate V5 adds 20 synthetic tests: **20 mandatory suites with >=218 native cases**, **>=222 complete GUI discovery cases** stacked on #53.
- All 19 original suite floors, including #53's self-suite floor of 14, and all ten protected required checks, remain unchanged. Native platforms Windows x86/x64, Ubuntu, macOS; GUI Windows, Ubuntu and macOS; pinned GET-only; CodeQL Python/Actions.
- Required identities: four original GUI tests and six security-critical non-GUI tests. Reject duplicate IDs, missing tests, import failures, skips, expected failures and partial discovery.
- The GUI workflow now runs `python -m tools.gui_ci_contract_gate`, which performs full unittest discovery internally.

## Limits and required review

- Test ID pinning protects *identity*, **not assertion-body/source integrity**; a fake test body retaining the ID is out of scope. Do not claim independent security approval.
- The offline Python 3.13.5 prototype ran 20/20 synthetic GUI gate regressions PASS. Verify GitHub exact-head native Python 3.12 CI and CodeQL; no assumed green status.
- DRAFT stacked on PR #53. Review and disposition #53 first; retarget this PR to main after #53 merge and reverify exact-SHA checks. No auto-merge, deployment, real Core, signer/scanner, or changes to frozen #3/#16, HOLD #50/#51 and closed #52.
