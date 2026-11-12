# Protecting `main` — owner action runbook (WAM Privacy Wallet)

**Review-only proposal, 2026-10-10.** Active ruleset `24835699` currently contains
only `deletion` and `non_fast_forward`. These prevent branch deletion/force
updates, but **do not require pull requests, approvals, or passing checks**.
A green GitHub Actions run without branch rules is not merge enforcement.

## 1. Configure in the GitHub UI (repository administrator / owner)

Open [Repository rulesets](https://github.com/Urriki1502/wam-privacy-wallet/settings/rules)
and edit the active `WAM-PRIVACY-WALLET-MAIN-PROTECTION` ruleset, or create an
equivalent additional active ruleset targeting **only** `refs/heads/main`.

Recommended enforceable controls:

1. Keep **Restrict deletions** and **Block force pushes** active.
2. Enable **Require a pull request before merging**, including administrators
   unless a documented, tightly controlled emergency bypass is necessary.
3. Require **status checks to pass** and **branch to be up to date before
   merging** (or enable merge queue with separately verified `merge_group`
   workflow support). Require **all ten current context names** below.
4. **Dismiss stale approvals** on new commits and require unresolved review
   conversations to be resolved before merge.
5. Set required approval count and **Require review from Code Owners** only
   *after* at least one independent, eligible reviewer is configured. Current
   `.github/CODEOWNERS` maps all paths to `@Urriki1502`; GitHub does **not**
   permit self-approval of one's own pull requests. Mandating an independent
   approval while no independent reviewer exists will deadlock normal merges.
   Do not silently replace this requirement with author self-approval.
6. Review bypass actors and restrict them to minimal, documented emergency
   maintainers. Rulesets should remain active, not set to evaluation-only.

**Note:** The available GitHub connector does not expose a write operation
for repository rulesets or branch protection. This runbook is **not** a claim
that the GitHub setting has been changed. A repository owner must apply it.

## 2. Exact status-check names from current workflow

Workflow `.github/workflows/wallet-ci.yml` names its matrix jobs as:

| Required status check |
| --- |
| `Offline contracts / windows-latest / x86` |
| `Offline contracts / windows-latest / x64` |
| `Offline contracts / macos-latest / x64` |
| `Offline contracts / ubuntu-latest / x64` |
| `GUI + full test discovery / windows-latest` |
| `GUI + full test discovery / macos-latest` |
| `GUI + full test discovery / ubuntu-latest` |
| `Verify pinned WAM Core source and current main (GET only)` |
| `Analyze (python)` |
| `Analyze (actions)` |

Use the GitHub UI to pick the **real app/source for each check** to prevent
context spoofing. The last two are from configured CodeQL analysis, not the
Wallet CI workflow; make sure they're scheduled for all `main`-targeted PRs.

**Care with stacked PRs:** A Draft PR targeting a nondefault branch may not
trigger main-only CodeQL; research #29 was verified via an exact-head,
temporary main-target PR #30 (now CLOSED UNMERGED). Do not change required
checks or disable CodeQL just to make a stacked PR appear green. Before merge
to `main`, recreate/rebase each candidate PR onto the updated main and run
native CI + CodeQL at its *final* HEAD.

**Care with merge queue:** Current `wallet-ci.yml` has `pull_request`,
`push main` and `workflow_dispatch` triggers but **not** `merge_group`.
Do not switch on merge queue before adding/reviewing that trigger and
validating that queue commit gets every required check.

## 3. Post-change enforcement verification (read-only/controlled)

- Reopen [rulesets](https://github.com/Urriki1502/wam-privacy-wallet/settings/rules);
  confirm **active**, correct `main` branch target, PR rule, required checks,
  review parameters and restricted bypass actors.
- On a disposable **Draft** PR, inspect `Merge blocked` reasons when review
  or required checks are still outstanding. Never attempt an unreviewed merge
  simply to test enforcement. Confirm source app and stale-HEAD protection.
- Recheck CODEOWNERS semantics with a *non-author* eligible reviewer before
  imposing the approval count; do not count self-review as independent audit.
- Keep security freeze boundaries and release blockers irrespective of
  GitHub branch protection: WSP-1 #3, research #16, rehearsal #25 and
  combined rehearsal #33 remain unmerged.
- If the repository plan/UI lacks the required option, mark governance
  `BLOCKED`; do not describe an unenforced policy as an active guard.

## 4. Owner verification record

| Gate | Current observation (2026-10-10) | Expected follow-up |
| --- | --- | --- |
| Deletion blocked | Active in ruleset #24835699 | Preserve |
| Force-push blocked | Active non-fast-forward rule | Preserve |
| PR required | **NOT CONFIGURED in inspected ruleset** | Owner configure & verify |
| Ten checks required | **NOT CONFIGURED in inspected ruleset** | Owner configure & verify |
| Independent review | No reviews on G1 #27/#28/#29/#31/#32/#33 | Arrange reviewer, then enforce |
| Governance release blocker | **REVIEW_REQUIRED** | Only close after UI enforcement proof |

**No setting changes were applied by this document.**
