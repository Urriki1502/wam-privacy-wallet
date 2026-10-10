# Open-source launch checklist

**Repository became public on 2026-10-10 (verified via GitHub repository visibility).** Public visibility was enabled **before** completion of a full pre-publication history/security audit. The tasks below must be tracked honestly; no security audit has been certified.

## Evidence from initial read-only review

- Repository visibility: `public`; default branch: `main`.
- Current open WSP-1 candidate: [Draft PR #3](https://github.com/Urriki1502/wam-privacy-wallet/pull/3), unmerged.
- Public source history found: multiple phase branches and merges; no baseline rewriting performed.
- Existing workflows reviewed at a high level: typical `pull_request` triggers and `contents: read` permissions with standard Linux/macOS/Windows runners.
- Existing `.gitignore` excludes common `.env`, key, wallet DB and secret file patterns, but **cannot prove historical safety**.
- Initial read-only inspection covered **28 commits returned by repository commit search** and their available patches, checking common GitHub/AWS/Google/Slack token or PEM private-key signatures and obvious sensitive filenames; no matches were detected in that limited sample. This is **not** a complete full-object, branch, tag or artifact secret audit, and is not evidence that the public history contains no credentials.

## Still required: security/provenance verification

- [ ] Clone with all refs and run a full-history secret scan (e.g. Gitleaks or TruffleHog), including every historical blob, branches and tags.
- [ ] Review previous Actions logs, expired/active artifacts, CI env and GitHub secrets exposure paths.
- [ ] If any live credential ever leaked, revoke/rotate immediately; handle Git history redaction separately with security review.
- [ ] Audit all third-party code, images, generated assets and dependency licenses/attribution.
- [ ] Enable GitHub private vulnerability reporting and dependency security alerts if available.
- [ ] Configure and verify `main` branch rulesets: pull requests, appropriate required checks, blocking force push and deletion.
- [ ] Restrict workflows to minimum required permissions; inspect forks, events, untrusted contributions and artifact access.
- [ ] Verify Actions billing/runner eligibility and the public-facing README, license detection and security tabs.
- [ ] Verify GitLab mirror visibility/credentials separately; never assume GitHub public setting changes GitLab access.
- [ ] Conduct an independent peer review and record the final evidence for this launch PR HEAD SHA.

## Publication policy

Open source under MIT is authorized **only** for code and documentation the copyright holder is entitled to license; third-party materials need separate validation. Public repository access is not equivalent to production security or official WAM Core endorsement. No WSP-1 PR merge, consensus changes or real-funds release should be bundled into this launch.
