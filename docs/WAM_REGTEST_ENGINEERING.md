# Cooperating local REGTEST engineering runs

The local engineering schedule must acquire a shared directory lease before
changing any WAM checkout. An already active owner makes the next run exit
promptly with `ENGINEERING_RUN_ALREADY_ACTIVE`; it must leave branches,
worktrees and checkpoints alone and try again at the next scheduled run.

The lease uses an actual kernel `flock` on an open directory descriptor on
macOS and Linux. The directory must already exist, belong to the effective
user and have mode `0700`. The tool refuses symlinks in every path component,
relative paths and parent traversal. It creates no lockfile and writes no PID.
Windows is unqualified and is refused before directory I/O.

All sessions, including ones working in different worktrees, use this **same
stable directory in the primary checkout**:

```text
/absolute/path/to/primary-checkout/reports/local/wam-regtest-engineering
```

Provision it once. Do not remove, replace, rename or resolve a different
directory to recover a supposedly stale lease: a different inode creates an
independent lock and would allow overlapping runs. A process holding this
lease must remain alive for the entire engineering session. Kernel teardown
releases its lease when it exits; no stale-lock deletion is required.

For an already committed tool, start a long-lived local terminal process:

```sh
/absolute/path/to/primary-checkout/.venv/bin/python -B \
  /absolute/path/to/qualified-checkout/tools/engineering_run_lease.py \
  /absolute/path/to/primary-checkout/reports/local/wam-regtest-engineering
```

Wait for `ENGINEERING_LEASE_ACQUIRED`, keep that process and its stdin open,
and then perform the engineering work. Save the final checkpoint before
sending a newline or closing stdin; either releases the lease and prints
`ENGINEERING_LEASE_RELEASED`. Do not use a short shell pipeline that immediately
closes stdin. Do not spawn detached children that continue modifying checkouts
after the engineering session releases its lease.

An unmerged tooling PR may be bootstrapped by copying its reviewed tool into
`reports/local/wam-regtest-engineering/engineering_run_lease.py` in the primary
checkout and recording the source commit and file digest in the checkpoint.
Run that absolute tooling path against the same stable directory. Generated
reports stay under the ignored `reports/local/` tree; this tracked document is
the reusable protocol, not a claim that an automation has been enabled.

At the start of every run, read the latest checkpoint, verify available usage,
inspect current GitHub source pins and active PRs, and continue the highest
priority unfinished unit. At the end, record the checkout SHA, changes and PR
links, actual test results, exact-head CI, remaining blockers and next action.
Keep the lease held until all modifying work and checkpoint writes finish.

This prevents overlap between cooperating sessions that obey the protocol.
It does not prevent arbitrary manual edits, a malicious process with the same
UID, or directory replacement. It is scheduling coordination, not a custody
boundary, process attestation or wallet approval. Core execution, genuine
REGTEST E2E, signing, broadcasting and mainnet gates remain unchanged.

The mandatory `test_engineering_run_lease.py` suite runs real owner and
contender Python processes on native macOS/Linux. It verifies refusal while
an owner lives, release on normal exit/EOF/termination, unchanged directory
identity and checkpoint data, descriptor cleanup, symlink rejection and
Windows denial before I/O. Children execute only the lease tool. No Core
executable, wallet secret, signer or network peer is involved. Passing these
tests provides no WAM Core E2E or production wallet qualification.
