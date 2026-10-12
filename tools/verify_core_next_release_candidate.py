"""Static intake for the next signed WAM Linux release; NEVER launches Core.

--expected-sha256 must be independently obtained from verified official
signed SHA256SUMS. This CLI does not perform GnuPG checks and must not be
used alone as evidence of release authenticity or regtest readiness.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from wam_privacy_wallet.node.core_next_release_audit import (
    CoreCandidateAuditError, inspect_next_linux_release,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only upcoming Core Linux candidate ELF/config audit — NO EXEC"
    )
    parser.add_argument("--archive", required=True,
                        help="Absolute Linux release tarball path; never executed")
    parser.add_argument("--expected-sha256", required=True,
                        help="SHA256 from independently authenticated DEV release metadata")
    args = parser.parse_args(argv)
    try:
        observation = inspect_next_linux_release(
            Path(args.archive), args.expected_sha256,
        )
    except CoreCandidateAuditError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(asdict(observation), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
