"""Offline intake of a future DEV-signed WAM Core Linux release (NO EXEC)."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from wam_privacy_wallet.node.core_next_signed_intake import (
    CoreSuccessorIntakeError, inspect_signed_successor,
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(
        "Inspect a future signed WAM Core Linux release. "
        "No Core process, no config launch, no wallet rights."
    ))
    for label in ("archive", "signing-key", "sha256sums",
                  "detached-signature", "gpg-executable"):
        ap.add_argument("--" + label, required=True,
                        help="Local absolute pathname, independently obtained/trusted")
    a = ap.parse_args(argv)
    try:
        evidence = inspect_signed_successor(
            archive=Path(a.archive), signing_key=Path(a.signing_key),
            sha256sums=Path(a.sha256sums),
            detached_signature=Path(a.detached_signature),
            gpg_executable=Path(a.gpg_executable),
        )
    except CoreSuccessorIntakeError as e:
        print(str(e), file=sys.stderr)
        return 2
    # No private keys, addresses, signing bytes or network requests.
    print(json.dumps(asdict(evidence), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
