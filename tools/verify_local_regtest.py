"""Opt-in manual identity run against an independently verified WAM Core binary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from wam_privacy_wallet.node.real_regtest import RealRegtestError, check_real_regtest


def main() -> int:
    parser = argparse.ArgumentParser(description="Isolated WAM Core regtest identity diagnostic")
    parser.add_argument("--wamd", type=Path, required=True, help="Verified local Core executable")
    parser.add_argument("--sha256", required=True, help="Binary digest confirmed against signed release")
    args = parser.parse_args()
    try:
        result = check_real_regtest(args.wamd, args.sha256)
    except RealRegtestError as exc:
        print(json.dumps({"result": "BLOCKED", "code": str(exc)}))
        return 1
    print(json.dumps({
        "result": "PASS",
        "mode": "real-regtest-identity-only",
        "binary_sha256": result.binary_sha256,
        "network": result.network,
        "height": result.height,
        "genesis": result.genesis,
        "tip": result.tip,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
