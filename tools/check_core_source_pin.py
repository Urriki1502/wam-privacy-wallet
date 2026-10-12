"""Read-only Core source requalification: no Core clone, binary or write API.

Runs only when explicitly invoked or in the wallet's source-pin CI. The pinned
snapshot and current Core 'main' are fetched as immutable content checks; any
source drift blocks compatibility claims pending human review.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from wam_privacy_wallet.node.core_source_pin import (
    CoreSourceContractError, load_core_manifest, verify_core_source,
)

MAX_BYTES = 500_001
PATHS = ("src/wam/wam-params.h", "src/wam/chainparams.cpp", "scripts/patch_upstream.py")


def fetch_sources(repository: str, reference: str) -> dict[str, bytes]:
    # Both source names are hardcoded in the verified manifest. No caller
    # supplied hostname, path, redirect target or binary is executed.
    if repository != "wamcoin-core-dev/wam-coin":
        raise CoreSourceContractError("CORE_SOURCE_WRONG_REPOSITORY")
    if reference != "main" and (
        len(reference) != 40 or any(c not in "0123456789abcdef" for c in reference)
    ):
        raise CoreSourceContractError("CORE_SOURCE_INVALID_REF")
    data = {}
    for name in PATHS:
        url = f"https://raw.githubusercontent.com/{repository}/{reference}/{name}"
        try:
            with urlopen(url, timeout=15) as response:
                raw = response.read(MAX_BYTES)
        except (OSError, HTTPError, URLError, TimeoutError):
            raise CoreSourceContractError("CORE_SOURCE_FETCH_FAILED") from None
        if len(raw) >= MAX_BYTES:
            raise CoreSourceContractError("CORE_SOURCE_TOO_LARGE")
        data[name] = raw
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only WAM Core source pin checker")
    parser.add_argument("--check-head", action="store_true", help="Also compare Core main's critical source blobs")
    args = parser.parse_args()
    path = Path(__file__).resolve().parents[1] / "compat" / "wam_core_source_pin.json"
    try:
        manifest = load_core_manifest(path)
        result = verify_core_source(
            manifest, fetch_sources(manifest["repository"], manifest["inspected_commit"])
        )
        if args.check_head:
            verify_core_source(manifest, fetch_sources(manifest["repository"], "main"))
    except CoreSourceContractError as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}))
        return 1
    print(json.dumps({
        "status": "PASS",
        "scope": "SOURCE_ONLY",
        "commit": result["source_commit"],
        "head_critical_files_match": bool(args.check_head),
        "genesis": result["regtest_genesis"],
        "rpc_port": result["network_ports"]["regtest"]["rpc"],
        "consensus_bip94": result["consensus_bip94"],
        "signed_binary_matches_source": False,
        "core_execution_allowed": False,
        "real_regtest_qualified": False,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
