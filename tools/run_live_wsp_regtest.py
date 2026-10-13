"""Explicit opt-in genuine WAM regtest localhost scan; never starts Core."""
from __future__ import annotations
import argparse
import getpass
import json
from pathlib import Path
import sys

from wam_privacy_wallet.application.live_regtest_scanner import (
    scan_existing_regtest, LiveRegtestScanError,
)
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="REAL localhost regtest WSP scan; unqualified Core binary, no signing",
    )
    parser.add_argument("--wsp-source-root", type=Path, required=True)
    parser.add_argument("--private-dir", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--rpc-port", type=int, required=True)
    parser.add_argument("--rpc-user", required=True)
    parser.add_argument("--max-blocks", type=int, default=16)
    parser.add_argument("--acknowledge-unverified-binary", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not sys.stdin.isatty():
            raise LiveRegtestScanError("LIVE_SCAN_TTY_REQUIRED")
        if not args.acknowledge_unverified_binary:
            raise LiveRegtestScanError("LIVE_SCAN_ACK_REQUIRED")
        endpoint = LocalRegtestEndpoint(args.host, args.rpc_port)
        rpc_secret = getpass.getpass("Disposable local regtest RPC password: ")
        scan_password = getpass.getpass(
            "Disposable encrypted scan-only account passphrase: ",
        ).encode("utf-8")
        receipt = scan_existing_regtest(
            args.wsp_source_root, args.private_dir, scan_password,
            endpoint=endpoint,
            rpc_auth=ExplicitRpcAuth(args.rpc_user, rpc_secret),
            user_consented=True, acknowledge_unverified_binary=True,
            max_blocks=args.max_blocks,
        )
    except (ValueError, LiveRegtestScanError, EOFError, KeyboardInterrupt):
        print("LIVE_REGTEST_WSP_SCAN_DENIED", file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
