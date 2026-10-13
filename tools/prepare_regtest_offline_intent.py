"""Local-only WSP UTXO proposal → encrypted offline-signer request."""
from __future__ import annotations
import argparse
import getpass
import json
from pathlib import Path
import sys
from wam_privacy_wallet.application.regtest_manual_intent import (
    create_manual_regtest_intent,
)
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Disposable REGTEST scan+UTXO reservation to encrypted intent only",
    )
    p.add_argument("--wsp-source-root", type=Path, required=True)
    p.add_argument("--private-dir", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--rpc-port", type=int, required=True)
    p.add_argument("--rpc-user", required=True)
    p.add_argument("--max-blocks", type=int, default=16)
    p.add_argument("--acknowledge-unverified-binary", action="store_true")
    args = p.parse_args(argv)
    try:
        if not sys.stdin.isatty() or not args.acknowledge_unverified_binary:
            raise ValueError
        node = LocalRegtestEndpoint("127.0.0.1", args.rpc_port)
        rpc_secret = getpass.getpass("Disposable regtest RPC password: ")
        scan_secret = getpass.getpass("Scan-only account passphrase: ").encode()
        intent_secret = getpass.getpass("New encrypted intent passphrase: ").encode()
        recipient = input("REGTEST WSP-1 recipient code: ").strip()
        amount = int(input("Recipient amount (integer atoms): ").strip())
        fee = int(input("Max fee (integer atoms): ").strip())
        result = create_manual_regtest_intent(
            args.wsp_source_root, args.private_dir, args.output_dir,
            scan_secret, intent_secret,
            endpoint=node, rpc_auth=ExplicitRpcAuth(args.rpc_user, rpc_secret),
            recipient_code=recipient, recipient_atoms=amount, fee_atoms=fee,
            user_consented=True, acknowledge_unverified_binary=True,
            max_blocks=args.max_blocks,
        )
    except (ValueError, EOFError, KeyboardInterrupt):
        print("REGTEST_MANUAL_INTENT_DENIED", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
