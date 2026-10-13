"""TTY-only real two-node REGTEST scan operator, never a node launcher."""
from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import sys

from wam_privacy_wallet.application.two_node_wsp_session import (
    scan_two_existing_regtest_nodes, TwoNodeWspSessionError,
)
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Existing two-node REGTEST WSP scanner; binary not attested",
    )
    parser.add_argument("--wsp-source-root", type=Path, required=True)
    parser.add_argument("--private-dir", type=Path, required=True)
    parser.add_argument("--node-a-rpc-port", type=int, required=True)
    parser.add_argument("--node-a-p2p-port", type=int, required=True)
    parser.add_argument("--node-a-rpc-user", required=True)
    parser.add_argument("--node-b-rpc-port", type=int, required=True)
    parser.add_argument("--node-b-p2p-port", type=int, required=True)
    parser.add_argument("--node-b-rpc-user", required=True)
    parser.add_argument("--max-blocks", type=int, default=16)
    parser.add_argument("--receive-account-index", type=int,
                        help="Opt in to show local receive code after both nodes agree")
    parser.add_argument("--show-observed-balance", action="store_true",
                        help="Opt in to unqualified confirmed atoms; NOT spendable")
    parser.add_argument("--history-limit", type=int)
    parser.add_argument("--save-checkpoint", action="store_true")
    parser.add_argument("--restore-checkpoint", action="store_true")
    parser.add_argument("--acknowledge-unverified-binaries", action="store_true")
    opts = parser.parse_args(argv)
    try:
        if not sys.stdin.isatty() or not opts.acknowledge_unverified_binaries:
            raise TwoNodeWspSessionError("TWO_NODE_WSP_TTY_OR_ACK_DENIED")
        a = LocalRegtestEndpoint("127.0.0.1", opts.node_a_rpc_port)
        b = LocalRegtestEndpoint("127.0.0.1", opts.node_b_rpc_port)
        if (a == b or len({a.port, b.port, opts.node_a_p2p_port,
                          opts.node_b_p2p_port}) != 4):
            raise TwoNodeWspSessionError("TWO_NODE_WSP_PORT_DENIED")
        pa = getpass.getpass("Disposable node A RPC password: ")
        pb = getpass.getpass("Disposable node B RPC password: ")
        scan_password = getpass.getpass(
            "Disposable encrypted scan-only account password: ",
        ).encode("utf-8")
        result = scan_two_existing_regtest_nodes(
            opts.wsp_source_root, opts.private_dir, scan_password,
            node_a=a, auth_a=ExplicitRpcAuth(opts.node_a_rpc_user, pa),
            node_b=b, auth_b=ExplicitRpcAuth(opts.node_b_rpc_user, pb),
            node_a_p2p_port=opts.node_a_p2p_port,
            node_b_p2p_port=opts.node_b_p2p_port,
            user_consented=True, acknowledge_unverified_binaries=True,
            max_blocks=opts.max_blocks, history_limit=opts.history_limit,
            save_checkpoint=opts.save_checkpoint,
            restore_checkpoint=opts.restore_checkpoint,
            receive_account_index=opts.receive_account_index,
            show_observed_balance=opts.show_observed_balance,
        )
    except (ValueError, EOFError, KeyboardInterrupt):
        print("TWO_NODE_WSP_SESSION_DENIED", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
