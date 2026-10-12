"""Opt-in read-only P2P RPC topology check on pre-existing regtest nodes.

No Core binary launch, addnode/disconnect, wallets, datadir access, signer,
broadcast or external-network operations. Explicit 4 unique local ports and
two TTY-only disposable credentials are required.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys

from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
from wam_privacy_wallet.node.two_node_p2p_readonly import (
    RegtestP2PAuditError, TwoNodeP2PReadOnlyAudit,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only WAM 2-node P2P topology observation, NO CORE LAUNCH",
    )
    for node in ("a", "b"):
        parser.add_argument(f"--node-{node}-rpc-port", required=True, type=int)
        parser.add_argument(f"--node-{node}-p2p-port", required=True, type=int)
        parser.add_argument(f"--node-{node}-rpc-user", required=True)
    options = parser.parse_args(argv)
    try:
        a = LocalRegtestEndpoint("127.0.0.1", options.node_a_rpc_port)
        b = LocalRegtestEndpoint("127.0.0.1", options.node_b_rpc_port)
        # Validate all 4 ports and peer policy before prompting for secrets,
        # by invoking a read-only constructor with disposable validation-only
        # credentials. These dummy values never reach any network transport.
        check = TwoNodeP2PReadOnlyAudit(
            a, ExplicitRpcAuth(options.node_a_rpc_user, "CHECK_ONLY"),
            b, ExplicitRpcAuth(options.node_b_rpc_user, "CHECK_ONLY"),
            node_a_p2p_port=options.node_a_p2p_port,
            node_b_p2p_port=options.node_b_p2p_port,
        )
        del check
        if not sys.stdin.isatty():
            raise RegtestP2PAuditError("REGTEST_P2P_TTY_REQUIRED")
        secret_a = getpass.getpass("Node A disposable regtest RPC password: ")
        secret_b = getpass.getpass("Node B disposable regtest RPC password: ")
        report = TwoNodeP2PReadOnlyAudit(
            a, ExplicitRpcAuth(options.node_a_rpc_user, secret_a),
            b, ExplicitRpcAuth(options.node_b_rpc_user, secret_b),
            node_a_p2p_port=options.node_a_p2p_port,
            node_b_p2p_port=options.node_b_p2p_port,
        ).audit()
    except RegtestP2PAuditError as err:
        print(str(err), file=sys.stderr)
        return 2
    except (ValueError, EOFError, KeyboardInterrupt):
        print("REGTEST_P2P_INPUT_DENIED", file=sys.stderr)
        return 2
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
