"""Interactive, NON-LAUNCHING, cross-platform WAM Core REGTEST two-node RPC audit."""
from __future__ import annotations

import argparse
import getpass
import json
import sys

from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
from wam_privacy_wallet.node.two_node_core_readiness import (
    inspect_existing_core_readiness, TwoNodeCoreReadinessError,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for node in ("a", "b"):
        parser.add_argument(f"--node-{node}-rpc-port", type=int, required=True)
        parser.add_argument(f"--node-{node}-p2p-port", type=int, required=True)
        parser.add_argument(f"--node-{node}-rpc-user", required=True)
    parser.add_argument("--acknowledge-unverified-processes", action="store_true")
    opt = parser.parse_args(argv)
    try:
        if not sys.stdin.isatty() or not opt.acknowledge_unverified_processes:
            raise TwoNodeCoreReadinessError("TWO_CORE_READINESS_TTY_OR_ACK_DENIED")
        a = LocalRegtestEndpoint("127.0.0.1", opt.node_a_rpc_port)
        b = LocalRegtestEndpoint("127.0.0.1", opt.node_b_rpc_port)
        if len({a.port, b.port, opt.node_a_p2p_port, opt.node_b_p2p_port}) != 4:
            raise TwoNodeCoreReadinessError("TWO_CORE_READINESS_PORT_DENIED")
        pa = getpass.getpass("Disposable node A RPC password: ")
        pb = getpass.getpass("Disposable node B RPC password: ")
        report = inspect_existing_core_readiness(
            a=a, aa=ExplicitRpcAuth(opt.node_a_rpc_user, pa),
            b=b, bb=ExplicitRpcAuth(opt.node_b_rpc_user, pb),
            p2p_a=opt.node_a_p2p_port, p2p_b=opt.node_b_p2p_port,
            consent=True, acknowledge_unverified_processes=True,
        )
    except (TwoNodeCoreReadinessError, ValueError, EOFError, KeyboardInterrupt):
        print("TWO_CORE_READINESS_DENIED", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
