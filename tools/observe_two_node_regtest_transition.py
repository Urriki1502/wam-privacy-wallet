"""Interactive read-only two-node localhost regtest transition diagnostic.

No Core startup, no privileged RPC, no wallet or spend path. A matching
reported chain cannot authenticate Core processes or prove actual reorg.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys

from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
from wam_privacy_wallet.node.two_node_live_transition import (
    RegtestTransitionError, TwoNodeLiveTransitionObserver,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare two already-running isolated localhost WAM regtest nodes",
    )
    for label in ("a", "b"):
        parser.add_argument(f"--node-{label}-host", required=True)
        parser.add_argument(f"--node-{label}-port", type=int, required=True)
        parser.add_argument(f"--node-{label}-rpc-user", required=True)
    parser.add_argument("--interval-seconds", type=float, default=0.0)
    opts = parser.parse_args(argv)
    try:
        # Endpoint and interval validation must happen BEFORE requesting
        # disposable passwords. No inherited environment/argv secrets.
        a = LocalRegtestEndpoint(opts.node_a_host, opts.node_a_port)
        b = LocalRegtestEndpoint(opts.node_b_host, opts.node_b_port)
        if a == b:
            raise RegtestTransitionError("REGTEST_TRANSITION_DUPLICATE_ENDPOINT")
        import math
        if (not math.isfinite(opts.interval_seconds)
                or not 0 <= opts.interval_seconds <= 5):
            raise RegtestTransitionError("REGTEST_TRANSITION_INTERVAL_DENIED")
        if not sys.stdin.isatty():
            raise RegtestTransitionError("REGTEST_TRANSITION_TTY_REQUIRED")
        first = getpass.getpass("Node A disposable regtest RPC password: ")
        second = getpass.getpass("Node B disposable regtest RPC password: ")
        observer = TwoNodeLiveTransitionObserver(
            a, ExplicitRpcAuth(opts.node_a_rpc_user, first),
            b, ExplicitRpcAuth(opts.node_b_rpc_user, second),
        )
        result = observer.observe(interval_seconds=opts.interval_seconds)
    except RegtestTransitionError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (ValueError, EOFError, KeyboardInterrupt):
        print("REGTEST_TRANSITION_INPUT_DENIED", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
