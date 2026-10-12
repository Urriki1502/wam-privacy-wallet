"""Interactive, read-only two-node WAM regtest ancestry diagnostics.

Run ONLY against two already-running, independently approved localhost RPC
endpoints. Passwords are obtained from distinct TTY-only prompts; no CLI or
environment passwords. Does not launch Core, control P2P, access wallets,
write files or grant scanner/signing/broadcast authority.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys

from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
from wam_privacy_wallet.node.two_node_bounded_ancestry import (
    TwoNodeAncestryError, TwoNodeBoundedAncestry,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only bounded ancestry comparison of existing local regtest RPC peers",
    )
    for node in ("a", "b"):
        parser.add_argument(f"--node-{node}-host", required=True)
        parser.add_argument(f"--node-{node}-port", type=int, required=True)
        parser.add_argument(f"--node-{node}-rpc-user", required=True)
    parser.add_argument("--window-size", type=int, default=8)
    arguments = parser.parse_args(argv)

    try:
        # Deny bad endpoints/port collisions/window BEFORE credentials
        # are requested or any network/socket attempt is made.
        a = LocalRegtestEndpoint(arguments.node_a_host, arguments.node_a_port)
        b = LocalRegtestEndpoint(arguments.node_b_host, arguments.node_b_port)
        if a == b:
            raise TwoNodeAncestryError("REGTEST_ANCESTRY_DUPLICATE_ENDPOINT")
        if not 1 <= arguments.window_size <= 16:
            raise TwoNodeAncestryError("REGTEST_ANCESTRY_WINDOW_DENIED")
        # Existing exact auth type validates username without transmitting.
        ExplicitRpcAuth(arguments.node_a_rpc_user, "VALIDATION_ONLY")
        ExplicitRpcAuth(arguments.node_b_rpc_user, "VALIDATION_ONLY")
        if not sys.stdin.isatty():
            raise TwoNodeAncestryError("REGTEST_ANCESTRY_TTY_REQUIRED")
        password_a = getpass.getpass("Node A disposable regtest RPC password: ")
        password_b = getpass.getpass("Node B disposable regtest RPC password: ")
        audit = TwoNodeBoundedAncestry(
            a, ExplicitRpcAuth(arguments.node_a_rpc_user, password_a),
            b, ExplicitRpcAuth(arguments.node_b_rpc_user, password_b),
        )
        result = audit.audit(window_size=arguments.window_size)
    except TwoNodeAncestryError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (ValueError, OSError, EOFError, KeyboardInterrupt):
        print("REGTEST_ANCESTRY_INPUT_DENIED", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
