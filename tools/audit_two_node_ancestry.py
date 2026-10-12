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
from wam_privacy_wallet.node.two_node_header_links import (
    TwoNodeHeaderLinkError, TwoNodeHeaderLinkAuditor,
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
    parser.add_argument("--include-header-links", action="store_true")
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
        auth_a = ExplicitRpcAuth(arguments.node_a_rpc_user, password_a)
        auth_b = ExplicitRpcAuth(arguments.node_b_rpc_user, password_b)
        audit = TwoNodeBoundedAncestry(a, auth_a, b, auth_b)
        result = audit.audit(window_size=arguments.window_size)
        # Fail closed if a future library change accidentally introduces
        # or asserts operational authority in a review-only CLI response.
        forbidden = (
            "genuine_core_processes_verified",
            "block_parent_links_verified",
            "real_two_node_regtest_qualified",
            "scanner_enabled",
            "wallet_ready",
            "signing_allowed",
            "broadcast_allowed",
            "mainnet_allowed",
        )
        if (type(result) is not dict
                or result.get("status") != "UNTRUSTED_TWO_NODE_BOUNDED_ANCESTRY_ONLY"
                or any(result.get(field) is not False for field in forbidden)):
            raise TwoNodeAncestryError("REGTEST_ANCESTRY_AUTHORITY_DENIED")
        expected_ancestry_fields = {
            "status", "height", "window_start", "window_count",
            "independent_rpc_endpoints", "height_hash_read_passes",
            "reported_histories_agree", *forbidden,
        }
        if (set(result) != expected_ancestry_fields
                or type(result["height"]) is not int
                or type(result["window_start"]) is not int
                or type(result["window_count"]) is not int
                or not 1 <= result["window_count"] <= 16
                or result["window_start"] < 0
                or result["height"] - result["window_start"] + 1 != result["window_count"]
                or type(result["independent_rpc_endpoints"]) is not int
                or result["independent_rpc_endpoints"] != 2
                or type(result["height_hash_read_passes"]) is not int
                or result["height_hash_read_passes"] != 2
                or result["reported_histories_agree"] is not True):
            raise TwoNodeAncestryError("REGTEST_ANCESTRY_RECEIPT_DENIED")
        if arguments.include_header_links:
            # This is a SECOND non-atomic RPC observation, not a proof of
            # consensus or that both audit windows describe one chain epoch.
            try:
                header = TwoNodeHeaderLinkAuditor(a, auth_a, b, auth_b).audit(
                    window_size=arguments.window_size,
                )
            except TwoNodeHeaderLinkError:
                raise TwoNodeAncestryError("REGTEST_ANCESTRY_HEADER_RPC_DENIED") from None
            header_false = (*forbidden, "cryptographic_headers_verified")
            if (type(header) is not dict
                    or header.get("status") != "UNTRUSTED_TWO_NODE_RPC_HEADER_LINKS_ONLY"
                    or header.get("rpc_reported_parent_links_match") is not True
                    or any(header.get(field) is not False for field in header_false)):
                raise TwoNodeAncestryError("REGTEST_ANCESTRY_HEADER_AUTHORITY_DENIED")
            expected_header_fields = {
                "status", "height", "window_start", "window_count",
                "independent_rpc_endpoints", "header_link_read_passes",
                "rpc_reported_parent_links_match", *header_false,
            }
            if (set(header) != expected_header_fields
                    or type(header["independent_rpc_endpoints"]) is not int
                    or header["independent_rpc_endpoints"] != 2
                    or type(header["header_link_read_passes"]) is not int
                    or header["header_link_read_passes"] != 2):
                raise TwoNodeAncestryError("REGTEST_ANCESTRY_HEADER_AUTHORITY_DENIED")
            for key in ("height", "window_start", "window_count"):
                if (type(header.get(key)) is not int
                        or type(result.get(key)) is not int
                        or header[key] != result[key]):
                    raise TwoNodeAncestryError("REGTEST_ANCESTRY_HEADER_EPOCH_DENIED")
            result = {
                **result,
                "status": "UNTRUSTED_TWO_NODE_HEADER_AND_ANCESTRY_REVIEW_ONLY",
                "rpc_reported_parent_links_match": True,
                "cryptographic_headers_verified": False,
                "same_epoch_proven": False,
            }
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
