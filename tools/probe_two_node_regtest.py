"""Compare two ALREADY-RUNNING isolated WAM regtest RPC endpoints.

Real socket-backed reads, not injected mock callbacks. This is read-only
research: observing matching chain tips cannot authenticate WAM Core binaries,
prove two independent processes, or grant wallet/scanner/spending authority.
"""
from __future__ import annotations

import argparse
import getpass
import json
import re
import sys

from wam_privacy_wallet.integrations.regtest_scanner_wire import (
    RegtestScannerReadBridge, RegtestScannerWireError,
)
from wam_privacy_wallet.node.attestation import RegtestIdentityError
from wam_privacy_wallet.node.core_profile import CoreProfileError
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth, LocalReadOnlyRpc, LocalRpcError
from wam_privacy_wallet.node.regtest_gateway import LocalRegtestIdentityGateway


_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class TwoNodeRegtestProbeError(ValueError):
    """Fixed denial code; never carries a secret or arbitrary RPC response."""


def probe_two_existing_regtest(
    *,
    node_a_host: str, node_a_port: int, node_a_auth: ExplicitRpcAuth,
    node_b_host: str, node_b_port: int, node_b_auth: ExplicitRpcAuth,
    block_height: int | None = None,
) -> dict[str, object]:
    """Perform real loopback RPC reads on both endpoints; never start Core.

    The first and final identity/profile observations enclose actual read-only
    mempool requests on both nodes. Mismatches fail closed. Even success is
    explicitly NOT two-node Core qualification or a scanner authorization.
    """
    if block_height is not None and (type(block_height) is not int or not 1 <= block_height <= 100_000_000):
        raise TwoNodeRegtestProbeError("TWO_NODE_HEIGHT_DENIED")
    try:
        endpoint_a = LocalRegtestEndpoint(node_a_host, node_a_port)
        endpoint_b = LocalRegtestEndpoint(node_b_host, node_b_port)
        if endpoint_a == endpoint_b:
            raise TwoNodeRegtestProbeError("TWO_NODE_ENDPOINTS_MUST_DIFFER")
        if type(node_a_auth) is not ExplicitRpcAuth or type(node_b_auth) is not ExplicitRpcAuth:
            raise TwoNodeRegtestProbeError("TWO_NODE_AUTH_REQUIRED")

        gateway_a = LocalRegtestIdentityGateway(endpoint_a, node_a_auth, timeout=3)
        gateway_b = LocalRegtestIdentityGateway(endpoint_b, node_b_auth, timeout=3)
        before_a = gateway_a.probe_core_profile()
        before_b = gateway_b.probe_core_profile()
        if (
            before_a.identity.height != before_b.identity.height
            or before_a.identity.best_block_hash != before_b.identity.best_block_hash
            or before_a.identity.genesis != before_b.identity.genesis
        ):
            raise TwoNodeRegtestProbeError("TWO_NODE_CHAIN_DIVERGED")

        bridge_a = RegtestScannerReadBridge(endpoint_a, node_a_auth, timeout=3)
        bridge_b = RegtestScannerReadBridge(endpoint_b, node_b_auth, timeout=3)
        anchors_a = anchors_b = None
        if block_height is None:
            sample_a, sample_b = bridge_a.read_mempool(), bridge_b.read_mempool()
        else:
            if block_height > before_a.identity.height:
                raise TwoNodeRegtestProbeError("TWO_NODE_HEIGHT_AHEAD")
            # Each bridge derives its block parent directly from live RPC and
            # validates before/after state. Never trust a user-supplied hash.
            sample_a = bridge_a.read_confirmed(block_height)
            sample_b = bridge_b.read_confirmed(block_height)
            rpc_a = LocalReadOnlyRpc(endpoint_a, node_a_auth, timeout=3)
            rpc_b = LocalReadOnlyRpc(endpoint_b, node_b_auth, timeout=3)

            def anchors(rpc: LocalReadOnlyRpc) -> tuple[str, str]:
                items = (rpc.call("getblockhash", [block_height - 1]),
                         rpc.call("getblockhash", [block_height]))
                if any(type(value) is not str or _HASH.fullmatch(value) is None
                       for value in items):
                    raise TwoNodeRegtestProbeError("TWO_NODE_ANCESTRY_INVALID")
                return items

            anchors_a, anchors_b = anchors(rpc_a), anchors(rpc_b)
            if anchors_a != anchors_b:
                raise TwoNodeRegtestProbeError("TWO_NODE_ANCESTRY_DIVERGED")
        after_a = gateway_a.probe_core_profile()
        after_b = gateway_b.probe_core_profile()
        if block_height is not None:
            if anchors(rpc_a) != anchors_a or anchors(rpc_b) != anchors_b:
                raise TwoNodeRegtestProbeError("TWO_NODE_ANCESTRY_MOVED")
        if before_a != after_a or before_b != after_b:
            raise TwoNodeRegtestProbeError("TWO_NODE_TIP_CHANGED")
        if any(
            flag is not False
            for sample in (sample_a, sample_b)
            for flag in (sample.scanner_enabled, sample.wallet_ready, sample.chain_identity_verified)
        ):
            raise TwoNodeRegtestProbeError("TWO_NODE_AUTHORITY_DENIED")
    except TwoNodeRegtestProbeError:
        raise
    except (
        RegtestIdentityError, CoreProfileError, LocalRpcError,
        RegtestScannerWireError, ValueError,
    ):
        raise TwoNodeRegtestProbeError("TWO_NODE_RPC_DENIED") from None

    return {
        "status": "TWO_ENDPOINT_REGTEST_UNTRUSTED_READ_ONLY",
        "height": before_a.identity.height,
        "same_reported_tip": True,
        "mode": "mempool" if block_height is None else "confirmed",
        "node_a_mempool_count": sample_a.item_count if block_height is None else None,
        "node_b_mempool_count": sample_b.item_count if block_height is None else None,
        "node_a_block_tx_count": sample_a.item_count if block_height is not None else None,
        "node_b_block_tx_count": sample_b.item_count if block_height is not None else None,
        "transport": "NUMERIC_LOOPBACK_ONLY",
        "genuine_core_binary_verified": False,
        "independent_processes_verified": False,
        "real_two_node_regtest_qualified": False,
        "scanner_enabled": False,
        "wallet_ready": False,
        "signing_allowed": False,
        "broadcast_allowed": False,
        "mainnet_allowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Two already-running localhost regtest RPC endpoints (read-only)",
    )
    for label in ("a", "b"):
        parser.add_argument(f"--node-{label}-host", required=True)
        parser.add_argument(f"--node-{label}-port", type=int, required=True)
        parser.add_argument(f"--node-{label}-rpc-user", required=True)
    parser.add_argument("--block-height", type=int)
    args = parser.parse_args(argv)
    try:
        # Validate both destinations before prompting for any credentials.
        a = LocalRegtestEndpoint(args.node_a_host, args.node_a_port)
        b = LocalRegtestEndpoint(args.node_b_host, args.node_b_port)
        if a == b:
            raise TwoNodeRegtestProbeError("TWO_NODE_ENDPOINTS_MUST_DIFFER")
        if not sys.stdin.isatty():
            raise TwoNodeRegtestProbeError("TWO_NODE_INTERACTIVE_TTY_REQUIRED")
        first_secret = getpass.getpass("Node A disposable regtest RPC password: ")
        second_secret = getpass.getpass("Node B disposable regtest RPC password: ")
        report = probe_two_existing_regtest(
            node_a_host=a.host, node_a_port=a.port,
            node_a_auth=ExplicitRpcAuth(args.node_a_rpc_user, first_secret),
            node_b_host=b.host, node_b_port=b.port,
            node_b_auth=ExplicitRpcAuth(args.node_b_rpc_user, second_secret),
            block_height=args.block_height,
        )
    except TwoNodeRegtestProbeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (ValueError, EOFError, KeyboardInterrupt):
        print("TWO_NODE_INPUT_DENIED", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
