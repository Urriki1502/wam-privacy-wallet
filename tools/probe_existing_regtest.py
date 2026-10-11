"""Opt-in read-only diagnostic against an ALREADY RUNNING local WAM regtest RPC.

No Core subprocess, datadir/cookie/keys/wallet access, network peers, signing,
broadcast or mock fallback. Uses the real numeric-loopback scanner RPC bridge.
An authenticated response does NOT attest to genuine DEV-issued executable
bytes; Core binary #36 and actual two-node #9 remain review-blocked.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys

from wam_privacy_wallet.integrations.regtest_scanner_wire import (
    RegtestScannerReadBridge, RegtestScannerWireError,
)
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth


class RegtestLiveProbeError(ValueError):
    """Redacted, fixed denial. Never embeds an RPC credential or response."""


def probe_existing_regtest(
    *, host: str, port: int, auth: ExplicitRpcAuth,
    block_height: int | None = None, previous_block_hash: str | None = None,
) -> dict[str, object]:
    """Connect to an existing local node; return scalar-only NO-AUTHORITY status."""
    if (block_height is None) != (previous_block_hash is None):
        raise RegtestLiveProbeError("REGTEST_PROBE_BLOCK_PAIR_DENIED")
    try:
        endpoint = LocalRegtestEndpoint(host, port)
        bridge = RegtestScannerReadBridge(endpoint, auth, timeout=3)
        if block_height is None:
            observation = bridge.read_mempool()
        else:
            observation = bridge.read_confirmed(
                block_height, expected_previous_hash=previous_block_hash,
            )
    except (RegtestScannerWireError, ValueError):
        raise RegtestLiveProbeError("REGTEST_PROBE_DENIED") from None
    if (observation.scanner_enabled is not False
            or observation.wallet_ready is not False
            or observation.chain_identity_verified is not False):
        raise RegtestLiveProbeError("REGTEST_PROBE_AUTHORITY_DENIED")
    return {
        "status": "LOCAL_REGTEST_RPC_UNTRUSTED_READ_ONLY",
        "phase": observation.phase,
        "height": observation.height,
        "item_count": observation.item_count,
        "transport": "NUMERIC_LOOPBACK_ONLY",
        "binary_publisher_authenticated": False,
        "real_two_node_regtest_qualified": False,
        "scanner_enabled": False,
        "wallet_ready": False,
        "signing_allowed": False,
        "broadcast_allowed": False,
        "mainnet_allowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only WAM local regtest RPC, no WAM Core launch",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--rpc-user", required=True)
    parser.add_argument("--block-height", type=int)
    parser.add_argument("--previous-block-hash")
    arguments = parser.parse_args(argv)
    try:
        # Refuse noninteractive CI/pipes: do not accept RPC passwords via argv,
        # environment variables, config files, wallet datadirs or shell history.
        if not sys.stdin.isatty():
            raise RegtestLiveProbeError("REGTEST_PROBE_TERMINAL_REQUIRED")
        password = getpass.getpass("Disposable regtest RPC password: ")
        auth = ExplicitRpcAuth(arguments.rpc_user, password)
        report = probe_existing_regtest(
            host=arguments.host, port=arguments.port, auth=auth,
            block_height=arguments.block_height,
            previous_block_hash=arguments.previous_block_hash,
        )
    except RegtestLiveProbeError as err:
        print(str(err), file=sys.stderr)
        return 2
    except (ValueError, EOFError, KeyboardInterrupt):
        print("REGTEST_PROBE_INPUT_DENIED", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
