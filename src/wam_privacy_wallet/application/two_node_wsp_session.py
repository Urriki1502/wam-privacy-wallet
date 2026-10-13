"""Real two-node regtest P2P gate around a genuine WSP Scanner RPC session.

Two already-running Core-shaped localhost endpoints only. Neither this module
nor its dependencies launch Core, use mock backends, sign or broadcast. Matching
localhost RPC replies do not authenticate WAM binaries or process isolation.
"""
from __future__ import annotations

from pathlib import Path

from wam_privacy_wallet.application.live_regtest_scanner import scan_existing_regtest
from wam_privacy_wallet.node.attestation import ChainIdentity
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
from wam_privacy_wallet.node.regtest_gateway import LocalRegtestIdentityGateway
from wam_privacy_wallet.node.two_node_p2p_readonly import TwoNodeP2PReadOnlyAudit


def same_reported_chain(a: ChainIdentity, b: ChainIdentity) -> bool:
    """Two distinct endpoints must never compare equal by endpoint identity."""
    return (
        type(a) is ChainIdentity and type(b) is ChainIdentity
        and a.endpoint != b.endpoint
        and a.genesis == b.genesis
        and a.height == b.height
        and a.best_block_hash == b.best_block_hash
    )


class TwoNodeWspSessionError(ValueError):
    """Fixed redacted denial; no address, wallet metadata or keys in errors."""


def scan_two_existing_regtest_nodes(
    source_root: Path, private_dir: Path, scan_password: bytes, *,
    node_a: LocalRegtestEndpoint, auth_a: ExplicitRpcAuth,
    node_b: LocalRegtestEndpoint, auth_b: ExplicitRpcAuth,
    node_a_p2p_port: int, node_b_p2p_port: int,
    user_consented: bool, acknowledge_unverified_binaries: bool,
    max_blocks: int = 16, history_limit: int | None = None,
    save_checkpoint: bool = False, restore_checkpoint: bool = False,
    receive_account_index: int | None = None,
    show_observed_balance: bool = False,
) -> dict[str, object]:
    """Bracket actual Scanner.sync with independent read-only P2P/chain probes.

    The only scanning endpoint is A; B provides an independently sampled
    reported chain and P2P topology. No returned evidence grants wallet
    authority, even when every observation agrees.
    """
    if (type(source_root) is not type(Path()) or not source_root.is_absolute()
            or type(private_dir) is not type(Path()) or not private_dir.is_absolute()
            or type(scan_password) is not bytes
            or not 12 <= len(scan_password) <= 1024
            or user_consented is not True
            or acknowledge_unverified_binaries is not True
            or type(node_a) is not LocalRegtestEndpoint
            or type(node_b) is not LocalRegtestEndpoint
            or node_a == node_b
            or type(auth_a) is not ExplicitRpcAuth
            or type(auth_b) is not ExplicitRpcAuth
            or auth_a == auth_b
            or type(node_a_p2p_port) is not int
            or type(node_b_p2p_port) is not int
            or len({node_a.port, node_b.port, node_a_p2p_port,
                    node_b_p2p_port}) != 4
            or node_a.host != "127.0.0.1" or node_b.host != "127.0.0.1"
            or type(max_blocks) is not int or not 1 <= max_blocks <= 16
            or (history_limit is not None and
                (type(history_limit) is not int or not 1 <= history_limit <= 100))
            or type(save_checkpoint) is not bool
            or type(restore_checkpoint) is not bool
            or (save_checkpoint and restore_checkpoint)
            or (receive_account_index is not None and (
                type(receive_account_index) is not int
                or not 0 <= receive_account_index < 16))
            or type(show_observed_balance) is not bool):
        raise TwoNodeWspSessionError("TWO_NODE_WSP_SCOPE_DENIED")
    try:
        topology = TwoNodeP2PReadOnlyAudit(
            node_a, auth_a, node_b, auth_b,
            node_a_p2p_port=node_a_p2p_port,
            node_b_p2p_port=node_b_p2p_port,
        )
        gateway_a = LocalRegtestIdentityGateway(node_a, auth_a, timeout=3)
        gateway_b = LocalRegtestIdentityGateway(node_b, auth_b, timeout=3)
        # This audit is actual socket I/O; a mock/synthetic runtime is never
        # selectable from application arguments.
        topology.audit()
        first_a = gateway_a.probe_core_profile()
        first_b = gateway_b.probe_core_profile()
        if not same_reported_chain(first_a.identity, first_b.identity):
            raise TwoNodeWspSessionError("TWO_NODE_WSP_CHAIN_DIVERGED")
        scan = scan_existing_regtest(
            source_root, private_dir, scan_password,
            endpoint=node_a, rpc_auth=auth_a,
            user_consented=True, acknowledge_unverified_binary=True,
            max_blocks=max_blocks, history_limit=history_limit,
            save_checkpoint=save_checkpoint,
            restore_checkpoint=restore_checkpoint,
            receive_account_index=receive_account_index,
            show_observed_balance=show_observed_balance,
        )
        if (type(scan) is not dict
                or scan.get("status") != "REAL_LOOPBACK_WSP_SCAN_UNQUALIFIED_CORE"
                or scan.get("core_binary_authenticated") is not False
                or scan.get("wallet_operational") is not False
                or scan.get("signer_enabled") is not False
                or scan.get("broadcast_allowed") is not False
                or scan.get("mainnet_allowed") is not False
                or scan.get("real_two_node_regtest_qualified") is not False
                or scan.get("chain_current") not in (True, False)
                or type(scan.get("tip_height")) is not int
                or (receive_account_index is not None and (
                    scan.get("chain_current") is not True
                    or type(scan.get("unqualified_receive_code")) is not str))
                or (show_observed_balance and (
                    scan.get("chain_current") is not True
                    or type(scan.get("unqualified_confirmed_atoms")) is not int))):

            raise TwoNodeWspSessionError("TWO_NODE_WSP_RECEIPT_DENIED")
        second_a = gateway_a.probe_core_profile()
        second_b = gateway_b.probe_core_profile()
        topology.audit()
        # Scanning against one snapshot while the other node changes is not
        # an accepted two-node session; require a retry with fresh RPC views.
        if (first_a != second_a or first_b != second_b
                or not same_reported_chain(second_a.identity, second_b.identity)
                or (scan["chain_current"] and
                    scan["tip_height"] != second_a.identity.height)):
            raise TwoNodeWspSessionError("TWO_NODE_WSP_MOVED_DENIED")
        if (receive_account_index is not None or show_observed_balance) and (
                scan["chain_current"] is not True
                or scan["tip_height"] != second_a.identity.height):
            raise TwoNodeWspSessionError("TWO_NODE_WSP_INCOMPLETE_DENIED")
        scan["status"] = "REAL_TWO_NODE_WSP_SCAN_UNQUALIFIED_BINARIES"
        scan["two_node_p2p_observed"] = True
        scan["two_node_reported_chain_agrees"] = True
        scan["independent_core_processes_verified"] = False
        scan["real_two_node_regtest_qualified"] = False
        return scan
    except TwoNodeWspSessionError:
        raise
    except Exception:
        raise TwoNodeWspSessionError("TWO_NODE_WSP_DENIED") from None
