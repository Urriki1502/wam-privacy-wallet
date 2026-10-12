"""Cross-check a bounded regtest chain-height window over two REAL local RPCs.

Both operational transports are constructed internally from explicit numeric
loopback endpoints and auth, not caller callbacks. Reports are diagnostic
only: matching RPC statements are not consensus proof, process identity,
parent-link validation, scanner authority or launch permission.
"""
from __future__ import annotations

import re

from .attestation import RegtestIdentityError
from .core_profile import CoreProfileError
from .endpoint import LocalRegtestEndpoint
from .read_rpc import ExplicitRpcAuth, LocalReadOnlyRpc, LocalRpcError
from .regtest_gateway import LocalRegtestIdentityGateway

_SHA256_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_WINDOW = 16


class TwoNodeAncestryError(ValueError):
    """Fixed redacted error code: never a credential, block hash or RPC body."""


class TwoNodeBoundedAncestry:
    """Read bounded independent chain data from two already-running RPC nodes."""

    __slots__ = ("_first_profile", "_second_profile", "_first_rpc", "_second_rpc")

    def __init__(
        self,
        node_a: LocalRegtestEndpoint, auth_a: ExplicitRpcAuth,
        node_b: LocalRegtestEndpoint, auth_b: ExplicitRpcAuth,
    ) -> None:
        if (type(node_a) is not LocalRegtestEndpoint
                or type(node_b) is not LocalRegtestEndpoint
                or type(auth_a) is not ExplicitRpcAuth
                or type(auth_b) is not ExplicitRpcAuth):
            raise TwoNodeAncestryError("REGTEST_ANCESTRY_ENDPOINT_DENIED")
        if node_a == node_b:
            raise TwoNodeAncestryError("REGTEST_ANCESTRY_DUPLICATE_ENDPOINT")
        try:
            self._first_profile = LocalRegtestIdentityGateway(
                node_a, auth_a, timeout=3,
            )
            self._second_profile = LocalRegtestIdentityGateway(
                node_b, auth_b, timeout=3,
            )
            self._first_rpc = LocalReadOnlyRpc(node_a, auth_a, timeout=3)
            self._second_rpc = LocalReadOnlyRpc(node_b, auth_b, timeout=3)
        except ValueError:
            raise TwoNodeAncestryError("REGTEST_ANCESTRY_ENDPOINT_DENIED") from None

    @staticmethod
    def _hash(value: object) -> str:
        if type(value) is not str or _SHA256_HASH.fullmatch(value) is None:
            raise TwoNodeAncestryError("REGTEST_ANCESTRY_HASH_DENIED")
        return value

    def audit(self, *, window_size: int = 8) -> dict[str, object]:
        """Read each height twice on each node, bracketed by full Core profiles.

        Deny any disagreement between nodes, any changed history in the
        audit window, and any changed profiles. No rpc method besides the
        established read-only getblockhash/profile methods is available.
        """
        if type(window_size) is not int or not 1 <= window_size <= _MAX_WINDOW:
            raise TwoNodeAncestryError("REGTEST_ANCESTRY_WINDOW_DENIED")
        try:
            first = self._first_profile.probe_core_profile()
            second = self._second_profile.probe_core_profile()
            if (first.identity.genesis != second.identity.genesis
                    or first.identity.height != second.identity.height
                    or first.identity.best_block_hash != second.identity.best_block_hash):
                raise TwoNodeAncestryError("REGTEST_ANCESTRY_CHAIN_DIVERGENCE")
            height = first.identity.height
            start = max(0, height - window_size + 1)
            heights = range(start, height + 1)
            seen: tuple[str, ...] | None = None
            # Two independent full-window passes detect ordinary mutations
            # hidden by a stable tip; each pass cross-checks both nodes.
            for _ in range(2):
                observed: list[str] = []
                for h in heights:
                    a = self._hash(self._first_rpc.call("getblockhash", [h]))
                    b = self._hash(self._second_rpc.call("getblockhash", [h]))
                    if a != b:
                        raise TwoNodeAncestryError("REGTEST_ANCESTRY_PEER_DIVERGENCE")
                    observed.append(a)
                current = tuple(observed)
                if (current[-1] != first.identity.best_block_hash
                        or (start == 0 and current[0] != first.identity.genesis)):
                    raise TwoNodeAncestryError("REGTEST_ANCESTRY_ANCHOR_DENIED")
                if seen is not None and seen != current:
                    raise TwoNodeAncestryError("REGTEST_ANCESTRY_CHANGED_DURING_READ")
                seen = current
                if (self._first_profile.probe_core_profile() != first
                        or self._second_profile.probe_core_profile() != second):
                    raise TwoNodeAncestryError("REGTEST_ANCESTRY_MOVED_DURING_READ")
        except TwoNodeAncestryError:
            raise
        except (RegtestIdentityError, CoreProfileError, LocalRpcError,
                OSError, ValueError, TimeoutError):
            raise TwoNodeAncestryError("REGTEST_ANCESTRY_RPC_DENIED") from None
        return {
            "status": "UNTRUSTED_TWO_NODE_BOUNDED_ANCESTRY_ONLY",
            "height": height,
            "window_start": start,
            "window_count": height - start + 1,
            "independent_rpc_endpoints": 2,
            "height_hash_read_passes": 2,
            "reported_histories_agree": True,
            "genuine_core_processes_verified": False,
            "block_parent_links_verified": False,
            "real_two_node_regtest_qualified": False,
            "scanner_enabled": False,
            "wallet_ready": False,
            "signing_allowed": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
        }
