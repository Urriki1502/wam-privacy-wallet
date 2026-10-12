"""Two-node regtest RPC-reported header-link consistency, without Core execution.

Operational sources are two real, independent, numeric-loopback authenticated
HTTP JSON-RPC transports. This checks what endpoints REPORT, not independent
PoW/consensus/cryptographic validity and not publisher/process identity.
"""
from __future__ import annotations

import re

from .attestation import RegtestIdentityError
from .core_profile import CoreProfileError, VerifiedCoreProfile
from .endpoint import LocalRegtestEndpoint
from .read_rpc import ExplicitRpcAuth, LocalReadOnlyRpc, LocalRpcError
from .regtest_gateway import LocalRegtestIdentityGateway

_HASH_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_WINDOW = 16


class TwoNodeHeaderLinkError(ValueError):
    """Fixed non-sensitive code; raw RPC content and passwords are never shown."""


class TwoNodeHeaderLinkAuditor:
    """Bounded, double-pass getblockhash + verbose getblockheader inspection."""

    __slots__ = ("_gate_a", "_gate_b", "_rpc_a", "_rpc_b")

    def __init__(
        self,
        node_a: LocalRegtestEndpoint, auth_a: ExplicitRpcAuth,
        node_b: LocalRegtestEndpoint, auth_b: ExplicitRpcAuth,
    ) -> None:
        if (type(node_a) is not LocalRegtestEndpoint
                or type(node_b) is not LocalRegtestEndpoint
                or type(auth_a) is not ExplicitRpcAuth
                or type(auth_b) is not ExplicitRpcAuth):
            raise TwoNodeHeaderLinkError("REGTEST_HEADER_ENDPOINT_DENIED")
        if node_a == node_b:
            raise TwoNodeHeaderLinkError("REGTEST_HEADER_DUPLICATE_ENDPOINT")
        try:
            self._gate_a = LocalRegtestIdentityGateway(node_a, auth_a, timeout=3)
            self._gate_b = LocalRegtestIdentityGateway(node_b, auth_b, timeout=3)
            self._rpc_a = LocalReadOnlyRpc(node_a, auth_a, timeout=3)
            self._rpc_b = LocalReadOnlyRpc(node_b, auth_b, timeout=3)
        except ValueError:
            raise TwoNodeHeaderLinkError("REGTEST_HEADER_ENDPOINT_DENIED") from None

    @staticmethod
    def _hash(value: object) -> str:
        if type(value) is not str or _HASH_RE.fullmatch(value) is None:
            raise TwoNodeHeaderLinkError("REGTEST_HEADER_HASH_DENIED")
        return value

    @classmethod
    def _validate_header(
        cls, raw: object, *, expected_hash: str, expected_height: int,
        expected_parent: str | None,
    ) -> None:
        if type(raw) is not dict:
            raise TwoNodeHeaderLinkError("REGTEST_HEADER_SHAPE_DENIED")
        if (cls._hash(raw.get("hash")) != expected_hash
                or type(raw.get("height")) is not int
                or raw["height"] != expected_height):
            raise TwoNodeHeaderLinkError("REGTEST_HEADER_IDENTITY_DENIED")
        if expected_height == 0:
            # Bitcoin-compatible genesis getblockheader(verbose=true) has no
            # previousblockhash; never accept a manufactured genesis parent.
            if "previousblockhash" in raw:
                raise TwoNodeHeaderLinkError("REGTEST_HEADER_GENESIS_PARENT_DENIED")
        elif cls._hash(raw.get("previousblockhash")) != expected_parent:
            raise TwoNodeHeaderLinkError("REGTEST_HEADER_PARENT_DENIED")

    @staticmethod
    def _same_chain(a: VerifiedCoreProfile, b: VerifiedCoreProfile) -> bool:
        return (
            a.identity.genesis == b.identity.genesis
            and a.identity.height == b.identity.height
            and a.identity.best_block_hash == b.identity.best_block_hash
        )

    def audit(self, *, window_size: int = 8) -> dict[str, object]:
        """Double-read a bounded window and verify reported parent hash edges.

        At window start >0 the expected parent is the separately observed
        getblockhash(start-1), not an unanchored object from a header reply.
        Each full pass is bracketed with fresh node profile checks. Strict
        pass-to-pass tuples reject observable ABA-free history changes.
        """
        if type(window_size) is not int or not 1 <= window_size <= _MAX_WINDOW:
            raise TwoNodeHeaderLinkError("REGTEST_HEADER_WINDOW_DENIED")
        try:
            baseline_a = self._gate_a.probe_core_profile()
            baseline_b = self._gate_b.probe_core_profile()
            if not self._same_chain(baseline_a, baseline_b):
                raise TwoNodeHeaderLinkError("REGTEST_HEADER_PEER_DIVERGENCE")
            height = baseline_a.identity.height
            start = max(0, height - window_size + 1)
            seen: tuple[tuple[str, str | None], ...] | None = None

            for _ in range(2):
                expected_parent: str | None = None
                if start > 0:
                    a = self._hash(self._rpc_a.call("getblockhash", [start - 1]))
                    b = self._hash(self._rpc_b.call("getblockhash", [start - 1]))
                    if a != b:
                        raise TwoNodeHeaderLinkError("REGTEST_HEADER_PEER_DIVERGENCE")
                    expected_parent = a

                observed: list[tuple[str, str | None]] = []
                for block_height in range(start, height + 1):
                    a = self._hash(self._rpc_a.call("getblockhash", [block_height]))
                    b = self._hash(self._rpc_b.call("getblockhash", [block_height]))
                    if a != b:
                        raise TwoNodeHeaderLinkError("REGTEST_HEADER_PEER_DIVERGENCE")
                    for rpc in (self._rpc_a, self._rpc_b):
                        raw = rpc.call("getblockheader", [a, True])
                        self._validate_header(
                            raw, expected_hash=a, expected_height=block_height,
                            expected_parent=expected_parent,
                        )
                    observed.append((a, expected_parent))
                    expected_parent = a
                current = tuple(observed)
                if (current[-1][0] != baseline_a.identity.best_block_hash
                        or (start == 0 and current[0][0] != baseline_a.identity.genesis)):
                    raise TwoNodeHeaderLinkError("REGTEST_HEADER_ANCHOR_DENIED")
                if seen is not None and current != seen:
                    raise TwoNodeHeaderLinkError("REGTEST_HEADER_CHANGED_DURING_READ")
                seen = current
                if (self._gate_a.probe_core_profile() != baseline_a
                        or self._gate_b.probe_core_profile() != baseline_b):
                    raise TwoNodeHeaderLinkError("REGTEST_HEADER_MOVED_DURING_READ")
        except TwoNodeHeaderLinkError:
            raise
        except (RegtestIdentityError, CoreProfileError, LocalRpcError,
                OSError, TimeoutError, ValueError):
            raise TwoNodeHeaderLinkError("REGTEST_HEADER_RPC_DENIED") from None

        return {
            "status": "UNTRUSTED_TWO_NODE_RPC_HEADER_LINKS_ONLY",
            "height": height,
            "window_start": start,
            "window_count": height - start + 1,
            "independent_rpc_endpoints": 2,
            "header_link_read_passes": 2,
            "rpc_reported_parent_links_match": True,
            "genuine_core_processes_verified": False,
            "cryptographic_headers_verified": False,
            "block_parent_links_verified": False,
            "real_two_node_regtest_qualified": False,
            "scanner_enabled": False,
            "wallet_ready": False,
            "signing_allowed": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
        }
