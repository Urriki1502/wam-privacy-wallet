"""Two-node regtest chain-transition observation over REAL localhost JSON-RPC.

No callback-injected operational RPC, mock data, Core launch, wallet, keys,
scanner, signing, broadcast, persistence or external network. Responses are
UNTRUSTED snapshots: matched peer replies do not attest binary/process identity
and no result grants execution or wallet authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import re
import time

from .attestation import RegtestIdentityError
from .core_profile import CoreProfileError
from .endpoint import LocalRegtestEndpoint
from .read_rpc import ExplicitRpcAuth, LocalReadOnlyRpc, LocalRpcError
from .regtest_gateway import LocalRegtestIdentityGateway

_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class RegtestTransitionError(ValueError):
    """Fixed redacted codes, never response bodies, hashes or credentials."""


@dataclass(frozen=True, slots=True)
class _PairSnapshot:
    height: int
    tip: str
    parent: str


class TwoNodeLiveTransitionObserver:
    """Bounded read-only observation of already-running local RPC endpoints."""

    __slots__ = ("_gateway_a", "_gateway_b", "_rpc_a", "_rpc_b")

    def __init__(
        self,
        node_a: LocalRegtestEndpoint, auth_a: ExplicitRpcAuth,
        node_b: LocalRegtestEndpoint, auth_b: ExplicitRpcAuth,
    ) -> None:
        if (type(node_a) is not LocalRegtestEndpoint
                or type(node_b) is not LocalRegtestEndpoint
                or type(auth_a) is not ExplicitRpcAuth
                or type(auth_b) is not ExplicitRpcAuth):
            raise RegtestTransitionError("REGTEST_TRANSITION_ENDPOINT_DENIED")
        if node_a == node_b:
            raise RegtestTransitionError("REGTEST_TRANSITION_DUPLICATE_ENDPOINT")
        try:
            self._gateway_a = LocalRegtestIdentityGateway(node_a, auth_a, timeout=3)
            self._gateway_b = LocalRegtestIdentityGateway(node_b, auth_b, timeout=3)
            self._rpc_a = LocalReadOnlyRpc(node_a, auth_a, timeout=3)
            self._rpc_b = LocalReadOnlyRpc(node_b, auth_b, timeout=3)
        except ValueError:
            raise RegtestTransitionError("REGTEST_TRANSITION_ENDPOINT_DENIED") from None

    @staticmethod
    def _hash(value: object) -> str:
        if type(value) is not str or _HASH.fullmatch(value) is None:
            raise RegtestTransitionError("REGTEST_TRANSITION_HASH_DENIED")
        return value

    def _capture(self) -> _PairSnapshot:
        """Independently sample two local nodes and bracket their chain state."""
        first_a = self._gateway_a.probe_core_profile()
        first_b = self._gateway_b.probe_core_profile()
        ia, ib = first_a.identity, first_b.identity
        if (ia.genesis != ib.genesis or ia.height != ib.height
                or ia.best_block_hash != ib.best_block_hash):
            raise RegtestTransitionError("REGTEST_TRANSITION_PEER_DIVERGENCE")
        height, tip = ia.height, ia.best_block_hash
        expected_parent = ia.genesis if height == 0 else None
        pa = (expected_parent if height == 0
              else self._hash(self._rpc_a.call("getblockhash", [height - 1])))
        pb = (expected_parent if height == 0
              else self._hash(self._rpc_b.call("getblockhash", [height - 1])))
        ca = self._hash(self._rpc_a.call("getblockhash", [height]))
        cb = self._hash(self._rpc_b.call("getblockhash", [height]))
        if pa != pb or ca != cb or ca != tip:
            raise RegtestTransitionError("REGTEST_TRANSITION_ANCESTRY_DIVERGENCE")
        if (self._gateway_a.probe_core_profile() != first_a
                or self._gateway_b.probe_core_profile() != first_b):
            raise RegtestTransitionError("REGTEST_TRANSITION_MOVED_DURING_READ")
        if (self._hash(self._rpc_a.call("getblockhash", [height])) != tip
                or self._hash(self._rpc_b.call("getblockhash", [height])) != tip):
            raise RegtestTransitionError("REGTEST_TRANSITION_MOVED_DURING_READ")
        if height:
            if (self._hash(self._rpc_a.call("getblockhash", [height - 1])) != pa
                    or self._hash(self._rpc_b.call("getblockhash", [height - 1])) != pb):
                raise RegtestTransitionError("REGTEST_TRANSITION_MOVED_DURING_READ")
        return _PairSnapshot(height, tip, pa)

    def observe(self, *, interval_seconds: float = 0) -> dict[str, object]:
        """Observe two live snapshots; classify extension or reorg as non-authority.

        This does not cause a fork/reorg. Observation interval is bounded,
        with no scheduler/background work. In real operation the operator
        coordinates a regtest event on independently approved node processes.
        """
        if (type(interval_seconds) not in (int, float)
                or not math.isfinite(interval_seconds)
                or not 0 <= interval_seconds <= 5):
            raise RegtestTransitionError("REGTEST_TRANSITION_INTERVAL_DENIED")
        try:
            before = self._capture()
            if interval_seconds:
                time.sleep(interval_seconds)
            after = self._capture()
            if after.height == before.height and after.tip == before.tip:
                if after.parent != before.parent:
                    raise RegtestTransitionError("REGTEST_TRANSITION_PARENT_CHANGED")
                transition = "UNCHANGED"
            elif after.height <= before.height:
                transition = "REORG_RESCAN_REQUIRED"
            else:
                # A higher tip alone does not prove extension: re-read the
                # *old* height on BOTH nodes to detect a fork buried below.
                prior_a = self._hash(self._rpc_a.call("getblockhash", [before.height]))
                prior_b = self._hash(self._rpc_b.call("getblockhash", [before.height]))
                if prior_a != prior_b:
                    raise RegtestTransitionError("REGTEST_TRANSITION_PEER_DIVERGENCE")
                # The newly sampled chain must remain stable throughout the
                # ancestral comparison, or this report could mix two epochs.
                stable = self._capture()
                if stable != after:
                    raise RegtestTransitionError("REGTEST_TRANSITION_MOVED_DURING_READ")
                transition = (
                    "EXTENSION" if prior_a == before.tip
                    else "REORG_RESCAN_REQUIRED"
                )
        except RegtestTransitionError:
            raise
        except (RegtestIdentityError, CoreProfileError, LocalRpcError,
                ValueError, OSError, TimeoutError):
            raise RegtestTransitionError("REGTEST_TRANSITION_RPC_DENIED") from None
        return {
            "status": "UNTRUSTED_TWO_NODE_REGTEST_CHAIN_OBSERVATION",
            "transition": transition,
            "height_before": before.height,
            "height_after": after.height,
            "reorg_observed": transition == "REORG_RESCAN_REQUIRED",
            "requires_rescan": transition == "REORG_RESCAN_REQUIRED",
            "same_reported_chain_after": True,
            "transport": "TWO_NUMERIC_LOOPBACK_RPC",
            "genuine_core_processes_verified": False,
            "two_node_regtest_qualified": False,
            "scanner_enabled": False,
            "wallet_ready": False,
            "signing_allowed": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
        }
