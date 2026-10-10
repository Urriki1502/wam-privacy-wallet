"""Read-only WAM regtest chain identity probe; no transport implementation.

All network I/O is delegated to a caller-supplied callback. It must be bound
separately to an authenticated user-owned WAM Core node before real use.
This module does not create a wallet, handle credentials, or open sockets.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from .endpoint import LocalRegtestEndpoint

# Network identity from the pinned WAM Core v0.1.11 WSP-1 regtest profile.
# Re-qualify this value against the chosen WAM Core binary before real-node use.
WAM_REGTEST_GENESIS = "b88f3d262f285e38e184f50bf3eea1c8e615486ae67d3d9eaf0976fbd6d3d30d"
_MAX_HEIGHT = 100_000_000
_HASH_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class RegtestIdentityError(RuntimeError):
    """A stable, non-sensitive status code, never an RPC exception message."""


@dataclass(frozen=True, slots=True)
class ChainIdentity:
    """Immutable attested chain identity snapshot; not a security attestation."""

    endpoint: LocalRegtestEndpoint
    genesis: str
    height: int
    best_block_hash: str


def _valid_hash(value: object) -> bool:
    return type(value) is str and _HASH_RE.fullmatch(value) is not None


class RegtestIdentityProbe:
    """Check a local regtest chain via a read-only, injected RPC call boundary.

    The callback must accept (method: str, params: list[object]). A callback
    that makes a remote connection would violate the external trust boundary;
    this class itself cannot enforce the transport/socket address.
    """

    def __init__(
        self,
        endpoint: LocalRegtestEndpoint,
        call: Callable[[str, list[object]], object],
    ) -> None:
        if type(endpoint) is not LocalRegtestEndpoint:
            raise ValueError("WAM_NODE_LOCAL_ENDPOINT_REQUIRED")
        if not callable(call):
            raise ValueError("WAM_NODE_CALL_REQUIRED")
        self._endpoint = endpoint
        self._call = call

    def _get(self, method: str, params: list[object]) -> object:
        # The only caller is probe(), with a fixed, read-only RPC method set.
        try:
            return self._call(method, params)
        except Exception:
            # RPC exceptions may include authentication details. Never echo.
            raise RegtestIdentityError("WAM_NODE_PROBE_TRANSPORT_ERROR") from None

    def probe(self) -> ChainIdentity:
        """Verify genesis and a stable tip using strictly read-only requests.

        Height/tip are re-read to fail closed on ordinary mid-probe reorgs.
        A malicious transport can still lie; real-node tests are mandatory.
        """
        genesis = self._get("getblockhash", [0])
        if not _valid_hash(genesis) or genesis != WAM_REGTEST_GENESIS:
            raise RegtestIdentityError("WAM_NODE_WRONG_GENESIS")

        height = self._get("getblockcount", [])
        if type(height) is not int or not 0 <= height <= _MAX_HEIGHT:
            raise RegtestIdentityError("WAM_NODE_INVALID_HEIGHT")

        tip = self._get("getbestblockhash", [])
        if not _valid_hash(tip):
            raise RegtestIdentityError("WAM_NODE_INVALID_TIP")

        at_height = self._get("getblockhash", [height])
        if not _valid_hash(at_height) or at_height != tip:
            raise RegtestIdentityError("WAM_NODE_INCONSISTENT_TIP")

        tip_after = self._get("getbestblockhash", [])
        height_after = self._get("getblockcount", [])
        if tip_after != tip or type(height_after) is not int or height_after != height:
            raise RegtestIdentityError("WAM_NODE_TIP_CHANGED")

        return ChainIdentity(self._endpoint, genesis, height, tip)
