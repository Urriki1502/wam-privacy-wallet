"""Offline, side-effect-free validation of proposed WSP-1 scanner read RPCs.

This module contains NO network client, credential handling, scanner adapter,
wallet state, signing or broadcast functionality. A validated request is
NOT an authorization to contact a node, scan blocks or handle wallet data.

A future transport must separately enforce source provenance, user-owned local
node identity, fresh attestation, bounded responses, privacy and error policy.
This parser must not be grafted into the existing diagnostic LocalReadOnlyRpc
to silently widen that endpoint's allowlist.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MAX_BLOCK_HEIGHT = 100_000_000
_COMMON_READS = frozenset(
    {"getblockchaininfo", "getblockcount", "getbestblockhash", "getblockhash"}
)
_CONFIRMED_READS = _COMMON_READS | {"getblock"}
_MEMPOOL_READS = _COMMON_READS | {"getrawmempool", "getrawtransaction"}


class ScannerReadContractError(ValueError):
    """Stable, redacted validation error; never include untrusted inputs."""


@dataclass(frozen=True, slots=True)
class ScannerReadShape:
    """Validated request *shape*, with no authority or external side effects."""

    method: str
    params: tuple[object, ...]
    scope: Literal["confirmed", "mempool"]


def _hash256(value: object) -> bool:
    return type(value) is str and _HASH.fullmatch(value) is not None


def validate_scanner_read_shape(
    method: object, params: object = None, *, scope: str = "confirmed"
) -> ScannerReadShape:
    """Fail closed on unexpected scanner methods, scopes or parameter types.

    'confirmed' is restricted to chain identity + the WSP-1 getblock(...,3)
    shape; 'mempool' is separately opt-in and cannot fetch blocks. This policy
    cannot prove chain provenance, reply integrity, or permission to scan.
    """
    if type(scope) is not str or scope not in ("confirmed", "mempool"):
        raise ScannerReadContractError("SCAN_RPC_SCOPE_DENIED")
    if type(method) is not str:
        raise ScannerReadContractError("SCAN_RPC_METHOD_DENIED")

    allowed = _CONFIRMED_READS if scope == "confirmed" else _MEMPOOL_READS
    if method not in allowed:
        raise ScannerReadContractError("SCAN_RPC_METHOD_DENIED")

    if params is None:
        params = []
    if type(params) is not list:
        raise ScannerReadContractError("SCAN_RPC_PARAMS_INVALID")

    if method == "getblockhash":
        valid = (
            len(params) == 1
            and type(params[0]) is int
            and 0 <= params[0] <= _MAX_BLOCK_HEIGHT
        )
    elif method == "getblock":
        valid = (
            len(params) == 2
            and _hash256(params[0])
            and type(params[1]) is int
            and params[1] == 3
        )
    elif method == "getrawtransaction":
        valid = (
            len(params) == 2
            and _hash256(params[0])
            and type(params[1]) is int
            and params[1] in (1, 2)
        )
    else:
        valid = len(params) == 0

    if not valid:
        raise ScannerReadContractError("SCAN_RPC_PARAMS_INVALID")
    return ScannerReadShape(method=method, params=tuple(params), scope=scope)
