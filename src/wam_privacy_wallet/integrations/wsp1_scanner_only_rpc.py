"""Bounded scan-only WSP-1 RPC contract for explicit LOCAL regtest sessions.

WSP-1 Scanner.sync() calls rpc.attest() and rpc.call(...). This adapter exposes
only the exact READ surface required by that API. It NEVER imports/runs WSP,
opens wallet stores, resolves arbitrary URLs, starts Core, signs or broadcasts.
Local identity probes describe reported chain state, not authenticated Core.
"""
from __future__ import annotations

import re

from .regtest_scanner_wire import _ScannerOnlyWire, RegtestScannerWireError
from .wam_transaction_shape import validate_wam_transaction, WamTransactionShapeError
from wam_privacy_wallet.node.attestation import RegtestIdentityError
from wam_privacy_wallet.node.core_profile import CoreProfileError, VerifiedCoreProfile
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth, LocalReadOnlyRpc, LocalRpcError
from wam_privacy_wallet.node.regtest_gateway import LocalRegtestIdentityGateway

_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDENTITY = frozenset(("getblockhash", "getblockcount", "getbestblockhash"))
_BLOCK = frozenset(("getblock",))
_MEMPOOL = frozenset(("getrawmempool", "getrawtransaction"))
_MAX_HEIGHT = 100_000_000
# Exact scanner limits at pinned WSP-1 commit ac55f13423620252bdbf848c7e8a280c3b84721e:
# wam_sp.limits.DEFAULT.max_block_transactions = 10000,
# max_inputs = 2048, max_outputs = 4096, Scanner.sync_mempool <= 10000.
# Reject upstream-invalid records at the RPC edge, before scanner DB work.
_MAX_BLOCK_TX = 10_000
_MAX_MEMPOOL_TX = 10_000
_MAX_TX_INPUTS = 2_048
_MAX_TX_OUTPUTS = 4_096


class WspScannerRpcError(RuntimeError):
    """Stable, redacted refusal. Never interpolate node responses or auth."""


class Wsp1ScannerOnlyRpc:
    """Regtest read surface compatible with WSP-1 Scanner.sync's RPC shape.

    Creation grants nothing: a fresh attest() is mandatory. Every call checks
    current reported profile before AND after the operation; the first change
    poisons the session. An attacker-controlled local RPC service may still lie
    about all observations, so no authoritative scan/funds claims are returned.
    Explicit include_mempool=True adds *only* two transaction READ methods.
    """

    __slots__ = ("_gateway", "_identity", "_scanner", "_baseline", "_mempool")

    def __init__(
        self,
        endpoint: LocalRegtestEndpoint,
        auth: ExplicitRpcAuth,
        *,
        timeout: float = 3.0,
        include_mempool: bool = False,
    ) -> None:
        if type(include_mempool) is not bool:
            raise ValueError("WSP_SCAN_MEMPOOL_SCOPE_DENIED")
        self._gateway = LocalRegtestIdentityGateway(endpoint, auth, timeout=timeout)
        self._identity = LocalReadOnlyRpc(endpoint, auth, timeout=timeout)
        self._scanner = _ScannerOnlyWire(
            endpoint, auth, timeout=timeout,
            allow_transaction_lookup=include_mempool,
        )
        self._baseline: VerifiedCoreProfile | None = None
        self._mempool = include_mempool

    def _fresh(self) -> VerifiedCoreProfile:
        try:
            return self._gateway.probe_core_profile()
        except (RegtestIdentityError, CoreProfileError, LocalRpcError):
            self._baseline = None
            raise WspScannerRpcError("WSP_SCAN_PROFILE_DENIED") from None

    def attest(self) -> None:
        """Fresh chain/profile observation, never a durable Core attestation."""
        profile = self._fresh()
        if self._baseline is not None and self._baseline != profile:
            self._baseline = None
            raise WspScannerRpcError("WSP_SCAN_CHAIN_DRIFT")
        self._baseline = profile

    def _params(self, method: object, params: object) -> list[object]:
        if type(method) is not str or method not in (_IDENTITY | _BLOCK | _MEMPOOL):
            raise WspScannerRpcError("WSP_SCAN_METHOD_DENIED")
        if method in _MEMPOOL and not self._mempool:
            raise WspScannerRpcError("WSP_SCAN_MEMPOOL_DENIED")
        if params is None:
            params = []
        if type(params) is not list:
            raise WspScannerRpcError("WSP_SCAN_PARAMS_DENIED")
        if method == "getblockhash":
            if (len(params) != 1 or type(params[0]) is not int
                    or not 0 <= params[0] <= _MAX_HEIGHT):
                raise WspScannerRpcError("WSP_SCAN_PARAMS_DENIED")
        elif method == "getblock":
            if (len(params) != 2 or type(params[0]) is not str
                    or _HASH.fullmatch(params[0]) is None
                    or type(params[1]) is not int or params[1] != 3):
                raise WspScannerRpcError("WSP_SCAN_PARAMS_DENIED")
        elif method == "getrawtransaction":
            if (len(params) != 2 or type(params[0]) is not str
                    or _HASH.fullmatch(params[0]) is None
                    or type(params[1]) is not int or params[1] not in (1, 2)):
                raise WspScannerRpcError("WSP_SCAN_PARAMS_DENIED")
        elif params:
            raise WspScannerRpcError("WSP_SCAN_PARAMS_DENIED")
        return params

    @staticmethod
    def _validate(method: str, params: list[object], result: object) -> None:
        if method in ("getbestblockhash", "getblockhash"):
            if type(result) is not str or _HASH.fullmatch(result) is None:
                raise WspScannerRpcError("WSP_SCAN_REPLY_DENIED")
        elif method == "getblockcount":
            if type(result) is not int or not 0 <= result <= _MAX_HEIGHT:
                raise WspScannerRpcError("WSP_SCAN_REPLY_DENIED")
        elif method == "getblock":
            if (type(result) is not dict or result.get("hash") != params[0]
                    or type(result.get("tx")) is not list
                    or not 1 <= len(result["tx"]) <= _MAX_BLOCK_TX):
                raise WspScannerRpcError("WSP_SCAN_REPLY_DENIED")
            txids = [tx.get("txid") if type(tx) is dict else None
                     for tx in result["tx"]]
            if (any(type(h) is not str or _HASH.fullmatch(h) is None for h in txids)
                    or len(set(txids)) != len(txids)):
                raise WspScannerRpcError("WSP_SCAN_REPLY_DENIED")
            height = result.get("height")
            if (type(height) is not int or not 0 <= height <= _MAX_HEIGHT
                    or (height > 0 and (type(result.get("previousblockhash")) is not str
                        or _HASH.fullmatch(result["previousblockhash"]) is None))):
                raise WspScannerRpcError("WSP_SCAN_REPLY_DENIED")
            try:
                for index, tx in enumerate(result["tx"]):
                    if validate_wam_transaction(tx, require_prevouts=True) != (index == 0):
                        raise WspScannerRpcError("WSP_SCAN_REPLY_DENIED")
            except WamTransactionShapeError:
                raise WspScannerRpcError("WSP_SCAN_REPLY_DENIED") from None
        elif method == "getrawmempool":
            if (type(result) is not list or len(result) > _MAX_MEMPOOL_TX
                    or any(type(h) is not str or _HASH.fullmatch(h) is None
                           for h in result) or len(set(result)) != len(result)):
                raise WspScannerRpcError("WSP_SCAN_REPLY_DENIED")
        elif method == "getrawtransaction":
            if (type(result) is not dict or result.get("txid") != params[0]
                    or type(result.get("vin")) is not list
                    or type(result.get("vout")) is not list
                    or not 1 <= len(result["vin"]) <= _MAX_TX_INPUTS
                    or not 1 <= len(result["vout"]) <= _MAX_TX_OUTPUTS):
                raise WspScannerRpcError("WSP_SCAN_REPLY_DENIED")
            try:
                validate_wam_transaction(result, require_prevouts=False)
            except WamTransactionShapeError:
                raise WspScannerRpcError("WSP_SCAN_REPLY_DENIED") from None

    def call(self, method: str, params: list[object] | None = None) -> object:
        """Bounded local HTTP only; rejects writes before any network request."""
        validated = self._params(method, params)
        if self._baseline is None:
            raise WspScannerRpcError("WSP_SCAN_ATTEST_REQUIRED")
        if self._fresh() != self._baseline:
            self._baseline = None
            raise WspScannerRpcError("WSP_SCAN_CHAIN_DRIFT")
        try:
            if method in _IDENTITY:
                response = self._identity.call(method, validated)
            else:
                response = self._scanner.call(method, validated)
            self._validate(method, validated, response)
        except (LocalRpcError, RegtestScannerWireError):
            self._baseline = None
            raise WspScannerRpcError("WSP_SCAN_TRANSPORT_DENIED") from None
        except WspScannerRpcError:
            self._baseline = None
            raise
        if self._fresh() != self._baseline:
            self._baseline = None
            raise WspScannerRpcError("WSP_SCAN_CHAIN_DRIFT")
        return response
