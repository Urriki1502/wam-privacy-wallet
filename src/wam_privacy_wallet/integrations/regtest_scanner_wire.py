"""Non-authorizing scanner-shaped reads from an already-running local WAM regtest node.

Unlike offline fixtures, this path sends actual bounded JSON-RPC over loopback.
It never launches Core, scans a wallet, imports WSP, signs, broadcasts, stores
transactions or accepts a network/credential from environment defaults.

IMPORTANT: A local RPC response is NOT trusted publisher/binary provenance.
Real-Core use remains blocked by #36/#9 until DEV-qualified artifacts and host
isolation are independently established. This adapter has no enable switch.
"""
from __future__ import annotations

import base64
import http.client
import json
import re

from wam_privacy_wallet.integrations.scanner_response_contract import (
    OfflineScannerResponseSummary, ScannerResponseShapeError,
    validate_offline_confirmed_block, validate_offline_mempool_ids,
)
from wam_privacy_wallet.node.attestation import RegtestIdentityError
from wam_privacy_wallet.node.core_profile import CoreProfileError
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth, LocalReadOnlyRpc, LocalRpcError
from wam_privacy_wallet.node.regtest_gateway import LocalRegtestIdentityGateway

_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_WIRE_BYTES = 8 * 1024 * 1024
_MAX_HEIGHT = 100_000_000


class RegtestScannerWireError(RuntimeError):
    """Fixed, redacted error code. Never contains node responses or auth."""


class _ScannerOnlyWire:
    """Separate scanner RPC allowlist: no inherited diagnostic widening."""

    __slots__ = ("_endpoint", "_auth", "_timeout", "_tx_read_allowed")

    def __init__(
        self, endpoint: LocalRegtestEndpoint, auth: ExplicitRpcAuth, *,
        timeout: float, allow_transaction_lookup: bool = False,
    ) -> None:
        if type(endpoint) is not LocalRegtestEndpoint or type(auth) is not ExplicitRpcAuth:
            raise ValueError("SCAN_RPC_LOCAL_AUTH_REQUIRED")
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            raise ValueError("SCAN_RPC_TIMEOUT_INVALID")
        if type(allow_transaction_lookup) is not bool:
            raise ValueError("SCAN_RPC_TX_SCOPE_DENIED")
        self._endpoint, self._auth, self._timeout = endpoint, auth, timeout
        # Default remains the original two-method scanner diagnostic boundary.
        # Only an independently attested WSP scanner session may opt in.
        self._tx_read_allowed = allow_transaction_lookup

    def call(self, method: str, params: list[object]) -> object:
        if method == "getblock":
            if (type(params) is not list or len(params) != 2
                    or type(params[0]) is not str
                    or _HASH.fullmatch(params[0]) is None
                    or type(params[1]) is not int or params[1] != 3):
                raise RegtestScannerWireError("SCAN_RPC_PARAMS_DENIED")
        elif method == "getrawmempool":
            if type(params) is not list or params:
                raise RegtestScannerWireError("SCAN_RPC_PARAMS_DENIED")
        elif method == "getrawtransaction" and self._tx_read_allowed:
            # WSP scanner uses JSON transaction views, never raw hex or
            # implicit wallet-context read; bool is not a verbosity integer.
            if (type(params) is not list or len(params) != 2
                    or type(params[0]) is not str
                    or _HASH.fullmatch(params[0]) is None
                    or type(params[1]) is not int or params[1] not in (1, 2)):
                raise RegtestScannerWireError("SCAN_RPC_PARAMS_DENIED")
        else:
            raise RegtestScannerWireError("SCAN_RPC_METHOD_DENIED")

        token = base64.b64encode(
            (self._auth.username + ":" + self._auth.password).encode("ascii")
        ).decode("ascii")
        wire = json.dumps(
            {"jsonrpc": "1.0", "id": 1, "method": method, "params": params},
            separators=(",", ":"), allow_nan=False,
        ).encode("ascii")
        conn = http.client.HTTPConnection(
            self._endpoint.host, self._endpoint.port, timeout=self._timeout,
        )
        try:
            conn.request("POST", "/", wire, headers={
                "Authorization": "Basic " + token,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Connection": "close",
            })
            response = conn.getresponse()
            if response.status != 200:
                raise RegtestScannerWireError("SCAN_RPC_HTTP_DENIED")
            size = response.getheader("Content-Length")
            if size is not None and (
                len(size) > 9 or not size.isascii()
                or not size.isdecimal() or int(size) > _MAX_WIRE_BYTES
            ):
                raise RegtestScannerWireError("SCAN_RPC_RESPONSE_LIMIT")
            raw = response.read(_MAX_WIRE_BYTES + 1)
            if len(raw) > _MAX_WIRE_BYTES:
                raise RegtestScannerWireError("SCAN_RPC_RESPONSE_LIMIT")
            try:
                payload = json.loads(raw)
            except (ValueError, UnicodeDecodeError, RecursionError):
                raise RegtestScannerWireError("SCAN_RPC_REPLY_DENIED") from None
            if (type(payload) is not dict or type(payload.get("id")) is not int
                    or payload["id"] != 1 or "result" not in payload
                    or "error" not in payload):
                raise RegtestScannerWireError("SCAN_RPC_REPLY_DENIED")
            if payload["error"] is not None:
                raise RegtestScannerWireError("SCAN_RPC_REMOTE_ERROR")
            return payload["result"]
        except (OSError, TimeoutError, http.client.HTTPException):
            raise RegtestScannerWireError("SCAN_RPC_TRANSPORT_DENIED") from None
        finally:
            conn.close()


class RegtestScannerReadBridge:
    """Real loopback HTTP read contract; **never** produces scanner authority.

    Connects only to an already-running explicit local regtest endpoint. Fresh
    profile probes bracket every read to reject observable reorgs or profile
    changes. No mock fallback, arbitrary method hooks or default credentials.
    """

    __slots__ = ("_gateway", "_identity_rpc", "_scanner")

    def __init__(
        self, endpoint: LocalRegtestEndpoint, auth: ExplicitRpcAuth, *,
        timeout: float = 3,
    ) -> None:
        self._scanner = _ScannerOnlyWire(endpoint, auth, timeout=timeout)
        self._identity_rpc = LocalReadOnlyRpc(endpoint, auth, timeout=timeout)
        self._gateway = LocalRegtestIdentityGateway(endpoint, auth, timeout=timeout)

    def _profile(self):
        try:
            return self._gateway.probe_core_profile()
        except (RegtestIdentityError, CoreProfileError, LocalRpcError):
            raise RegtestScannerWireError("SCAN_RPC_PROFILE_DENIED") from None

    def read_confirmed(
        self, height: int, *, expected_previous_hash: str | None = None,
    ) -> OfflineScannerResponseSummary:
        """Read a block anchored to the *live* node's parent hash, not a fixture.

        A caller-provided previous hash is an optional additional expectation,
        NEVER the source of chain ancestry. Before and after the read, both
        the block and its parent are rechecked at their heights. A dishonest
        local RPC peer can still forge a self-consistent chain: no authority.
        """
        if (type(height) is not int or not 1 <= height <= _MAX_HEIGHT
                or (expected_previous_hash is not None and
                    (type(expected_previous_hash) is not str
                     or _HASH.fullmatch(expected_previous_hash) is None))):
            raise RegtestScannerWireError("SCAN_RPC_EXPECTATION_DENIED")
        before = self._profile()
        if height > before.identity.height:
            raise RegtestScannerWireError("SCAN_RPC_HEIGHT_AHEAD")
        try:
            parent_hash = self._identity_rpc.call("getblockhash", [height - 1])
            if type(parent_hash) is not str or _HASH.fullmatch(parent_hash) is None:
                raise RegtestScannerWireError("SCAN_RPC_PARENT_DENIED")
            if (expected_previous_hash is not None
                    and parent_hash != expected_previous_hash):
                raise RegtestScannerWireError("SCAN_RPC_PREVIOUS_MISMATCH")
            blockhash = self._identity_rpc.call("getblockhash", [height])
            if type(blockhash) is not str or _HASH.fullmatch(blockhash) is None:
                raise RegtestScannerWireError("SCAN_RPC_HASH_DENIED")
            block = self._scanner.call("getblock", [blockhash, 3])
            summary = validate_offline_confirmed_block(
                block, expected_hash=blockhash,
                expected_previous_hash=parent_hash, height=height,
            )
            after = self._profile()
            if (before != after
                    or self._identity_rpc.call("getblockhash", [height]) != blockhash
                    or self._identity_rpc.call("getblockhash", [height - 1]) != parent_hash):
                raise RegtestScannerWireError("SCAN_RPC_TIP_CHANGED")
            return summary
        except (LocalRpcError, ScannerResponseShapeError):
            raise RegtestScannerWireError("SCAN_RPC_BLOCK_DENIED") from None

    def read_mempool(self) -> OfflineScannerResponseSummary:
        before = self._profile()
        try:
            ids = self._scanner.call("getrawmempool", [])
            summary = validate_offline_mempool_ids(ids)
        except ScannerResponseShapeError:
            raise RegtestScannerWireError("SCAN_RPC_MEMPOOL_DENIED") from None
        if before != self._profile():
            raise RegtestScannerWireError("SCAN_RPC_TIP_CHANGED")
        return summary
