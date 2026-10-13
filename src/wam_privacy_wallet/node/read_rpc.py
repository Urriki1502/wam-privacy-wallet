"""Bounded, read-only JSON-RPC transport for a user-owned loopback WAM node.

No wallet, secrets-file parsing, scanner or transaction functions belong here.
Only supported regtest identity RPCs may be invoked. Authentication is
explicit; no environment proxies, URL redirects or DNS-based hosts are used.
"""

from __future__ import annotations

import base64
import http.client
import json
import re
from dataclasses import dataclass

from .endpoint import LocalRegtestEndpoint
from .rpc_json import decode_rpc_json

_READ_METHODS = frozenset({"getblockhash", "getblockcount", "getbestblockhash", "getblockchaininfo", "getblockheader"})
_HEADER_HASH_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_RESPONSE_BYTES = 1_048_576
_MAX_BLOCK_HEIGHT = 100_000_000


class LocalRpcError(RuntimeError):
    """Stable non-sensitive error code; raw HTTP/RPC exceptions are suppressed."""


@dataclass(frozen=True, slots=True, repr=False)
class ExplicitRpcAuth:
    """Caller-provided authentication (never loaded from disk implicitly)."""

    username: str
    password: str

    def __post_init__(self) -> None:
        if (
            type(self.username) is not str
            or type(self.password) is not str
            or not 1 <= len(self.username) <= 128
            or not 1 <= len(self.password) <= 1024
            or any(ord(c) < 33 or ord(c) > 126 or c == ":" for c in self.username)
            or any(ord(c) < 33 or ord(c) > 126 for c in self.password)
        ):
            raise ValueError("WAM_RPC_INVALID_AUTH")


class LocalReadOnlyRpc:
    """Fixed-method HTTP transport; does not attest the actual Core binary."""

    def __init__(
        self,
        endpoint: LocalRegtestEndpoint,
        auth: ExplicitRpcAuth,
        *,
        timeout: float = 3.0,
    ) -> None:
        if type(endpoint) is not LocalRegtestEndpoint:
            raise ValueError("WAM_RPC_LOCAL_ENDPOINT_REQUIRED")
        if type(auth) is not ExplicitRpcAuth:
            raise ValueError("WAM_RPC_AUTH_REQUIRED")
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            raise ValueError("WAM_RPC_TIMEOUT_INVALID")
        self._endpoint = endpoint
        self._auth = auth
        self._timeout = timeout

    def call(self, method: str, params: list[object] | None = None) -> object:
        """One RPC request, with no automatic retries or redirect handling."""
        if type(method) is not str or method not in _READ_METHODS:
            raise LocalRpcError("WAM_RPC_METHOD_DENIED")
        if params is None:
            params = []
        if type(params) is not list:
            raise LocalRpcError("WAM_RPC_INVALID_PARAMS")
        if method == "getblockhash":
            if (len(params) != 1 or type(params[0]) is not int
                    or not 0 <= params[0] <= _MAX_BLOCK_HEIGHT):
                raise LocalRpcError("WAM_RPC_INVALID_PARAMS")
        elif method == "getblockheader":
            # Exact verbose header read on one specified block hash only.
            # Never accept a raw hex full-block request or implicit params.
            if (len(params) != 2 or type(params[0]) is not str
                    or _HEADER_HASH_RE.fullmatch(params[0]) is None
                    or params[1] is not True):
                raise LocalRpcError("WAM_RPC_INVALID_PARAMS")
        elif params:
            raise LocalRpcError("WAM_RPC_INVALID_PARAMS")

        userpass = f"{self._auth.username}:{self._auth.password}".encode("ascii")
        token = base64.b64encode(userpass).decode("ascii")
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}, separators=(",", ":")).encode("utf-8")
        connection = http.client.HTTPConnection(self._endpoint.host, self._endpoint.port, timeout=self._timeout)
        response = None
        try:
            connection.request(
                "POST", "/", body=body,
                headers={
                    "Authorization": "Basic " + token,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            if response.status != 200:
                raise LocalRpcError("WAM_RPC_HTTP_REJECTED")
            size = response.getheader("Content-Length")
            if size is not None:
                if len(size) > 7 or not size.isascii() or not size.isdecimal() or int(size) > _MAX_RESPONSE_BYTES:
                    raise LocalRpcError("WAM_RPC_RESPONSE_LIMIT")
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_RESPONSE_BYTES:
                raise LocalRpcError("WAM_RPC_RESPONSE_LIMIT")
            try:
                reply = decode_rpc_json(raw)
            except (ValueError, UnicodeDecodeError, RecursionError):
                raise LocalRpcError("WAM_RPC_INVALID_RESPONSE") from None
            if (
                type(reply) is not dict
                or type(reply.get("id")) is not int
                or reply["id"] != 1
                or "result" not in reply
                or "error" not in reply
            ):
                raise LocalRpcError("WAM_RPC_INVALID_RESPONSE")
            if reply["error"] is not None:
                raise LocalRpcError("WAM_RPC_REMOTE_ERROR")
            return reply["result"]
        except (OSError, TimeoutError, http.client.HTTPException):
            raise LocalRpcError("WAM_RPC_TRANSPORT_ERROR") from None
        finally:
            if response is not None:
                response.close()
            connection.close()
