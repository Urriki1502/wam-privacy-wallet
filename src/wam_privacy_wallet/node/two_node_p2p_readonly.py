"""Read-only P2P topology audit of two ALREADY RUNNING localhost regtest RPCs.

This uses genuine bounded HTTP requests, not a callback-based operational mock.
Peer data are hostile. No Core binary/process attestations, P2P connection
creation, peer identifiers/addresses in output, wallets, keys or launch API.
"""
from __future__ import annotations

import base64
import http.client
import json
import re
from dataclasses import dataclass

from .core_profile import CoreProfileError
from .attestation import RegtestIdentityError
from .endpoint import LocalRegtestEndpoint
from .read_rpc import ExplicitRpcAuth, LocalRpcError
from .regtest_gateway import LocalRegtestIdentityGateway

_MAX_RESPONSE_BYTES = 131072
_ENDPOINT = re.compile(r"127\.0\.0\.1:([0-9]{1,5})\Z", re.ASCII)


class RegtestP2PAuditError(ValueError):
    """Fixed redacted status, never credentials or untrusted network data."""


@dataclass(frozen=True, slots=True)
class _Peer:
    inbound: bool
    remote_port: int
    local_port: int


class _P2PReadOnlyWire:
    """Separate fixed-method P2P RPC client; does not expand wallet RPC allowlists."""

    __slots__ = ("_endpoint", "_auth")

    def __init__(self, endpoint: LocalRegtestEndpoint, auth: ExplicitRpcAuth):
        if type(endpoint) is not LocalRegtestEndpoint or type(auth) is not ExplicitRpcAuth:
            raise RegtestP2PAuditError("REGTEST_P2P_ENDPOINT_DENIED")
        if endpoint.host != "127.0.0.1":
            raise RegtestP2PAuditError("REGTEST_P2P_IPV4_REQUIRED")
        self._endpoint, self._auth = endpoint, auth

    def call(self, method: str) -> object:
        if type(method) is not str or method not in ("getpeerinfo", "getnetworkinfo"):
            raise RegtestP2PAuditError("REGTEST_P2P_METHOD_DENIED")
        token = base64.b64encode(
            (self._auth.username + ":" + self._auth.password).encode("ascii")
        ).decode("ascii")
        payload = json.dumps(
            {"jsonrpc": "1.0", "id": 1, "method": method, "params": []},
            separators=(",", ":"), allow_nan=False,
        ).encode("ascii")
        connection = http.client.HTTPConnection(
            self._endpoint.host, self._endpoint.port, timeout=3,
        )
        try:
            connection.request("POST", "/", payload, headers={
                "Authorization": "Basic " + token,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Connection": "close",
            })
            response = connection.getresponse()
            if response.status != 200:
                raise RegtestP2PAuditError("REGTEST_P2P_HTTP_DENIED")
            encoding = response.getheader("Content-Encoding")
            if encoding is not None and encoding.lower().strip() != "identity":
                raise RegtestP2PAuditError("REGTEST_P2P_ENCODING_DENIED")
            size = response.getheader("Content-Length")
            if size is not None and (
                type(size) is not str or len(size) > 8
                or not size.isascii() or not size.isdecimal()
                or not 0 < int(size) <= _MAX_RESPONSE_BYTES
            ):
                raise RegtestP2PAuditError("REGTEST_P2P_RESPONSE_LIMIT")
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
            if (not raw or len(raw) > _MAX_RESPONSE_BYTES
                    or (size is not None and len(raw) != int(size))):
                raise RegtestP2PAuditError("REGTEST_P2P_RESPONSE_LIMIT")
            try:
                reply = json.loads(raw)
            except (ValueError, UnicodeDecodeError, RecursionError):
                raise RegtestP2PAuditError("REGTEST_P2P_REPLY_DENIED") from None
            if (type(reply) is not dict
                    or type(reply.get("id")) is not int or reply["id"] != 1
                    or "result" not in reply or "error" not in reply):
                raise RegtestP2PAuditError("REGTEST_P2P_REPLY_DENIED")
            if reply["error"] is not None:
                raise RegtestP2PAuditError("REGTEST_P2P_REMOTE_DENIED")
            return reply["result"]
        except RegtestP2PAuditError:
            raise
        except (OSError, TimeoutError, http.client.HTTPException):
            raise RegtestP2PAuditError("REGTEST_P2P_TRANSPORT_DENIED") from None
        finally:
            connection.close()


def _p2p_port(port: object) -> int:
    if type(port) is not int or not 1024 <= port <= 65535:
        raise RegtestP2PAuditError("REGTEST_P2P_PORT_DENIED")
    return port


def _address_port(address: object) -> int:
    if type(address) is not str:
        raise RegtestP2PAuditError("REGTEST_P2P_PEER_ADDRESS_DENIED")
    match = _ENDPOINT.fullmatch(address)
    if match is None:
        raise RegtestP2PAuditError("REGTEST_P2P_PEER_ADDRESS_DENIED")
    result = int(match.group(1))
    if not 1 <= result <= 65535 or str(result) != match.group(1):
        raise RegtestP2PAuditError("REGTEST_P2P_PEER_ADDRESS_DENIED")
    return result


def _network(payload: object, *, expected_inbound: bool) -> None:
    if (type(payload) is not dict
            or payload.get("networkactive") is not True
            or type(payload.get("networkactive")) is not bool
            or type(payload.get("connections")) is not int
            or payload["connections"] != 1):
        raise RegtestP2PAuditError("REGTEST_P2P_NETWORK_DENIED")
    # A hidden public local-address announcement is disallowed, even if the
    # only connected peer happens to be localhost.
    local = payload.get("localaddresses", [])
    if type(local) is not list or local:
        raise RegtestP2PAuditError("REGTEST_P2P_ADVERTISEMENT_DENIED")
    # Bitcoin Core v28-compatible fields: the network-level counts must
    # agree with peerinfo direction and the one-peer isolation contract.
    # Missing fields are DENIED rather than silently inferring them.
    inbound = payload.get("connections_in")
    outbound = payload.get("connections_out")
    if (type(inbound) is not int or type(outbound) is not int
            or inbound != int(expected_inbound)
            or outbound != int(not expected_inbound)):
        raise RegtestP2PAuditError("REGTEST_P2P_NETWORK_DENIED")


def _peer(payload: object, *, expected_inbound: bool) -> _Peer:
    if type(payload) is not list or len(payload) != 1:
        raise RegtestP2PAuditError("REGTEST_P2P_PEER_COUNT_DENIED")
    item = payload[0]
    if (type(item) is not dict
            or type(item.get("inbound")) is not bool
            or item["inbound"] is not expected_inbound):
        raise RegtestP2PAuditError("REGTEST_P2P_DIRECTION_DENIED")
    return _Peer(
        inbound=item["inbound"],
        remote_port=_address_port(item.get("addr")),
        local_port=_address_port(item.get("addrbind")),
    )


class TwoNodeP2PReadOnlyAudit:
    """Read live P2P topology without proving actual Core process identity."""

    __slots__ = ("_a", "_b", "_gw_a", "_gw_b", "_port_a", "_port_b")

    def __init__(
        self, node_a: LocalRegtestEndpoint, auth_a: ExplicitRpcAuth,
        node_b: LocalRegtestEndpoint, auth_b: ExplicitRpcAuth, *,
        node_a_p2p_port: int, node_b_p2p_port: int,
    ):
        if (type(node_a) is not LocalRegtestEndpoint
                or type(node_b) is not LocalRegtestEndpoint
                or node_a == node_b
                or type(auth_a) is not ExplicitRpcAuth
                or type(auth_b) is not ExplicitRpcAuth):
            raise RegtestP2PAuditError("REGTEST_P2P_ENDPOINT_DENIED")
        a_port, b_port = _p2p_port(node_a_p2p_port), _p2p_port(node_b_p2p_port)
        if len({node_a.port, node_b.port, a_port, b_port}) != 4:
            raise RegtestP2PAuditError("REGTEST_P2P_PORT_COLLISION")
        self._a = _P2PReadOnlyWire(node_a, auth_a)
        self._b = _P2PReadOnlyWire(node_b, auth_b)
        self._gw_a = LocalRegtestIdentityGateway(node_a, auth_a, timeout=3)
        self._gw_b = LocalRegtestIdentityGateway(node_b, auth_b, timeout=3)
        self._port_a, self._port_b = a_port, b_port

    def _observe(self) -> tuple[object, object, _Peer, _Peer]:
        p_a = self._gw_a.probe_core_profile()
        p_b = self._gw_b.probe_core_profile()
        if (p_a.identity.genesis != p_b.identity.genesis
                or p_a.identity.height != p_b.identity.height
                or p_a.identity.best_block_hash != p_b.identity.best_block_hash):
            raise RegtestP2PAuditError("REGTEST_P2P_CHAIN_DIVERGED")
        _network(self._a.call("getnetworkinfo"), expected_inbound=False)
        _network(self._b.call("getnetworkinfo"), expected_inbound=True)
        peer_a = _peer(self._a.call("getpeerinfo"), expected_inbound=False)
        peer_b = _peer(self._b.call("getpeerinfo"), expected_inbound=True)
        # A's remote address must be exactly B's approved P2P listener.
        # A's local ephemeral port must be B's one inbound peer.
        # B's local bound port must equal the audited listener.
        if (peer_a.remote_port != self._port_b
                or peer_b.local_port != self._port_b
                or peer_a.local_port != peer_b.remote_port
                or peer_a.local_port in (self._port_a, self._port_b)
                or peer_a.local_port <= 1023):
            raise RegtestP2PAuditError("REGTEST_P2P_TOPOLOGY_DENIED")
        if (self._gw_a.probe_core_profile() != p_a
                or self._gw_b.probe_core_profile() != p_b):
            raise RegtestP2PAuditError("REGTEST_P2P_CHAIN_MOVED")
        return p_a, p_b, peer_a, peer_b

    def audit(self) -> dict[str, object]:
        try:
            before = self._observe()
            after = self._observe()
            if before != after:
                raise RegtestP2PAuditError("REGTEST_P2P_CHANGED_DURING_READ")
        except RegtestP2PAuditError:
            raise
        except (RegtestIdentityError, CoreProfileError, LocalRpcError, ValueError):
            raise RegtestP2PAuditError("REGTEST_P2P_PROFILE_DENIED") from None
        return {
            "status": "UNTRUSTED_LOCAL_REGTEST_P2P_TOPOLOGY_ONLY",
            "peer_count_a": 1,
            "peer_count_b": 1,
            "localhost_only_observed": True,
            "expected_direction_observed": True,
            "reported_chain_agrees": True,
            "genuine_wam_process_verified": False,
            "independent_processes_verified": False,
            "external_network_exclusion_proven": False,
            "real_two_node_regtest_qualified": False,
            "scanner_enabled": False,
            "wallet_ready": False,
            "signing_allowed": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
        }
