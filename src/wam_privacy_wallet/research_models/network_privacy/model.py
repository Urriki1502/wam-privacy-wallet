"""Data model for the Phase 5 network privacy policy."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress


ROLES = {"chain_scan", "tx_broadcast", "payjoin_directory"}
ROUTES = {"local", "direct", "tor", "i2p", "ohttp"}


def _loopback(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class Endpoint:
    role: str
    host: str
    port: int
    route: str
    encrypted_transport: bool = False
    authenticated_transport: bool = False
    fallback: bool = False

    def validate(self) -> None:
        if self.role not in ROLES:
            raise ValueError("ENDPOINT_ROLE")
        if not isinstance(self.host, str) or not 1 <= len(self.host) <= 255:
            raise ValueError("ENDPOINT_HOST")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("ENDPOINT_PORT")
        if self.route not in ROUTES:
            raise ValueError("ENDPOINT_ROUTE")
        for value in (self.encrypted_transport, self.authenticated_transport, self.fallback):
            if type(value) is not bool:
                raise ValueError("ENDPOINT_FLAGS")

        if self.route == "local" and not _loopback(self.host):
            raise ValueError("LOCAL_ROUTE_NOT_LOOPBACK")
        if self.route != "local" and _loopback(self.host):
            raise ValueError("NONLOCAL_ROUTE_LOOPBACK")

    @property
    def is_loopback(self) -> bool:
        return _loopback(self.host)

    @property
    def public_identity(self) -> tuple[str, int]:
        return self.host.lower(), self.port


@dataclass(frozen=True)
class NetworkPolicy:
    allow_remote_scan: bool = False
    require_private_broadcast: bool = True
    require_ohttp_for_async_payjoin: bool = True
    allow_direct_fallback: bool = False
    require_public_role_separation: bool = True
    async_payjoin: bool = False

    def validate(self) -> None:
        for value in (
            self.allow_remote_scan,
            self.require_private_broadcast,
            self.require_ohttp_for_async_payjoin,
            self.allow_direct_fallback,
            self.require_public_role_separation,
            self.async_payjoin,
        ):
            if type(value) is not bool:
                raise ValueError("NETWORK_POLICY")


@dataclass(frozen=True)
class NetworkPlan:
    endpoints: tuple[Endpoint, ...]

    def validate(self) -> None:
        if not self.endpoints or len(self.endpoints) > 32:
            raise ValueError("NETWORK_ENDPOINT_COUNT")
        for endpoint in self.endpoints:
            endpoint.validate()

        roles = {e.role for e in self.endpoints if not e.fallback}
        if "chain_scan" not in roles:
            raise ValueError("CHAIN_SCAN_MISSING")
        if "tx_broadcast" not in roles:
            raise ValueError("TX_BROADCAST_MISSING")
