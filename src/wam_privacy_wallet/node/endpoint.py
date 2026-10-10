"""A fail-closed local regtest endpoint descriptor, not a network client.

The WAM mainnet/testnet WSP profile is not yet approved. This module does not
select default ports, read node configuration, resolve DNS, authenticate, or
create any socket. Later adapters must revalidate boundaries when connecting.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv6Address, ip_address


@dataclass(frozen=True, slots=True)
class LocalRegtestEndpoint:
    """Explicit loopback RPC destination for isolated WAM Core regtest only.

    Numeric IP addresses avoid DNS rebinding and host-name ambiguity. Both IPv4
    and IPv6 loopback addresses are accepted. Ports are always caller-supplied;
    18443 is *not* implicitly treated as the WAM default.
    """

    host: str
    port: int
    network: str = "regtest"

    def __post_init__(self) -> None:
        if type(self.host) is not str or not self.host or "%" in self.host:
            raise ValueError("WAM_RPC_INVALID_HOST")
        try:
            address = ip_address(self.host)
        except ValueError as exc:
            raise ValueError("WAM_RPC_INVALID_HOST") from exc
        # IPv4-mapped IPv6 addresses are not accepted even when some Python
        # versions classify the mapped target as loopback. Keep one canonical
        # address family per endpoint and avoid platform-dependent routing.
        if not address.is_loopback or (
            isinstance(address, IPv6Address) and address.ipv4_mapped is not None
        ):
            raise ValueError("WAM_RPC_NONLOCAL_HOST")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("WAM_RPC_INVALID_PORT")
        if type(self.network) is not str or self.network != "regtest":
            raise ValueError("WAM_RPC_UNAPPROVED_NETWORK")
        object.__setattr__(self, "host", str(address))

    @property
    def url(self) -> str:
        """Return a loopback HTTP address only; this performs no I/O."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}"
