"""Compose the local read-only RPC transport and strict regtest identity probe.

No scanner, private keys, wallets or persistent approval state. This gateway
is a diagnostic *snapshot*, not an authorization to use blockchain data or
sign transactions. It does not identify a WAM Core binary or verify consensus.
"""

from __future__ import annotations

from .attestation import ChainIdentity, RegtestIdentityProbe
from .endpoint import LocalRegtestEndpoint
from .read_rpc import ExplicitRpcAuth, LocalReadOnlyRpc, LocalRpcError
from .core_profile import CoreProfileError, VerifiedCoreProfile, validate_core_profile


class LocalRegtestIdentityGateway:
    """Single explicit trust path for the read-only regtest identity snapshot.

    The gateway constructs its own loopback-only RPC transport rather than
    accepting an arbitrary callback. Every probe re-reads genesis, height and
    tip, so no previously successful probe is cached as permanent permission.
    """

    __slots__ = ("_endpoint", "_transport")

    def __init__(
        self,
        endpoint: LocalRegtestEndpoint,
        auth: ExplicitRpcAuth,
        *,
        timeout: float = 3.0,
    ) -> None:
        # LocalReadOnlyRpc validates the exact endpoint/auth types, regtest
        # endpoint constraints and timeout *before* any I/O can happen.
        self._transport = LocalReadOnlyRpc(endpoint, auth, timeout=timeout)
        self._endpoint = endpoint

    def probe_identity(self) -> ChainIdentity:
        """Make six fixed, read-only RPC calls and return a fresh chain snapshot.

        Failures are redacted by RegtestIdentityProbe; no credentials or RPC
        server error bodies are returned to the caller. The snapshot becomes
        stale immediately after this function returns and must never authorize
        a later scanner/signing operation without a separate trust gate.
        """
        return RegtestIdentityProbe(self._endpoint, self._transport.call).probe()

    def probe_core_profile(self) -> VerifiedCoreProfile:
        """Verify Core's reported regtest chain and no pruning after tip checks.

        This makes seven read-only calls and returns no durable authorization.
        Results can become stale immediately after the last RPC response.
        """
        identity = self.probe_identity()
        try:
            details = self._transport.call("getblockchaininfo", [])
        except LocalRpcError:
            raise CoreProfileError("WAM_CORE_PROFILE_RPC_ERROR") from None
        return validate_core_profile(details, identity)
