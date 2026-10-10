"""Immutable diagnostic UI projection; NOT node or wallet authorization.

This module does not import WSP-1, WAM SDK, Qt, wallet services or transports.
An upstream VerifiedCoreProfile is only a point-in-time read-only snapshot:
it cannot attest the actual WAM Core binary, authorize scanning or signing.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from wam_privacy_wallet.node.attestation import ChainIdentity, WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.core_profile import VerifiedCoreProfile
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint


class DiagnosticBoundaryError(ValueError):
    """Redacted fixed error code; never leak upstream input representations."""


@dataclass(frozen=True, slots=True)
class NodeOverview:
    """Safe to display; contains no endpoint, credentials or action capability."""

    network: Literal["regtest"]
    height: int
    status: Literal["READ_ONLY_SNAPSHOT"]
    notice: Literal["EXPERIMENTAL_NO_REAL_FUNDS"]


def node_overview(profile: object) -> NodeOverview:
    """Derive a non-authorizing UI summary from an offline/diagnostic profile.

    The snapshot is stale immediately. This intentionally neither opens
    connections nor retains the profile object or any of its credentials.
    """
    if type(profile) is not VerifiedCoreProfile:
        raise DiagnosticBoundaryError("APP_NODE_PROFILE_REQUIRED")
    identity = profile.identity
    if (
        type(identity) is not ChainIdentity
        or type(identity.endpoint) is not LocalRegtestEndpoint
        or identity.endpoint.network != "regtest"
        or identity.genesis != WAM_REGTEST_GENESIS
        or type(identity.height) is not int
        or not 0 <= identity.height <= 100_000_000
        or type(identity.best_block_hash) is not str
        or len(identity.best_block_hash) != 64
        or type(profile.headers) is not int
        or profile.headers < identity.height
        or type(profile.pruned) is not bool
        or profile.pruned
    ):
        raise DiagnosticBoundaryError("APP_NODE_PROFILE_INVALID")
    return NodeOverview(
        network="regtest",
        height=identity.height,
        status="READ_ONLY_SNAPSHOT",
        notice="EXPERIMENTAL_NO_REAL_FUNDS",
    )
