"""Fail-closed qualification state for genuine two-node WAM Core regtest.

Preparation only: this module cannot start nodes or authorize wallet operations.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TwoNodeReadiness:
    verified_executable_binding: bool = False
    approved_core_binary: bool = False
    isolated_two_node_runner: bool = False
    authenticated_live_rpc: bool = False
    observed_real_p2p: bool = False
    reviewed_reorg_recovery: bool = False

    def __post_init__(self) -> None:
        if any(type(getattr(self, field)) is not bool for field in self.__dataclass_fields__):
            raise ValueError("REGTEST_READINESS_INVALID")

    def receipt(self) -> dict[str, bool | str]:
        # Evidence booleans supplied by callers cannot grant execution authority.
        return {
            "status": "BLOCKED_REQUIRES_GENUINE_CORE_REVIEW",
            "evidence_complete": False,
            "real_two_node_regtest_qualified": False,
            "core_execution_allowed": False,
            "scanner_enabled": False,
            "wallet_ready": False,
            "signing_allowed": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
        }
