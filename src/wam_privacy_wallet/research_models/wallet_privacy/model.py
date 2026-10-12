"""Data model for the Phase 2 wallet-privacy reference policy."""

from __future__ import annotations

from dataclasses import dataclass

MAX_MONEY = 22_000_000 * 100_000_000


def _is_txid(value: str) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class Coin:
    """Wallet-owned spendable candidate.

    cluster is an opaque wallet-local identifier. It must not be exported to
    analytics/logging systems as a stable user identifier.
    """

    txid: str
    vout: int
    atoms: int
    cluster: str
    confirmations: int = 1
    reserved: bool = False

    def validate(self) -> None:
        if not _is_txid(self.txid):
            raise ValueError("COIN_TXID")
        if type(self.vout) is not int or not 0 <= self.vout < 2**32:
            raise ValueError("COIN_VOUT")
        if type(self.atoms) is not int or not 1 <= self.atoms <= MAX_MONEY:
            raise ValueError("COIN_AMOUNT")
        if not isinstance(self.cluster, str) or not 1 <= len(self.cluster) <= 128:
            raise ValueError("COIN_CLUSTER")
        if any(ord(c) < 32 for c in self.cluster):
            raise ValueError("COIN_CLUSTER")
        if type(self.confirmations) is not int or not 0 <= self.confirmations < 2**31:
            raise ValueError("COIN_CONFIRMATIONS")
        if type(self.reserved) is not bool:
            raise ValueError("COIN_RESERVED")

    @property
    def outpoint(self) -> tuple[str, int]:
        return self.txid, self.vout


@dataclass(frozen=True)
class Intent:
    """Opaque payment intent.

    recipient is intentionally opaque here. Address parsing belongs to the
    protocol-specific integration layer, not this policy module.
    """

    recipient: str
    atoms: int

    def validate(self) -> None:
        if not isinstance(self.recipient, str) or not 1 <= len(self.recipient) <= 512:
            raise ValueError("INTENT_RECIPIENT")
        if type(self.atoms) is not int or not 1 <= self.atoms <= MAX_MONEY:
            raise ValueError("INTENT_AMOUNT")


@dataclass(frozen=True)
class Policy:
    """Deterministic privacy policy.

    Cluster merge is deliberately opt-in.
    """

    min_confirmations: int = 1
    dust_threshold: int = 330
    max_inputs: int = 128
    allow_cluster_merge: bool = False
    exact_search_limit: int = 18
    exact_search_width: int = 4

    def validate(self) -> None:
        if type(self.min_confirmations) is not int or not 0 <= self.min_confirmations < 2**31:
            raise ValueError("POLICY_CONFIRMATIONS")
        if type(self.dust_threshold) is not int or not 1 <= self.dust_threshold <= 100_000:
            raise ValueError("POLICY_DUST")
        if type(self.max_inputs) is not int or not 1 <= self.max_inputs <= 128:
            raise ValueError("POLICY_MAX_INPUTS")
        if type(self.allow_cluster_merge) is not bool:
            raise ValueError("POLICY_CLUSTER_MERGE")
        if type(self.exact_search_limit) is not int or not 1 <= self.exact_search_limit <= 24:
            raise ValueError("POLICY_SEARCH_LIMIT")
        if type(self.exact_search_width) is not int or not 1 <= self.exact_search_width <= 6:
            raise ValueError("POLICY_SEARCH_WIDTH")


@dataclass(frozen=True)
class Selection:
    selected: tuple[Coin, ...]
    target_atoms: int
    fee_atoms: int
    total_input_atoms: int
    change_atoms: int
    clusters: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def change_required(self) -> bool:
        return self.change_atoms > 0
