"""Deterministic privacy-aware coin selection reference model.

Security/privacy properties:
- cluster merging is opt-in;
- already-reserved and under-confirmed coins are excluded;
- duplicate outpoints fail closed;
- exact/no-change candidates are preferred;
- dust change is never created;
- tie-breaking is deterministic;
- default audit events contain no txids, recipients, cluster identifiers, or amounts.

This is a policy prototype, not a production wallet implementation.
"""

from __future__ import annotations

from collections import defaultdict
from itertools import combinations

from .model import Coin, Intent, Policy, Selection, MAX_MONEY


class PolicyError(ValueError):
    """Fixed-code policy failure suitable for safe test assertions."""


def _validate_inputs(
    coins: tuple[Coin, ...], intents: tuple[Intent, ...], fee_atoms: int, policy: Policy
) -> int:
    try:
        policy.validate()
    except ValueError as exc:
        raise PolicyError(str(exc)) from None

    if not coins:
        raise PolicyError("NO_COINS")
    if not intents or len(intents) > 128:
        raise PolicyError("INTENT_COUNT")
    if type(fee_atoms) is not int or not 1 <= fee_atoms <= 1_000_000:
        raise PolicyError("FEE_POLICY")

    seen: set[tuple[str, int]] = set()
    for coin in coins:
        try:
            coin.validate()
        except ValueError as exc:
            raise PolicyError(str(exc)) from None
        if coin.outpoint in seen:
            raise PolicyError("DUPLICATE_OUTPOINT")
        seen.add(coin.outpoint)

    total = fee_atoms
    for intent in intents:
        try:
            intent.validate()
        except ValueError as exc:
            raise PolicyError(str(exc)) from None
        total += intent.atoms
        if total > MAX_MONEY:
            raise PolicyError("TARGET_RANGE")
    return total


def _acceptable(total: int, needed: int, dust: int) -> bool:
    change = total - needed
    return change == 0 or change >= dust


def _candidate_key(candidate: tuple[Coin, ...], needed: int) -> tuple:
    total = sum(c.atoms for c in candidate)
    change = total - needed
    clusters = len({c.cluster for c in candidate})
    # Privacy-first ordering:
    #   1) fewer clusters,
    #   2) no change,
    #   3) fewer inputs,
    #   4) smaller change,
    #   5) deterministic outpoint order.
    return (
        clusters,
        0 if change == 0 else 1,
        len(candidate),
        change,
        tuple(sorted(c.outpoint for c in candidate)),
    )


def _enumerate_group(
    group: tuple[Coin, ...],
    needed: int,
    policy: Policy,
) -> list[tuple[Coin, ...]]:
    ordered = tuple(sorted(group, key=lambda c: (c.atoms, c.txid, c.vout)))
    candidates: dict[tuple[tuple[str, int], ...], tuple[Coin, ...]] = {}

    def add(items: tuple[Coin, ...]) -> None:
        if not items or len(items) > policy.max_inputs:
            return
        total = sum(c.atoms for c in items)
        if total < needed or not _acceptable(total, needed, policy.dust_threshold):
            return
        canonical = tuple(sorted(items, key=lambda c: c.outpoint))
        key = tuple(c.outpoint for c in canonical)
        candidates[key] = canonical

    # Single-coin exact/near-exact opportunities.
    for coin in ordered:
        add((coin,))

    # Bounded exact/near-exact search. This is deterministic and intentionally
    # capped to avoid turning wallet policy into an attacker-controlled subset
    # sum DoS surface.
    search = ordered[: policy.exact_search_limit]
    width = min(policy.exact_search_width, policy.max_inputs, len(search))
    for n in range(2, width + 1):
        for combo in combinations(search, n):
            add(combo)

    # Always include deterministic greedy candidates so large wallets remain
    # usable even when the bounded combination search does not find an optimum.
    desc = tuple(sorted(ordered, key=lambda c: (-c.atoms, c.txid, c.vout)))
    running: list[Coin] = []
    total = 0
    for coin in desc:
        if len(running) >= policy.max_inputs:
            break
        running.append(coin)
        total += coin.atoms
        if total >= needed and _acceptable(total, needed, policy.dust_threshold):
            add(tuple(running))
            break

    asc = tuple(sorted(ordered, key=lambda c: (c.atoms, c.txid, c.vout)))
    running = []
    total = 0
    for coin in asc:
        if len(running) >= policy.max_inputs:
            break
        running.append(coin)
        total += coin.atoms
        if total >= needed and _acceptable(total, needed, policy.dust_threshold):
            add(tuple(running))
            break

    return list(candidates.values())


def select_coins(
    coins: tuple[Coin, ...] | list[Coin],
    intents: tuple[Intent, ...] | list[Intent],
    fee_atoms: int,
    policy: Policy | None = None,
) -> Selection:
    """Select coins without creating implicit cross-cluster linkage."""

    policy = Policy() if policy is None else policy
    coins = tuple(coins)
    intents = tuple(intents)
    needed = _validate_inputs(coins, intents, fee_atoms, policy)

    eligible = tuple(
        c
        for c in coins
        if not c.reserved and c.confirmations >= policy.min_confirmations
    )
    if not eligible:
        raise PolicyError("NO_ELIGIBLE_COINS")

    groups: list[tuple[Coin, ...]]
    if policy.allow_cluster_merge:
        groups = [eligible]
    else:
        by_cluster: dict[str, list[Coin]] = defaultdict(list)
        for coin in eligible:
            by_cluster[coin.cluster].append(coin)
        groups = [
            tuple(by_cluster[name])
            for name in sorted(by_cluster)
        ]

    candidates: list[tuple[Coin, ...]] = []
    for group in groups:
        candidates.extend(_enumerate_group(group, needed, policy))

    if not candidates:
        if (
            not policy.allow_cluster_merge
            and sum(c.atoms for c in eligible) >= needed
            and len({c.cluster for c in eligible}) > 1
        ):
            raise PolicyError("INSUFFICIENT_SINGLE_CLUSTER_FUNDS")
        raise PolicyError("INSUFFICIENT_FUNDS_OR_DUST_CHANGE")

    chosen = min(candidates, key=lambda c: _candidate_key(c, needed))
    total = sum(c.atoms for c in chosen)
    change = total - needed
    clusters = tuple(sorted({c.cluster for c in chosen}))

    warnings: list[str] = []
    if len(clusters) > 1:
        warnings.append("CLUSTER_MERGE")
    if change:
        warnings.append("CHANGE_CREATED")

    return Selection(
        selected=chosen,
        target_atoms=sum(i.atoms for i in intents),
        fee_atoms=fee_atoms,
        total_input_atoms=total,
        change_atoms=change,
        clusters=clusters,
        warnings=tuple(warnings),
    )


def redacted_event(selection: Selection) -> dict:
    """Return privacy-preserving operational telemetry.

    Deliberately excluded:
    - txids / vouts;
    - recipient identifiers;
    - cluster identifiers;
    - exact amounts;
    - deterministic cross-run identifiers.
    """

    return {
        "schema": 1,
        "selected_inputs": len(selection.selected),
        "cluster_count": len(selection.clusters),
        "change_created": selection.change_required,
        "warning_codes": list(selection.warnings),
    }
