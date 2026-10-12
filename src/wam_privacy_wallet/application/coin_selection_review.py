"""Pinned real WAM coin-selection policy in a NON-AUTHORIZING application review.

Runs the unmodified upstream algorithm on caller-supplied normalized regtest
records, NOT actual WAM node/UTXO ownership data. No PSBT, signer, RPC,
secret, network transport, spending, broadcast, or mainnet is present.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha1
from pathlib import Path
from typing import Callable

_UPSTREAM_COMMIT = "db3d2dcaa540f1129d540101813b761167d33174"
_ROOT = Path(__file__).resolve().parents[1]
_PINNED = {
    "research_models/wallet_privacy/__init__.py":
        "d1a5272b8e389add8ca5e13767ccfe0ec319b1ee",
    "research_models/wallet_privacy/model.py":
        "c53df0c40f183bd51fbfaffe64d6a5aa899c8a43",
    "research_models/wallet_privacy/policy.py":
        "4c37f9c78d1c0f2818bf6530871cd0a87f4741dd",
}
_SAFE_WARNINGS = frozenset(("CLUSTER_MERGE", "CHANGE_CREATED"))


class CoinSelectionReviewError(ValueError):
    """Fixed public denial; no identifiers, amount or raw upstream exception."""


@dataclass(frozen=True, slots=True)
class CoinSelectionReview:
    selected_inputs: int
    cluster_count: int
    change_created: bool
    warning_codes: tuple[str, ...]
    provenance: str = field(default="PINNED_SOURCE_BYTES_NOT_RUNTIME_ATTESTATION", init=False)
    status: str = field(default="REGTEST_POLICY_REVIEW_UNTRUSTED", init=False)
    consent_granted: bool = field(default=True, init=False)
    core_authenticated: bool = field(default=False, init=False)
    wallet_operational: bool = field(default=False, init=False)
    wallet_balance_qualified: bool = field(default=False, init=False)
    signing_allowed: bool = field(default=False, init=False)
    broadcast_allowed: bool = field(default=False, init=False)
    mainnet_allowed: bool = field(default=False, init=False)


def _verify_source() -> None:
    """Verify pinned upstream Git blobs BEFORE importing its policy code."""
    try:
        for name, expected in _PINNED.items():
            data = (_ROOT / name).read_bytes()
            oid = sha1(b"blob " + str(len(data)).encode("ascii")
                       + b"\0" + data).hexdigest()
            if oid != expected:
                raise CoinSelectionReviewError("APP_COIN_SELECTION_SOURCE_DENIED")
    except (OSError, ValueError):
        raise CoinSelectionReviewError("APP_COIN_SELECTION_SOURCE_DENIED") from None


def review_regtest_coin_selection(
    coins: tuple[object, ...],
    intents: tuple[object, ...],
    fee_atoms: int,
    *,
    user_consented: bool,
    allow_cluster_merge: bool = False,
    policy: object = None,
    cancelled: Callable[[], bool] | None = None,
) -> CoinSelectionReview:
    """Evaluate actual pinned pure wallet policy; never authorize a spend."""
    if (user_consented is not True
            or type(allow_cluster_merge) is not bool
            or type(coins) is not tuple or not 1 <= len(coins) <= 128
            or type(intents) is not tuple or len(intents) != 1
            or type(fee_atoms) is not int or not 1 <= fee_atoms <= 1_000_000
            or (cancelled is not None and not callable(cancelled))):
        raise CoinSelectionReviewError("APP_COIN_SELECTION_INPUT_DENIED")
    if cancelled is not None:
        try:
            if cancelled() is not False:
                raise CoinSelectionReviewError("APP_COIN_SELECTION_CANCELLED")
        except CoinSelectionReviewError:
            raise
        except Exception:
            raise CoinSelectionReviewError("APP_COIN_SELECTION_CANCELLED") from None
    _verify_source()
    try:
        from wam_privacy_wallet.research_models.wallet_privacy.model import (
            Coin, Intent, Policy, Selection,
        )
        from wam_privacy_wallet.research_models.wallet_privacy.policy import (
            select_coins, redacted_event,
        )
        if (any(type(c) is not Coin for c in coins)
                or any(type(i) is not Intent for i in intents)
                or (policy is not None and type(policy) is not Policy)):
            raise CoinSelectionReviewError("APP_COIN_SELECTION_MODEL_DENIED")
        # Exact model classes still permit string subclasses in their fields.
        # Deny those before the upstream algorithm can compare/hash them.
        if (any(type(c.txid) is not str or type(c.cluster) is not str for c in coins)
                or type(intents[0].recipient) is not str):
            raise CoinSelectionReviewError("APP_COIN_SELECTION_MODEL_DENIED")
        chosen = Policy() if policy is None else policy
        if (type(chosen.exact_search_limit) is not int
                or not 1 <= chosen.exact_search_limit <= 18
                or type(chosen.exact_search_width) is not int
                or not 1 <= chosen.exact_search_width <= 4):
            raise CoinSelectionReviewError("APP_COIN_SELECTION_POLICY_DENIED")
        if (type(chosen.allow_cluster_merge) is not bool
                or chosen.allow_cluster_merge is not allow_cluster_merge):
            raise CoinSelectionReviewError("APP_COIN_SELECTION_CLUSTER_CONSENT_DENIED")
        result = select_coins(coins, intents, fee_atoms, chosen)
        if type(result) is not Selection:
            raise CoinSelectionReviewError("APP_COIN_SELECTION_RESULT_DENIED")
        event = redacted_event(result)
        if (type(event) is not dict
                or set(event) != {"schema", "selected_inputs", "cluster_count",
                                  "change_created", "warning_codes"}
                or type(event["schema"]) is not int or event["schema"] != 1
                or type(event["selected_inputs"]) is not int
                or not 1 <= event["selected_inputs"] <= 128
                or type(event["cluster_count"]) is not int
                or not 1 <= event["cluster_count"] <= 128
                or type(event["change_created"]) is not bool
                or type(event["warning_codes"]) is not list
                or len(event["warning_codes"]) > 2
                or any(type(w) is not str or w not in _SAFE_WARNINGS
                       for w in event["warning_codes"])
                or ("CLUSTER_MERGE" in event["warning_codes"])
                   != (event["cluster_count"] > 1)
                or ("CHANGE_CREATED" in event["warning_codes"])
                   != event["change_created"]):
            raise CoinSelectionReviewError("APP_COIN_SELECTION_RESULT_DENIED")
        return CoinSelectionReview(
            event["selected_inputs"], event["cluster_count"],
            event["change_created"], tuple(event["warning_codes"]),
        )
    except CoinSelectionReviewError:
        raise
    except Exception:
        raise CoinSelectionReviewError("APP_COIN_SELECTION_POLICY_DENIED") from None
