"""Direct pinned PayJoin model integration, not a PSBT/ownership verifier."""
from __future__ import annotations

from dataclasses import dataclass
import re

from .synthetic_policy_demo import _verify_source_bytes

_INPUT_FIELDS = frozenset(("txid", "vout", "atoms", "owner", "sequence",
                          "finalized", "utxo_present", "has_keypaths", "has_partial_signature"))
_OUTPUT_FIELDS = frozenset(("destination", "atoms", "owner"))
_TX_FIELDS = frozenset(("version", "locktime", "inputs", "outputs"))
_TXID = re.compile(r"[0-9a-f]{64}\Z")


class PayjoinProposalReviewError(ValueError):
    """No caller data or underlying exception in public errors."""


@dataclass(frozen=True, slots=True)
class PayjoinProposalReview:
    source_commit: str = "db3d2dcaa540f1129d540101813b761167d33174"
    evidence: str = "PINNED_MODEL_EXECUTED_UNTRUSTED_INPUT"
    psbt_verified: bool = False
    ownership_verified: bool = False
    sign_allowed: bool = False
    broadcast_allowed: bool = False


def _shape(tx: object) -> None:
    if type(tx) is not dict or set(tx) != _TX_FIELDS:
        raise ValueError
    # Bounds precede object construction and policy evaluation.
    if type(tx["version"]) is not int or type(tx["locktime"]) is not int:
        raise ValueError
    for key, fields, bound in (("inputs", _INPUT_FIELDS, 128), ("outputs", _OUTPUT_FIELDS, 256)):
        rows = tx[key]
        if type(rows) is not tuple or not 1 <= len(rows) <= bound:
            raise ValueError
        for row in rows:
            if type(row) is not dict or set(row) != fields:
                raise ValueError
            if type(row["atoms"]) is not int or type(row["owner"]) is not str:
                raise ValueError
            if key == "inputs":
                if (type(row["txid"]) is not str or _TXID.fullmatch(row["txid"]) is None
                        or type(row["vout"]) is not int or type(row["sequence"]) is not int
                        or any(type(row[k]) is not bool for k in (
                            "finalized", "utxo_present", "has_keypaths", "has_partial_signature"))):
                    raise ValueError
            else:
                value = row["destination"]
                if (type(value) is not str or not 1 <= len(value) <= 512
                        or any(ord(c) < 33 or ord(c) > 126 for c in value)):
                    raise ValueError


def review_synthetic_payjoin_proposal(
    original: object, proposal: object, *, payment_output_index: object,
    scope: object, consent: object,
) -> PayjoinProposalReview:
    """Strict zero sender fee contribution and no output substitution.

    Normalized caller annotations are synthetic/untrusted, not wire-derived.
    Consent permits local model execution only. Never retain transactions,
    return a signing handle or trust an injected PASS/ownership assertion.
    """
    try:
        if (type(scope) is not str or scope != "synthetic-regtest"
                or consent is not True or type(payment_output_index) is not int):
            raise ValueError
        _shape(original)
        _shape(proposal)
        _verify_source_bytes()
        from ..research_models.payjoin_safety.model import Transaction, TxInput, TxOutput, PayjoinContext
        from ..research_models.payjoin_safety.validator import validate_proposal

        def materialize(tx):
            return Transaction(tx["version"], tx["locktime"],
                tuple(TxInput(**dict(row)) for row in tx["inputs"]),
                tuple(TxOutput(**dict(row)) for row in tx["outputs"]))

        validate_proposal(materialize(original), materialize(proposal),
                         PayjoinContext(payment_output_index=payment_output_index))
    except Exception:
        raise PayjoinProposalReviewError("APP_PAYJOIN_PROPOSAL_REVIEW_DENIED") from None
    return PayjoinProposalReview()
