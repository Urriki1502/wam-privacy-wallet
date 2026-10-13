"""Direct pinned PayJoin model integration, not a PSBT/ownership verifier."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

from .synthetic_policy_demo import _verify_source_bytes
from .synthetic_input_shape import has_exact_primitive_fields

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
    if not has_exact_primitive_fields(tx, _TX_FIELDS):
        raise ValueError
    # Bounds precede object construction and policy evaluation.
    if type(tx["version"]) is not int or type(tx["locktime"]) is not int:
        raise ValueError
    for key, fields, bound in (("inputs", _INPUT_FIELDS, 128), ("outputs", _OUTPUT_FIELDS, 256)):
        rows = tx[key]
        if type(rows) is not tuple or not 1 <= len(rows) <= bound:
            raise ValueError
        for row in rows:
            if not has_exact_primitive_fields(row, fields):
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


@dataclass(frozen=True, slots=True)
class PayjoinPsbtReview:
    """Exact wire parsing and signature validity do not prove input ownership."""
    privacy_source_commit: str = "db3d2dcaa540f1129d540101813b761167d33174"
    wsp_source_commit: str = "ac55f13423620252bdbf848c7e8a280c3b84721e"
    evidence: str = "PINNED_PSBT_V2_PAYJOIN_REVIEW_UNQUALIFIED"
    ownership_verified: bool = False
    chain_verified: bool = False
    sign_allowed: bool = False
    broadcast_allowed: bool = False


def review_synthetic_payjoin_psbt_v2(
    original: object, proposal: object, *, source_root: object,
    payment_output_index: object, scope: object, consent: object,
) -> PayjoinPsbtReview:
    """Fixed read-only worker; strict P2TR, zero sender contribution profile.

    Consent authorizes this local fixture review only. Original inputs are
    candidate sender inputs, never an authenticated wallet ownership set.
    No PSBT, key, output, witness or signer object returns from the child.
    """
    try:
        if (consent is not True or type(scope) is not str or scope != "synthetic-regtest"
                or type(payment_output_index) is not int
                or not 0 <= payment_output_index < 256
                or any(type(raw) is not bytes or not 5 <= len(raw) <= 1_000_000
                       for raw in (original, proposal))
                or struct.calcsize("P") != 8
                or sys.platform not in ("linux", "darwin", "win32")):
            raise ValueError
        if (type(source_root) is not type(Path()) or not source_root.is_absolute()
                or source_root.is_symlink()):
            raise ValueError
        # Length framing preserves exact binary bytes; no filenames or commands
        # are accepted from a remote proposal. Index is a bounded local choice.
        payload = (payment_output_index.to_bytes(2, "big")
                   + len(original).to_bytes(4, "big") + original + proposal)
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-m",
             "wam_privacy_wallet.application._payjoin_psbt_worker",
             "--source-root", str(source_root)],
            input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=30, check=False,
        )
        if result.returncode != 0 or not 1 <= len(result.stdout) <= 2048:
            raise ValueError
        data = json.loads(result.stdout)
        expected = PayjoinPsbtReview()
        if (type(data) is not dict or len(data) != len(expected.__slots__)
                or any(type(k) is not str for k in data)
                or set(data) != set(expected.__slots__)
                or any(type(data[k]) is not type(getattr(expected, k))
                       or data[k] != getattr(expected, k) for k in data)):
            raise ValueError
        return expected
    except Exception:
        raise PayjoinProposalReviewError("APP_PAYJOIN_PSBT_REVIEW_DENIED") from None
