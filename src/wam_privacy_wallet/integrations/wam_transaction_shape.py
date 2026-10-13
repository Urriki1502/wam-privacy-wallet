"""WAM RPC transaction boundary, ahead of the source-pinned WSP scanner.

No signature, consensus or address-ownership verification occurs here.
Script bytes, not RPC address/type annotations, feed upstream WSP eligibility.
Limits match the pinned scanner; WAM's output count/reward split is not fixed.
"""
from __future__ import annotations

import re
from decimal import Decimal, localcontext

_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_HEX = re.compile(r"(?:[0-9a-f]{2})*\Z", re.ASCII)
_MAX_MONEY = 22_000_000 * 100_000_000


class WamTransactionShapeError(ValueError):
    """Fixed refusal, without response data or credentials."""


def _deny() -> None:
    raise WamTransactionShapeError("WAM_TX_SHAPE_DENIED")


def _hash(value: object) -> None:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        _deny()


def _hex(value: object, maximum: int, *, minimum: int = 0) -> int:
    if (type(value) is not str or not minimum * 2 <= len(value) <= maximum * 2
            or _HEX.fullmatch(value) is None):
        _deny()
    return len(value) // 2


def _atoms(value: object) -> int:
    # HTTP parsing produces Decimal, never float. Use sufficient precision
    # for the entire bounded literal so fractional atoms cannot round away.
    if type(value) is int:
        result = value * 100_000_000
    elif type(value) is Decimal:
        if (not value.is_finite() or len(value.as_tuple().digits) > 64
                or abs(value.as_tuple().exponent) > 64):
            _deny()
        if not 0 <= value <= 22_000_000:
            _deny()
        with localcontext() as context:
            context.prec = 128
            scaled = value * 100_000_000
            result = int(scaled)
            if scaled != result:
                _deny()
    else:
        _deny()
    if not 0 <= result <= _MAX_MONEY:
        _deny()
    return result


def _output(output: object, *, index: int | None = None) -> tuple[int, int]:
    if type(output) is not dict:
        _deny()
    if index is not None and (type(output.get("n")) is not int
                              or output["n"] != index):
        _deny()
    script = output.get("scriptPubKey")
    if type(script) is not dict:
        _deny()
    return _atoms(output.get("value")), _hex(script.get("hex"), 10_000)


def validate_wam_transaction(tx: object, *, require_prevouts: bool) -> bool:
    """Return coinbase classification, with no mutation or synthetic filling.

    Confirmed getblock(...,3) requires every ordinary prevout. Raw transaction
    views may omit prevouts: upstream can read the real parent via verbosity 1.
    Any provided prevout is always validated, even on a mempool response.
    """
    if type(tx) is not dict or type(require_prevouts) is not bool:
        _deny()
    _hash(tx.get("txid"))
    vin, vout = tx.get("vin"), tx.get("vout")
    if (type(vin) is not list or not 1 <= len(vin) <= 2_048
            or type(vout) is not list or not 1 <= len(vout) <= 4_096):
        _deny()
    coinbase = False
    outpoints: set[tuple[str, int]] = set()
    script_bytes = 0
    for entry in vin:
        if type(entry) is not dict:
            _deny()
        if "coinbase" in entry:
            if len(vin) != 1 or any(k in entry for k in ("txid", "vout", "prevout")):
                _deny()
            script_bytes += _hex(entry["coinbase"], 100, minimum=1)
            coinbase = True
        else:
            _hash(entry.get("txid"))
            n = entry.get("vout")
            if type(n) is not int or not 0 <= n <= 0xffffffff:
                _deny()
            outpoint = (entry["txid"], n)
            if outpoint in outpoints:
                _deny()
            outpoints.add(outpoint)
            if "prevout" in entry:
                _, size = _output(entry["prevout"])
                script_bytes += size
            elif require_prevouts:
                _deny()
        if "scriptSig" in entry:
            script = entry["scriptSig"]
            if type(script) is not dict:
                _deny()
            script_bytes += _hex(script.get("hex"), 10_000)
        if "txinwitness" in entry:
            witness = entry["txinwitness"]
            if type(witness) is not list or len(witness) > 1_000:
                _deny()
            for item in witness:
                script_bytes += _hex(item, 10_000)
        if script_bytes > 1_000_000:
            _deny()
    total = 0
    for index, output in enumerate(vout):
        atoms, size = _output(output, index=index)
        total += atoms
        script_bytes += size
        if total > _MAX_MONEY or script_bytes > 1_000_000:
            _deny()
    return coinbase
