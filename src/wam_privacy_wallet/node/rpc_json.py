"""Unambiguous bounded RPC JSON; money never passes through binary floats.

Reuses the Decimal / duplicate-key / non-finite rejection pattern in pinned
WSP-1 wam_sp.rpc (ac55f134...), without importing its broader RPC privileges.
The caller retains responsibility for HTTP size limits and method schemas.
"""
from __future__ import annotations

import json
from decimal import Decimal


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("RPC_JSON_DENIED")
        result[key] = value
    return result


def _constant(_value: str) -> object:
    raise ValueError("RPC_JSON_DENIED")


def _decimal(value: str) -> Decimal:
    if len(value) > 64:
        raise ValueError("RPC_JSON_DENIED")
    result = Decimal(value)
    if not result.is_finite() or abs(result.as_tuple().exponent) > 64:
        raise ValueError("RPC_JSON_DENIED")
    return result


def _integer(value: str) -> int:
    if len(value) > 128:
        raise ValueError("RPC_JSON_DENIED")
    return int(value)


def decode_rpc_json(raw: bytes) -> object:
    """Strict UTF-8, exact decimals, no duplicate keys at any nesting depth."""
    try:
        result = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique,
            parse_float=_decimal, parse_int=_integer, parse_constant=_constant,
        )
        # Do not depend on a host's configurable Python recursion limit.
        pending = [(result, 0)]
        while pending:
            value, depth = pending.pop()
            if depth > 64:
                raise ValueError("RPC_JSON_DENIED")
            if type(value) is dict:
                pending.extend((v, depth + 1) for v in value.values())
            elif type(value) is list:
                pending.extend((v, depth + 1) for v in value)
        return result
    except (ValueError, UnicodeError, ArithmeticError, RecursionError):
        raise ValueError("RPC_JSON_DENIED") from None
