"""Bounded primitive dictionary schema checks without caller key callbacks."""
from __future__ import annotations


def has_exact_primitive_fields(value: object, fields: frozenset[str]) -> bool:
    """Check count/type before hashing/comparing any caller-supplied key.

    Exact dict type prevents custom container methods; exact str keys prevent
    str-subclass equality/hash callbacks. Count bounds the temporary set.
    """
    return (
        type(value) is dict
        and len(value) == len(fields)
        and all(type(key) is str for key in value)
        and set(value) == fields
    )
