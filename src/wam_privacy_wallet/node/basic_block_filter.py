"""Bounded BIP-158 BASIC serialization and BIP-157 header consistency.

Format: bitcoin/bips bip-0158.mediawiki and bip-0157.mediawiki. This is a
parser, not a SipHash matcher, consensus verifier or silent-payment prefilter.
No block may be skipped by the WSP scanner based on this module.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

_HEX = re.compile(r"(?:[0-9a-f]{2})*\Z", re.ASCII)
_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_BYTES = 1_048_576
_MAX_ELEMENTS = 100_000
_P = 19
_M = 784_931


class BasicFilterError(ValueError):
    """Redacted fixed-code malformed/unsupported filter refusal."""


@dataclass(frozen=True, slots=True)
class ParsedBasicFilter:
    element_count: int
    byte_count: int
    filter_hash: str


def _deny() -> None:
    raise BasicFilterError("CORE_BASIC_FILTER_DENIED")


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def parse_basic_filter(encoded: object) -> ParsedBasicFilter:
    """Canonical CompactSize, Golomb-Rice range, exact zero-padding and caps.

    Hashed set elements are decoded incrementally without retaining a set.
    Collisions/equal elements are legitimate. Limits are wallet resource bounds,
    not changes to WAM consensus. Even a valid encoding may be a dishonest peer.
    """
    if (type(encoded) is not str or not 2 <= len(encoded) <= _MAX_BYTES * 2
            or _HEX.fullmatch(encoded) is None):
        _deny()
    raw = bytes.fromhex(encoded)
    prefix = raw[0]
    if prefix < 253:
        count, offset = prefix, 1
    else:
        size, minimum = {253: (2, 253), 254: (4, 65536),
                         255: (8, 4294967296)}[prefix]
        if len(raw) < 1 + size:
            _deny()
        count, offset = int.from_bytes(raw[1:1 + size], "little"), 1 + size
        if count < minimum:
            _deny()
    if count > _MAX_ELEMENTS:
        _deny()
    if count == 0:
        if len(raw) != 1:
            _deny()
    else:
        position = offset * 8
        end = len(raw) * 8
        if end - position < count * (_P + 1):
            _deny()
        value = 0
        limit = count * _M
        for _ in range(count):
            quotient = 0
            # Each delta must leave the cumulative hash in [0, N*M).
            maximum = (limit - 1 - value) >> _P
            while True:
                if position >= end:
                    _deny()
                bit = (raw[position >> 3] >> (7 - (position & 7))) & 1
                position += 1
                if bit == 0:
                    break
                quotient += 1
                if quotient > maximum:
                    _deny()
            if end - position < _P:
                _deny()
            remainder = 0
            for _ in range(_P):
                remainder = (remainder << 1) | (
                    (raw[position >> 3] >> (7 - (position & 7))) & 1)
                position += 1
            value += (quotient << _P) + remainder
            if value >= limit:
                _deny()
        if end - position > 7:
            _deny()
        if (end - position) and raw[-1] & ((1 << (end - position)) - 1):
            _deny()
    return ParsedBasicFilter(count, len(raw), _sha256d(raw)[::-1].hex())


def validate_filter_header(encoded: object, header: object,
                           previous_header: object) -> ParsedBasicFilter:
    """Check a reported header against this filter and a reported parent.

    RPC uint256 strings are display-endian; hashing uses little-endian bytes.
    This relation supplies consistency, never independent chain authentication.
    """
    for value in (header, previous_header):
        if type(value) is not str or _HASH.fullmatch(value) is None:
            _deny()
    result = parse_basic_filter(encoded)
    expected = _sha256d(bytes.fromhex(result.filter_hash)[::-1]
                        + bytes.fromhex(previous_header)[::-1])[::-1].hex()
    if header != expected:
        _deny()
    return result
