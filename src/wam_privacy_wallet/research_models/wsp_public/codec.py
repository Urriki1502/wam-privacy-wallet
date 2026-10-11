"""Strict Bech32m codec; long BIP352 codes intentionally exceed BIP173's 90 chars."""

ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def polymod(values):
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i, g in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            if (top >> i) & 1:
                chk ^= g
    return chk


def expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bits(data, source, target, pad=True):
    acc = count = 0
    result = []
    for value in data:
        if not 0 <= value < 1 << source:
            raise ValueError("INVALID_ENCODING")
        acc = ((acc << source) | value) & ((1 << (source + target - 1)) - 1)
        count += source
        while count >= target:
            count -= target
            result.append((acc >> count) & ((1 << target) - 1))
    if pad and count:
        result.append((acc << (target - count)) & ((1 << target) - 1))
    elif not pad and (count >= source or (acc << (target - count)) & ((1 << target) - 1)):
        raise ValueError("INVALID_PADDING")
    return result


def encode(hrp, payload, version=0, bech32m=True):
    if not hrp or hrp != hrp.lower() or any(not 33 <= ord(c) <= 126 for c in hrp):
        raise ValueError("INVALID_HRP")
    data = [version] + bits(payload, 8, 5)
    checksum = polymod(expand(hrp) + data + [0] * 6) ^ (0x2BC830A3 if bech32m else 1)
    return (
        hrp
        + "1"
        + "".join(ALPHABET[x] for x in data + [(checksum >> 5 * (5 - i)) & 31 for i in range(6)])
    )


def decode(address, hrp):
    if (
        not isinstance(address, str)
        or len(address) > 1023
        or address != address.lower()
        and address != address.upper()
    ):
        raise ValueError("INVALID_ADDRESS")
    address = address.lower()
    prefix, sep, tail = address.rpartition("1")
    if not sep or prefix != hrp or len(tail) < 7:
        raise ValueError("WRONG_NETWORK_OR_ADDRESS")
    try:
        data = [ALPHABET.index(c) for c in tail]
    except ValueError:
        raise ValueError("INVALID_ADDRESS") from None
    if polymod(expand(hrp) + data) != 0x2BC830A3 or data[0] != 0:
        raise ValueError("INVALID_VERSION_OR_CHECKSUM")
    return bytes(bits(data[1:-6], 5, 8, False))
