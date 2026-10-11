"""Non-payable Receive preview from one pinned, PUBLIC WSP-1 test vector.

This module does not derive addresses, keys or accounts, and never starts a
scanner, RPC client, wallet or signer. The upstream public fixture is already
known; only its Bech32m checksum and public data layout are inspected. Never
present any string from this fixture as a recipient or user deposit address.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha1, sha256
from pathlib import Path
from typing import Literal

UPSTREAM_REPOSITORY = "Urriki1502/wam-silent-payments"
UPSTREAM_COMMIT_SHA = "ac55f13423620252bdbf848c7e8a280c3b84721e"
UPSTREAM_VECTOR_PATH = "tests/vectors/wsp1-wallet.json"
UPSTREAM_VECTOR_BLOB_SHA = "67c77f1c60ed574d81e20147689d9fafc8797991"
# Independently recorded digest of the one public address in that fixture.
PUBLIC_VECTOR_SHA256 = "5a0f212b2e6153242f68576d3b7e7649e17dbfe98a8235448849e59870dfaaf4"
UPSTREAM_CODEC_PATH = "src/wam_sp/codec.py"
UPSTREAM_CODEC_BLOB_SHA = "ec28511113f055ce587f3bfabcd97608a3dfed56"
EXPECTED_HRP = "wamrtsp"
# Only the public synthetic fixture address is copied. Source seed, scan
# private key, spend key and transaction/payment vector are NEVER vendored.
_PUBLIC_ONLY_VECTOR = (
    "wamrtsp1qq2kcg56metldmeyqlrxu66qwhnevpdt2r9g7ywwrxcqq0umrz45n2q"
    "h4amhz06a2nnvq4ct98u99v0zyzc792uzr5zraml3fs6etrkt7nqexejtf"
)
_CODEC_FILE = (
    Path(__file__).resolve().parents[1]
    / "research_models"
    / "wsp_public"
    / "codec.py"
)
_FIXED_FINGERPRINT = PUBLIC_VECTOR_SHA256[:16]


class ReceiveVectorError(ValueError):
    """Fixed failure code; never echo an address, seed, path or caller input."""


@dataclass(frozen=True, slots=True)
class ReceiveVectorPreview:
    """Display-only immutable record, never a receive address/capability."""

    profile: Literal["WSP-1"]
    network: Literal["regtest"]
    provenance: Literal["PIN_RECORDED_UNATTESTED"]
    sample: Literal["PUBLIC_SYNTHETIC_FIXTURE"]
    fingerprint: str
    receive: Literal["BLOCKED"]
    scanner: Literal["BLOCKED"]
    signer: Literal["BLOCKED"]


def _deny() -> None:
    raise ReceiveVectorError("APP_RECEIVE_PUBLIC_VECTOR_DENIED")


def inspect_pinned_public_vector(
    public_address: object = _PUBLIC_ONLY_VECTOR,
    *,
    network: object = "regtest",
    source_commit: object = UPSTREAM_COMMIT_SHA,
) -> ReceiveVectorPreview:
    """Check exactly one public fixture, without deriving or returning addresses.

    A Git blob SHA is only a local byte-integrity check and an upstream pin;
    it is NOT a signature, Core attestation, or permission to receive funds.
    The public address is fixed, and arbitrary user-provided addresses cannot
    be processed by this research-only adapter.
    """
    if (
        type(public_address) is not str
        or public_address != _PUBLIC_ONLY_VECTOR
        or type(network) is not str
        or network != "regtest"
        or type(source_commit) is not str
        or source_commit != UPSTREAM_COMMIT_SHA
    ):
        _deny()
    if sha256(public_address.encode("ascii")).hexdigest() != PUBLIC_VECTOR_SHA256:
        _deny()
    try:
        raw = _CODEC_FILE.read_bytes()
    except OSError:
        _deny()
    blob = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    if sha1(blob).hexdigest() != UPSTREAM_CODEC_BLOB_SHA:
        _deny()

    # Import only after byte verification; upstream wallet API, scanner,
    # keys, signing, transport and WAM Core modules are never imported.
    from wam_privacy_wallet.research_models.wsp_public import codec

    try:
        payload = codec.decode(public_address, EXPECTED_HRP)
    except ValueError:
        _deny()
    if (
        type(payload) is not bytes
        or len(payload) != 66
        or payload[0] not in (2, 3)
        or payload[33] not in (2, 3)
    ):
        _deny()
    return ReceiveVectorPreview(
        "WSP-1",
        "regtest",
        "PIN_RECORDED_UNATTESTED",
        "PUBLIC_SYNTHETIC_FIXTURE",
        _FIXED_FINGERPRINT,
        "BLOCKED",
        "BLOCKED",
        "BLOCKED",
    )
