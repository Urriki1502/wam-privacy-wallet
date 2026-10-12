"""Consent-gated synthetic PSBTv2 review in a fixed isolated Python worker.

No signer handles, transaction bytes, scripts, outpoints or amounts are returned.
An executed parser is not chain inclusion, ownership or signing authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import struct
import subprocess
import sys

_MAX_BYTES = 1_000_000
_PIN = "ac55f13423620252bdbf848c7e8a280c3b84721e"
_FIELDS = frozenset(("source_commit", "evidence", "input_count", "output_count",
                     "ownership_verified", "chain_verified", "sign_allowed",
                     "broadcast_allowed"))


class PsbtV2ReviewError(ValueError):
    """Fixed public code, never private PSBT contents, paths or child errors."""


@dataclass(frozen=True, slots=True)
class PsbtV2Review:
    input_count: int
    output_count: int
    source_commit: str = _PIN
    evidence: str = "PINNED_UNSIGNED_PSBT_V2_PARSED_UNTRUSTED"
    ownership_verified: bool = False
    chain_verified: bool = False
    sign_allowed: bool = False
    broadcast_allowed: bool = False


def review_synthetic_psbt_v2(
    raw: object, *, source_root: object, scope: object, consent: object,
) -> PsbtV2Review:
    """Parse unsigned v2 fixtures only; installed pinned source is required.

    The 32-bit dependency build is unqualified. A dedicated child keeps mutable
    upstream parser/signer objects out of the application and Qt process.
    This is bounded research execution, not hostile-code isolation or custody.
    """
    if (consent is not True or type(scope) is not str or scope != "synthetic-regtest"
            or type(raw) is not bytes or not 5 <= len(raw) <= _MAX_BYTES):
        raise PsbtV2ReviewError("APP_PSBT_V2_REVIEW_DENIED")
    if struct.calcsize("P") != 8 or sys.platform not in ("linux", "darwin", "win32"):
        raise PsbtV2ReviewError("APP_PSBT_V2_PLATFORM_UNQUALIFIED")
    try:
        if (type(source_root) is not type(Path()) or not source_root.is_absolute()
                or source_root.is_symlink()):
            raise ValueError
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-m",
             "wam_privacy_wallet.application._psbt_v2_worker",
             "--source-root", str(source_root)],
            input=raw, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=30, check=False,
        )
        if result.returncode != 0 or not 1 <= len(result.stdout) <= 2048:
            raise ValueError
        data = json.loads(result.stdout)
        if type(data) is not dict or set(data) != _FIELDS:
            raise ValueError
        if (data["source_commit"] != _PIN
                or data["evidence"] != "PINNED_UNSIGNED_PSBT_V2_PARSED_UNTRUSTED"
                or type(data["input_count"]) is not int or not 1 <= data["input_count"] <= 128
                or type(data["output_count"]) is not int or not 1 <= data["output_count"] <= 256
                or any(data[k] is not False for k in (
                    "ownership_verified", "chain_verified", "sign_allowed", "broadcast_allowed"))):
            raise ValueError
        return PsbtV2Review(data["input_count"], data["output_count"])
    except Exception:
        raise PsbtV2ReviewError("APP_PSBT_V2_REVIEW_DENIED") from None
