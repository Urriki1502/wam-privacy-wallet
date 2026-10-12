"""Consent-gated execution of an installed PUBLIC synthetic HPKE fixture worker.

The local build manifest detects byte changes, not publisher/runtime authenticity.
No key/note input, plaintext, ciphertext, spend capability or release permission
crosses this boundary. External upstream review remains incomplete.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys

_PIN = "db3d2dcaa540f1129d540101813b761167d33174"
_NATIVE = Path(__file__).resolve().parents[1] / "integrations" / "_native"
_MANIFEST_FIELDS = frozenset(("source_commit", "worker_sha256", "pointer_bits", "platform", "release_allowed"))
_FIELDS = frozenset(("source_commit", "role", "negative_checks", "pointer_bits", "evidence",
                    "external_review_complete", "runtime_authenticated", "spend_authorized",
                    "sign_allowed", "broadcast_allowed"))


class SelectiveDisclosureReviewError(ValueError):
    """Fixed denial without local paths or private/native errors."""


@dataclass(frozen=True, slots=True)
class SelectiveDisclosureReview:
    role: str
    negative_checks: int
    source_commit: str = _PIN
    evidence: str = "PUBLIC_HPKE_FIXTURE_EXECUTED_UNTRUSTED"
    external_review_complete: bool = False
    runtime_authenticated: bool = False
    spend_authorized: bool = False
    sign_allowed: bool = False
    broadcast_allowed: bool = False


def review_public_disclosure_fixture(*, role: object, scope: object, consent: object) -> SelectiveDisclosureReview:
    """Only two fixed public fixture requests; no caller-selected executable."""
    if (consent is not True or type(scope) is not str or scope != "synthetic-regtest"
            or type(role) is not str or role not in ("incoming", "audit")
            or sys.platform not in ("linux", "darwin", "win32")):
        raise SelectiveDisclosureReviewError("APP_DISCLOSURE_FIXTURE_DENIED")
    try:
        executable = _NATIVE / ("wam-wallet-hpke-readonly.exe" if sys.platform == "win32" else "wam-wallet-hpke-readonly")
        manifest = _NATIVE / "hpke-public-fixture-build.json"
        if _NATIVE.is_symlink() or executable.is_symlink() or manifest.is_symlink():
            raise ValueError
        if not 1 <= manifest.stat().st_size <= 1024 or not 1 <= executable.stat().st_size <= 64_000_000:
            raise ValueError
        with manifest.open("rb") as stream:
            encoded_build = stream.read(1025)
        if len(encoded_build) > 1024: raise ValueError
        build = json.loads(encoded_build)
        with executable.open("rb") as stream:
            executable_bytes = stream.read(64_000_001)
        if len(executable_bytes) > 64_000_000: raise ValueError
        if (type(build) is not dict or set(build) != _MANIFEST_FIELDS
                or build["source_commit"] != _PIN or build["platform"] != sys.platform
                or type(build["pointer_bits"]) is not int or build["pointer_bits"] != struct.calcsize("P") * 8
                or build["release_allowed"] is not False
                or type(build["worker_sha256"]) is not str or len(build["worker_sha256"]) != 64
                or sha256(executable_bytes).hexdigest() != build["worker_sha256"]):
            raise ValueError
        # This is an own-package research worker, not an authenticated loader.
        # The fixed request can neither supply key material nor select a path.
        result = subprocess.run([str(executable)],
            input=f"PUBLIC_SYNTHETIC_HPKE_V1:{role}\n".encode("ascii"),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=False)
        if result.returncode != 0 or not 1 <= len(result.stdout) <= 2048:
            raise ValueError
        data = json.loads(result.stdout)
        if (type(data) is not dict or set(data) != _FIELDS
                or data["source_commit"] != _PIN or data["role"] != role
                or data["evidence"] != "PUBLIC_HPKE_FIXTURE_EXECUTED_UNTRUSTED"
                or type(data["negative_checks"]) is not int or data["negative_checks"] != 14
                or type(data["pointer_bits"]) is not int or data["pointer_bits"] != struct.calcsize("P") * 8
                or any(data[k] is not False for k in ("external_review_complete", "runtime_authenticated",
                    "spend_authorized", "sign_allowed", "broadcast_allowed"))):
            raise ValueError
        return SelectiveDisclosureReview(role, 14)
    except Exception:
        raise SelectiveDisclosureReviewError("APP_DISCLOSURE_FIXTURE_DENIED") from None
