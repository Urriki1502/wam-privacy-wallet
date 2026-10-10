"""G1-02: pure offline WAM Core artifact provenance *intake*, NOT verification.

An untrusted caller can manufacture a checksum, tag or release claim. This
module only rejects malformed candidate metadata and records it for review.
It never fetches artifacts, reads local files, runs Core or issues permission.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal

SOURCE_REPOSITORY = "wamcoin-core-dev/wam-coin"
REVIEWED_SOURCE_COMMIT = "260bc468e5adffea7ce68d8f97fac3e27e4c50b2"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_RELEASE = re.compile(r"v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\Z", re.ASCII)
_PLATFORMS = frozenset((
    "linux-x64", "linux-arm64", "windows-x86", "windows-x64",
    "macos-x64", "macos-arm64",
))
_FIELDS = frozenset((
    "schema", "repository", "reviewed_source_commit", "claimed_release",
    "platform", "binary_sha256", "publisher_proof", "real_regtest_qualified",
    "release_allowed",
))


class ProvenanceIntakeError(ValueError):
    """Stable error code; never echoes arbitrary untrusted metadata."""


@dataclass(frozen=True, slots=True)
class CoreArtifactCandidate:
    repository: Literal["wamcoin-core-dev/wam-coin"]
    reviewed_source_commit: str
    claimed_release: str
    platform: str
    binary_sha256: str
    status: Literal["UNTRUSTED_CANDIDATE_REVIEW_ONLY"] = "UNTRUSTED_CANDIDATE_REVIEW_ONLY"
    publisher_identity_verified: bool = False
    binary_source_equivalence_verified: bool = False
    real_regtest_qualified: bool = False
    execution_allowed: bool = False
    release_allowed: bool = False


def intake_core_artifact(payload: object) -> CoreArtifactCandidate:
    """Validate untrusted descriptive fields; never upgrade their trust level.

    Pinned inspected *source* does not prove any provided binary was built
    from those bytes. Even a matching binary hash isn't a signed attestation.
    """
    if type(payload) is not dict or set(payload) != _FIELDS:
        raise ProvenanceIntakeError("G1_PROVENANCE_SCHEMA_REJECTED")
    if (
        type(payload["schema"]) is not str
        or payload["schema"] != "wam-core-candidate-intake/v1"
        or type(payload["repository"]) is not str
        or payload["repository"] != SOURCE_REPOSITORY
        or type(payload["reviewed_source_commit"]) is not str
        or payload["reviewed_source_commit"] != REVIEWED_SOURCE_COMMIT
    ):
        raise ProvenanceIntakeError("G1_PROVENANCE_SOURCE_REJECTED")
    version = payload["claimed_release"]
    platform = payload["platform"]
    digest = payload["binary_sha256"]
    if type(version) is not str or _RELEASE.fullmatch(version) is None:
        raise ProvenanceIntakeError("G1_PROVENANCE_RELEASE_REJECTED")
    if type(platform) is not str or platform not in _PLATFORMS:
        raise ProvenanceIntakeError("G1_PROVENANCE_PLATFORM_REJECTED")
    if type(digest) is not str or _SHA256.fullmatch(digest) is None:
        raise ProvenanceIntakeError("G1_PROVENANCE_SHA256_REJECTED")
    if (
        type(payload["publisher_proof"]) is not str
        or payload["publisher_proof"] != "NOT_VERIFIED"
        or payload["real_regtest_qualified"] is not False
        or payload["release_allowed"] is not False
    ):
        raise ProvenanceIntakeError("G1_PROVENANCE_AUTHORITY_REJECTED")
    return CoreArtifactCandidate(
        repository=SOURCE_REPOSITORY,
        reviewed_source_commit=REVIEWED_SOURCE_COMMIT,
        claimed_release=version,
        platform=platform,
        binary_sha256=digest,
    )
