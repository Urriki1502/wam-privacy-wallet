"""Match untrusted WAM Core candidate metadata to nonexecuting staged bytes.

The allowlisted source SHA proves neither release provenance nor binary build
equivalence. No publisher trust root has been supplied by DEV WAM yet, so
this bridge never grants WAM Core launch, even on a matching host and digest.
"""
from __future__ import annotations

from contextlib import contextmanager
import platform
import struct
import sys
from typing import Iterator

from .core_artifact_staging import (
    CoreArtifactStagingEvidence, CoreArtifactStagingError,
    stage_untrusted_core_artifact,
)
from .provenance_intake import (
    CoreArtifactCandidate, ProvenanceIntakeError, intake_core_artifact,
)


class CoreCandidateBridgeError(ValueError):
    """Fixed redacted denial code, not an executable or publisher approval."""


def _native_runtime_platform() -> str | None:
    """Supported *process* architecture; never an authority or OS sandbox."""
    bits = struct.calcsize("P") * 8
    machine = platform.machine().casefold()
    if sys.platform == "win32" and bits in (32, 64):
        return "windows-x86" if bits == 32 else "windows-x64"
    if sys.platform == "darwin" and bits == 64:
        if machine in ("x86_64", "amd64"):
            return "macos-x64"
        if machine in ("arm64", "aarch64"):
            return "macos-arm64"
    if sys.platform.startswith("linux") and bits == 64:
        if machine in ("x86_64", "amd64"):
            return "linux-x64"
        if machine in ("arm64", "aarch64"):
            return "linux-arm64"
    return None


@contextmanager
def review_local_core_candidate(
    candidate_metadata: object, source: object,
) -> Iterator[tuple[CoreArtifactCandidate, CoreArtifactStagingEvidence]]:
    """Reject false provenance claims before reading/duplicating any bytes.

    This bridges the separately tested intake schema to an actual local-file
    digest match, and ensures the declared platform matches the Python host.
    It cannot prove a binary was released or built by a trusted publisher.
    Any staged evidence remains OFFLINE_STAGED_UNTRUSTED with all permissions
    denied. The snapshot is destroyed after the context exits.
    """
    try:
        candidate = intake_core_artifact(candidate_metadata)
    except ProvenanceIntakeError:
        raise CoreCandidateBridgeError("CORE_CANDIDATE_INTAKE_DENIED") from None
    native = _native_runtime_platform()
    if native is None:
        raise CoreCandidateBridgeError("CORE_CANDIDATE_HOST_UNSUPPORTED")
    if candidate.platform != native:
        raise CoreCandidateBridgeError("CORE_CANDIDATE_PLATFORM_MISMATCH")
    try:
        with stage_untrusted_core_artifact(
            source, candidate.binary_sha256, network="regtest",
        ) as staged:
            if (staged.core_execution_allowed is not False
                    or staged.mainnet_allowed is not False
                    or staged.publisher_verified is not False
                    or staged.execution_identity_bound is not False
                    or candidate.execution_allowed is not False
                    or candidate.publisher_identity_verified is not False):
                raise CoreCandidateBridgeError("CORE_CANDIDATE_AUTHORITY_DENIED")
            yield candidate, staged
    except CoreArtifactStagingError:
        raise CoreCandidateBridgeError("CORE_CANDIDATE_STAGING_DENIED") from None
