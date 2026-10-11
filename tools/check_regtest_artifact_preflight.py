"""Explicit local WAM Core binary-hash preflight (never executes a node).

A matching user-supplied SHA-256 is NOT publisher provenance or real-regtest
qualification. No network, subprocess, wallet, datadir, keys or secrets.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import sys

from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.core_source_pin import CoreSourceContractError, load_core_manifest
from wam_privacy_wallet.node.real_regtest import RealRegtestError, verify_binary

PIN = Path(__file__).resolve().parents[1] / "compat" / "wam_core_source_pin.json"


class ArtifactPreflightError(ValueError):
    """Stable failure code, no binary path or filesystem detail in the message."""


@dataclass(frozen=True, slots=True)
class LocalHashEvidence:
    """Local hash match only. No attestation or permission is represented."""

    sha256: str
    # All status/authority claims are non-configurable, even at construction.
    # This remains a data contract, not a sandbox against hostile Python code.
    profile_network: str = field(default="regtest", init=False)
    status: str = field(default="LOCAL_SHA256_MATCH_ONLY", init=False)
    real_regtest_qualified: bool = field(default=False, init=False)
    publisher_identity_verified: bool = field(default=False, init=False)
    binary_source_equivalence_verified: bool = field(default=False, init=False)
    execution_allowed: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        # Prevent malformed or noncanonical strings from masquerading as
        # evidence DTOs. A canonical SHA format is NOT proof of a real file,
        # publisher provenance, executable identity or launch permission.
        if type(self.sha256) is not str or re.fullmatch(
            r"[0-9a-f]{64}", self.sha256, flags=re.ASCII
        ) is None:
            raise ValueError("G1_LOCAL_EVIDENCE_DIGEST_INVALID")


def evaluate_local_binary(binary: object, expected_sha256: object) -> LocalHashEvidence:
    """Precheck explicit absolute path and digest without starting anything.

    This does not prove that the file is WAM Core; an independently verified
    publisher-provided digest and separate live regtest remain mandatory.
    """
    if not (type(binary) is str or isinstance(binary, Path)) or not str(binary):
        raise ArtifactPreflightError("G1_BINARY_PATH_REQUIRED")
    path = Path(binary)
    if not path.is_absolute():
        raise ArtifactPreflightError("G1_ABSOLUTE_PATH_REQUIRED")
    if type(expected_sha256) is not str:
        raise ArtifactPreflightError("G1_SHA256_REQUIRED")
    try:
        profile = load_core_manifest(PIN)
    except (CoreSourceContractError, OSError, ValueError):
        raise ArtifactPreflightError("G1_PINNED_PROFILE_REJECTED") from None
    if (
        profile["regtest_genesis"] != WAM_REGTEST_GENESIS
        or profile["network_ports"]["regtest"] != {"p2p": 29555, "rpc": 29554}
    ):
        raise ArtifactPreflightError("G1_PINNED_PROFILE_REJECTED")
    try:
        verify_binary(path, expected_sha256)
    except RealRegtestError as exc:
        # Expose only a fixed diagnostic code, never paths or exception chains.
        code = str(exc)
        if code not in ("CORE_SHA256_INVALID", "CORE_SHA256_MISMATCH",
                        "CORE_BINARY_NOT_REGULAR", "CORE_BINARY_UNAVAILABLE"):
            code = "CORE_BINARY_UNAVAILABLE"
        raise ArtifactPreflightError("G1_" + code) from None
    return LocalHashEvidence(sha256=expected_sha256)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare an explicit local file to an independently sourced SHA-256; does not execute it."
    )
    parser.add_argument("--binary", required=True, help="Absolute path; never auto-discovered")
    parser.add_argument("--sha256", required=True, help="Lowercase hex SHA-256 obtained independently")
    args = parser.parse_args(argv)
    try:
        evidence = evaluate_local_binary(args.binary, args.sha256)
    except ArtifactPreflightError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({
        "status": evidence.status,
        "profile_network": evidence.profile_network,
        "sha256": evidence.sha256,
        "real_regtest_qualified": evidence.real_regtest_qualified,
        "publisher_identity_verified": evidence.publisher_identity_verified,
        "binary_source_equivalence_verified": evidence.binary_source_equivalence_verified,
        "execution_allowed": evidence.execution_allowed,
        "release_allowed": evidence.release_allowed,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
