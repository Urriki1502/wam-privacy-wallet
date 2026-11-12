"""Offline signed WAM Core *successor* intake, never an executable approval.

Composes existing WAM pinned-publisher GPG verification primitives with the
NEXT-release ELF/GNU_STACK + inert wam.conf archive inspector. Requires an
operator-supplied authentic publisher key and signed checksum metadata; it
does not accept an arbitrary expected SHA as evidence of release identity.
No Core binary, miner, wallet or network connection is started.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import tempfile

from .core_signed_release import (
    WAM_RELEASE_SIGNING_FINGERPRINT,
    CoreReleaseSignatureError,
    _read_bounded_regular, _run_gpg, _gpg_primary_fingerprint,
    _validate_gpg_status,
)
from .core_next_release_audit import (
    CoreCandidateAuditError, inspect_next_linux_release,
)
from .core_artifact_staging import (
    CoreArtifactStagingError, stage_untrusted_core_artifact,
)

_RELEASE_NAME = re.compile(
    r"wam-coin-(v(0|[1-9][0-9]*)\.([0-9]+)\.([0-9]+))-x86_64-linux-gnu\.tar\.gz\Z",
    re.ASCII,
)
_SHA_LINE = re.compile(r"([0-9a-f]{64}) [ *]([A-Za-z0-9._-]+)\Z", re.ASCII)


class CoreSuccessorIntakeError(ValueError):
    """Fixed errors: no local paths, publisher key material or GPG output."""


@dataclass(frozen=True, slots=True)
class CoreSuccessorIntakeEvidence:
    archive_name: str
    archive_sha256: str = field(repr=False)
    config_sha256: str = field(repr=False)
    binary_names: tuple[str, ...] = ()
    binary_sha256: tuple[str, ...] = field(default=(), repr=False)
    signing_fingerprint: str = field(
        default=WAM_RELEASE_SIGNING_FINGERPRINT, init=False,
    )
    status: str = field(
        default="SIGNED_SUCCESSOR_STATIC_ARCHIVE_INSPECTED_NO_EXEC", init=False,
    )
    detached_signature_verified: bool = field(default=True, init=False)
    published_key_freshness_verified: bool = field(default=False, init=False)
    source_build_mapping_verified: bool = field(default=False, init=False)
    help_options_parity_verified: bool = field(default=False, init=False)
    os_loader_identity_verified: bool = field(default=False, init=False)
    process_identity_verified: bool = field(default=False, init=False)
    core_execution_allowed: bool = field(default=False, init=False)
    genuine_two_node_regtest_qualified: bool = field(default=False, init=False)
    wallet_operational: bool = field(default=False, init=False)
    signer_enabled: bool = field(default=False, init=False)
    broadcast_allowed: bool = field(default=False, init=False)
    mainnet_allowed: bool = field(default=False, init=False)


def _successor_name(archive: object) -> str:
    if type(archive) is not type(Path()) or not archive.is_absolute():
        raise CoreSuccessorIntakeError("CORE_SUCCESSOR_ARCHIVE_DENIED")
    name = archive.name
    match = _RELEASE_NAME.fullmatch(name)
    if match is None:
        raise CoreSuccessorIntakeError("CORE_SUCCESSOR_ARCHIVE_DENIED")
    version = tuple(int(match.group(i)) for i in (2, 3, 4))
    if version <= (0, 1, 11):
        # v0.1.11 is the legacy, independently verified but GNU_STACK RWE
        # release. Never accept it as a successor by renaming files.
        raise CoreSuccessorIntakeError("CORE_SUCCESSOR_VERSION_DENIED")
    return name


def _signed_successor_digest(sums: bytes, name: str) -> str:
    try:
        lines = sums.decode("ascii").splitlines()
    except UnicodeError:
        raise CoreSuccessorIntakeError("CORE_SUCCESSOR_SUMS_DENIED") from None
    if not 1 <= len(lines) <= 128:
        raise CoreSuccessorIntakeError("CORE_SUCCESSOR_SUMS_DENIED")
    found: dict[str, str] = {}
    casefolded: set[str] = set()
    for line in lines:
        m = _SHA_LINE.fullmatch(line)
        if m is None:
            raise CoreSuccessorIntakeError("CORE_SUCCESSOR_SUMS_DENIED")
        asset = m.group(2)
        folded = asset.casefold()
        if folded in casefolded:
            raise CoreSuccessorIntakeError("CORE_SUCCESSOR_SUMS_DENIED")
        casefolded.add(folded)
        found[asset] = m.group(1)
    if name not in found:
        raise CoreSuccessorIntakeError("CORE_SUCCESSOR_SIGNED_ASSET_MISSING")
    return found[name]


def _verified_gpg_digest(*, key: Path, sums: Path, signature: Path,
                         gpg: Path, archive_name: str) -> str:
    if (any(type(p) is not type(Path()) or not p.is_absolute()
            for p in (key, sums, signature, gpg))):
        raise CoreSuccessorIntakeError("CORE_SUCCESSOR_SIGNER_INPUT_DENIED")
    try:
        key_blob = _read_bounded_regular(key, 32_768)
        sums_blob = _read_bounded_regular(sums, 131_072)
        sig_blob = _read_bounded_regular(signature, 16_384)
        with tempfile.TemporaryDirectory(prefix="wam-successor-gpg-") as folder:
            home = Path(folder)
            if os.name != "nt":
                home.chmod(0o700)
            k, s, sig = (home / "key.asc", home / "SHA256SUMS",
                         home / "SHA256SUMS.asc")
            for target, blob in ((k, key_blob), (s, sums_blob), (sig, sig_blob)):
                with target.open("xb") as fp:
                    fp.write(blob)
                if os.name != "nt":
                    target.chmod(0o600)
            status, listed = _run_gpg(
                gpg, home, ("--with-colons", "--import-options",
                             "show-only", "--import", str(k)),
            )
            if status != 0:
                raise CoreSuccessorIntakeError("CORE_SUCCESSOR_SIGNER_DENIED")
            _gpg_primary_fingerprint(listed)
            imported, _ = _run_gpg(gpg, home, ("--import", str(k)))
            if imported != 0:
                raise CoreSuccessorIntakeError("CORE_SUCCESSOR_SIGNER_DENIED")
            verified, verdict = _run_gpg(
                gpg, home, ("--status-fd", "1", "--verify",
                            str(sig), str(s)),
            )
            if verified != 0:
                raise CoreSuccessorIntakeError("CORE_SUCCESSOR_SIGNATURE_DENIED")
            _validate_gpg_status(verdict)
            return _signed_successor_digest(sums_blob, archive_name)
    except CoreSuccessorIntakeError:
        raise
    except (OSError, ValueError, CoreReleaseSignatureError):
        raise CoreSuccessorIntakeError("CORE_SUCCESSOR_SIGNATURE_DENIED") from None


def inspect_signed_successor(*, archive: Path, signing_key: Path,
                             sha256sums: Path, detached_signature: Path,
                             gpg_executable: Path) -> CoreSuccessorIntakeEvidence:
    """Require a pinned-key detached signature THEN strict static ELF/config.

    This routine authenticates a *signed checksum file* under a pre-pinned
    fingerprint; it cannot prove that signer trust hasn't been revoked,
    associate a tag with a particular Core source commit, validate future
    help/config semantic parity, nor bind bytes to an executed process.
    """
    name = _successor_name(archive)
    digest = _verified_gpg_digest(
        key=signing_key, sums=sha256sums, signature=detached_signature,
        gpg=gpg_executable, archive_name=name,
    )
    try:
        # Redundant exact byte/member-size rechecking, with no process exec.
        with stage_untrusted_core_artifact(archive, digest) as staged:
            if (staged.sha256 != digest or
                    staged.core_execution_allowed is not False):
                raise CoreSuccessorIntakeError("CORE_SUCCESSOR_AUTHORITY_DENIED")
        static = inspect_next_linux_release(archive, digest)
    except (CoreArtifactStagingError, CoreCandidateAuditError):
        raise CoreSuccessorIntakeError("CORE_SUCCESSOR_STATIC_DENIED") from None
    if (static.archive_sha256 != digest
            or static.status != "CANDIDATE_RELEASE_STATIC_INSPECTION_ONLY"
            or not static.binary_names or "wamd" not in static.binary_names
            or any(getattr(static, attribute) is not False for attribute in (
                "signed_provenance_verified", "help_parity_verified",
                "dynamic_loader_verified", "kernel_process_identity_verified",
                "core_execution_allowed", "real_regtest_qualified",
                "signer_enabled", "broadcast_allowed", "mainnet_allowed"
            ))):
        raise CoreSuccessorIntakeError("CORE_SUCCESSOR_AUTHORITY_DENIED")
    return CoreSuccessorIntakeEvidence(
        archive_name=name,
        archive_sha256=digest,
        config_sha256=static.config_sha256,
        binary_names=static.binary_names,
        binary_sha256=static.binary_sha256,
    )
