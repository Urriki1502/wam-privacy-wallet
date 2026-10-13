"""Verify WAM's detached *distribution archive* release signature offline.

A SHA256SUMS match without a signature proves only integrity relative to a
caller-supplied list. An independently pinned WAM signing fingerprint plus
GnuPG can instead validate the release archive hash listed in signed bytes.
This never authenticates an *extracted* executable or binds bytes to Popen.
The installed GnuPG tool itself and the trust anchor require operator review.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from .core_artifact_staging import (
    CoreArtifactStagingError, stage_untrusted_core_artifact,
)

# Independent HTTPS WAM project security page: https://wamcoin.org/security/
# Do NOT accept a user-provided replacement fingerprint in this API.
WAM_RELEASE_SIGNING_FINGERPRINT = "4BD4A8D3AFD43F5CBCB500E23798462FE00ADBA4"
RELEASE_TAG = "v0.1.11"
RELEASE_ASSETS = frozenset((
    "wam-coin-v0.1.11-x86_64-linux-gnu.tar.gz",
    "wam-coin-v0.1.11-arm64-apple-darwin.tar.gz",
    "wam-coin-v0.1.11-x86_64-w64-mingw32.zip",
))
_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_LINE = re.compile(r"([0-9a-f]{64}) [ *]([A-Za-z0-9._-]+)\Z", re.ASCII)


class CoreReleaseSignatureError(ValueError):
    """Redacted denial; no release signature data or file path is echoed."""


@dataclass(frozen=True, slots=True)
class SignedDistributionEvidence:
    """Verified archive checksum is NEVER an approval to execute WAM Core."""

    archive_name: str
    distribution_sha256: str = field(repr=False)
    signing_fingerprint: str = field(
        default=WAM_RELEASE_SIGNING_FINGERPRINT, init=False,
    )
    status: str = field(default="SIGNED_DISTRIBUTION_ONLY", init=False)
    extracted_binary_verified: bool = field(default=False, init=False)
    execution_identity_bound: bool = field(default=False, init=False)
    core_execution_allowed: bool = field(default=False, init=False)
    mainnet_allowed: bool = field(default=False, init=False)
    real_wallet_allowed: bool = field(default=False, init=False)


def _read_bounded_regular(path: object, limit: int) -> bytes:
    if type(path) not in (str, type(Path())):
        raise CoreReleaseSignatureError("CORE_RELEASE_FILE_DENIED")
    try:
        file = Path(path)
        before = file.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size < 1 or before.st_size > limit
                or (getattr(before, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))):
            raise CoreReleaseSignatureError("CORE_RELEASE_FILE_DENIED")
        options = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            options |= os.O_NOFOLLOW
        with os.fdopen(os.open(file, options), "rb") as inp:
            observed = os.fstat(inp.fileno())
            if (observed.st_dev != before.st_dev
                    or observed.st_ino != before.st_ino
                    or observed.st_size != before.st_size
                    or observed.st_mtime_ns != before.st_mtime_ns):
                raise CoreReleaseSignatureError("CORE_RELEASE_FILE_CHANGED")
            data = inp.read(limit + 1)
            after = os.fstat(inp.fileno())
            now = file.lstat()
            if (len(data) != before.st_size or len(data) > limit
                    or after.st_size != before.st_size
                    or after.st_mtime_ns != before.st_mtime_ns
                    or now.st_dev != before.st_dev or now.st_ino != before.st_ino
                    or now.st_size != before.st_size
                    or now.st_mtime_ns != before.st_mtime_ns):
                raise CoreReleaseSignatureError("CORE_RELEASE_FILE_CHANGED")
            return data
    except CoreReleaseSignatureError:
        raise
    except (OSError, TypeError, ValueError):
        raise CoreReleaseSignatureError("CORE_RELEASE_FILE_DENIED") from None


def _signed_digest(sums: bytes, archive_name: str) -> str:
    """Only a signed exact archive basename may supply the expected digest."""
    if archive_name not in RELEASE_ASSETS:
        raise CoreReleaseSignatureError("CORE_RELEASE_ASSET_DENIED")
    try:
        lines = sums.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise CoreReleaseSignatureError("CORE_RELEASE_SUMS_DENIED") from None
    if not lines or len(lines) > 128:
        raise CoreReleaseSignatureError("CORE_RELEASE_SUMS_DENIED")
    found = {}
    for line in lines:
        hit = _LINE.fullmatch(line)
        if hit is None or hit.group(2) in found:
            raise CoreReleaseSignatureError("CORE_RELEASE_SUMS_DENIED")
        found[hit.group(2)] = hit.group(1)
    if archive_name not in found:
        raise CoreReleaseSignatureError("CORE_RELEASE_ASSET_MISSING")
    return found[archive_name]


def _run_gpg(
    gpg_executable: Path, homedir: Path, args: tuple[str, ...],
    *,
    timeout: int = 12,
) -> tuple[int, str]:
    """Invoke caller-reviewed local GnuPG binary without a shell or network."""
    env = {key: os.environ[key] for key in
           ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATH") if key in os.environ}
    env["GNUPGHOME"] = str(homedir)
    env["HOME"] = str(homedir)
    env["LC_ALL"] = "C"
    try:
        cp = subprocess.run(
            [str(gpg_executable), "--homedir", str(homedir), "--batch",
             "--no-tty", "--no-options", "--no-auto-key-retrieve",
             "--no-autostart", *args],
            shell=False, check=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            cwd=homedir, env=env, timeout=timeout,
        )
        return cp.returncode, cp.stdout.decode("utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        raise CoreReleaseSignatureError("CORE_RELEASE_GPG_UNAVAILABLE") from None


def _gpg_primary_fingerprint(colon_listing: str) -> str:
    """Require one and only one primary key whose FPR matches pinned trust."""
    state, primaries = "", []
    for line in colon_listing.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            state = "pub"
        elif fields[0] == "sub":
            state = "sub"
        elif fields[0] == "fpr" and len(fields) > 9 and state == "pub":
            primaries.append(fields[9])
    if primaries != [WAM_RELEASE_SIGNING_FINGERPRINT]:
        raise CoreReleaseSignatureError("CORE_RELEASE_SIGNER_DENIED")
    return primaries[0]


def _validate_gpg_status(stdout: str) -> None:
    valid = []
    good = 0
    for raw in stdout.splitlines():
        if not raw.startswith("[GNUPG:] "):
            continue
        parts = raw[9:].split()
        if not parts:
            continue
        if parts[0] in ("BADSIG", "ERRSIG", "REVKEYSIG", "EXPKEYSIG",
                        "KEYEXPIRED", "SIGEXPIRED", "NO_PUBKEY", "FAILURE"):
            raise CoreReleaseSignatureError("CORE_RELEASE_SIGNATURE_DENIED")
        if parts[0] == "GOODSIG":
            good += 1
        if parts[0] == "VALIDSIG":
            if len(parts) < 2:
                raise CoreReleaseSignatureError("CORE_RELEASE_SIGNATURE_DENIED")
            signer = parts[-1] if len(parts) > 11 else parts[1]
            valid.append(signer)
    if good != 1 or valid != [WAM_RELEASE_SIGNING_FINGERPRINT]:
        raise CoreReleaseSignatureError("CORE_RELEASE_SIGNATURE_DENIED")


def verify_wam_signed_distribution(
    *,
    signing_key: object,
    sha256sums: object,
    detached_signature: object,
    archive: object,
    archive_name: object,
    gpg_executable: object,
) -> SignedDistributionEvidence:
    """Detached-signature validation for an archive; **NEVER** a launch token.

    GnuPG binary must be independently trusted by the operator/OS, not fetched
    from an untrusted bundle. Windows x86 has no official v0.1.11 node archive.
    No WAM Core process runs; only GnuPG may execute for signature checking.
    """
    if type(archive_name) is not str or archive_name not in RELEASE_ASSETS:
        raise CoreReleaseSignatureError("CORE_RELEASE_ASSET_DENIED")
    if type(gpg_executable) not in (str, type(Path())):
        raise CoreReleaseSignatureError("CORE_RELEASE_GPG_UNAVAILABLE")
    gpg_path = Path(gpg_executable)
    if not gpg_path.is_absolute():
        raise CoreReleaseSignatureError("CORE_RELEASE_GPG_UNAVAILABLE")

    key_bytes = _read_bounded_regular(signing_key, 32768)
    sums_bytes = _read_bounded_regular(sha256sums, 131072)
    sig_bytes = _read_bounded_regular(detached_signature, 16384)
    with tempfile.TemporaryDirectory(prefix="wam-release-verify-") as temp:
        home = Path(temp)
        if os.name != "nt":
            home.chmod(0o700)
        key = home / "release-key.asc"
        sums = home / "SHA256SUMS"
        sig = home / "SHA256SUMS.asc"
        key.write_bytes(key_bytes)
        sums.write_bytes(sums_bytes)
        sig.write_bytes(sig_bytes)
        status, listing = _run_gpg(
            gpg_path, home, ("--with-colons", "--import-options",
                             "show-only", "--import", str(key)),
        )
        if status != 0:
            raise CoreReleaseSignatureError("CORE_RELEASE_SIGNER_DENIED")
        _gpg_primary_fingerprint(listing)
        # Public signature verification requires no secret-key agent. Importing
        # a key into a normal GPG home can nevertheless try to start gpg-agent.
        # Decode the already fingerprint-checked public key into one ephemeral
        # keyring instead. Never use user/default keyrings or autostart agents.
        keyring = home / "release-public.gpg"
        decoded, _ = _run_gpg(gpg_path, home, ("--dearmor", "--output",
                                            str(keyring), str(key)))
        if decoded != 0:
            raise CoreReleaseSignatureError("CORE_RELEASE_SIGNER_DENIED")
        checked, verdict = _run_gpg(
            gpg_path, home, ("--no-default-keyring", "--keyring", str(keyring),
                             "--status-fd", "1", "--verify",
                             str(sig), str(sums)),
        )
        if checked != 0:
            raise CoreReleaseSignatureError("CORE_RELEASE_SIGNATURE_DENIED")
        _validate_gpg_status(verdict)
        digest = _signed_digest(sums_bytes, archive_name)
        try:
            with stage_untrusted_core_artifact(archive, digest) as staged:
                if staged.core_execution_allowed is not False:
                    raise CoreReleaseSignatureError("CORE_RELEASE_AUTHORITY_DENIED")
                if staged.publisher_verified is not False:
                    raise CoreReleaseSignatureError("CORE_RELEASE_AUTHORITY_DENIED")
        except CoreArtifactStagingError:
            raise CoreReleaseSignatureError("CORE_RELEASE_ARCHIVE_DENIED") from None

    return SignedDistributionEvidence(archive_name, digest)
