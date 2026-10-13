"""Offline WSP signer handoff: verify immutable file identity, never execute signer.

A separate upstream `wam_sp.offline_signer` command is the only signing role.
This coordinator cannot import a Keyring, decrypt, sign, broadcast or open RPC.
Before upstream signer review the application stops at a verified handoff.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import re
import stat
import sys

_PIN = "ac55f13423620252bdbf848c7e8a280c3b84721e"
_GUARD = re.compile(r"[0-9a-f]{40}\Z")

class SignerHandoffError(ValueError):
    """Only stable refusal codes leave the local offline authority boundary."""


@dataclass(frozen=True, slots=True, repr=False)
class SignerHandoff:
    """Non-authorizing local evidence: no secrets, no invocation side effects."""
    source_commit: str
    keyring_digest: str
    request_digest: str
    signer_entrypoint: str = "wam_sp.offline_signer"
    status: str = "SOURCE_PINNED_EXTERNAL_CLI_HANDOFF_ONLY"
    signer_executed: bool = False
    signing_allowed: bool = False
    broadcast_allowed: bool = False
    mainnet_allowed: bool = False


def _digest_private_regular(path: Path) -> str:
    if type(path) is not type(Path()) or not path.is_absolute():
        raise SignerHandoffError("SIGNER_INPUT_PATH_DENIED")
    try:
        parent = path.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or path.parent.is_symlink()
                or (os.name == "posix" and stat.S_IMODE(parent.st_mode) != 0o700)):
            raise ValueError
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size < 24 or before.st_size > 32 * 1024 * 1024
                or (os.name == "posix" and (stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_uid != os.geteuid()))):
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as source:
            opened = os.fstat(source.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size) != (
                    before.st_dev, before.st_ino, before.st_size):
                raise ValueError
            digest = sha256()
            remaining = before.st_size
            while remaining:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError
                digest.update(chunk)
                remaining -= len(chunk)
            after = os.fstat(source.fileno())
            last = path.lstat()
            attrs = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
            if any(getattr(opened, key) != getattr(after, key) or
                   getattr(after, key) != getattr(last, key) for key in attrs):
                raise ValueError
        return digest.hexdigest()
    except (OSError, ValueError):
        raise SignerHandoffError("SIGNER_PRIVATE_FILE_DENIED") from None


def inspect_external_signer_request(
    keyring: Path, request: Path, output: Path, *, upstream_commit: str,
    user_consented: bool,
) -> SignerHandoff:
    """Qualify already encrypted artifacts for a *manual* offline process.

    The caller never obtains a signer token or any private key. Output must
    not exist (upstream CLI writes create-once 0600) and must be distinct.
    """
    if (user_consented is not True or type(upstream_commit) is not str
            or _GUARD.fullmatch(upstream_commit) is None
            or upstream_commit != _PIN):
        raise SignerHandoffError("SIGNER_SOURCE_OR_CONSENT_DENIED")
    if (type(keyring) is not type(Path()) or type(request) is not type(Path())
            or type(output) is not type(Path())
            or not all(path.is_absolute() for path in (keyring, request, output))
            or len({str(keyring), str(request), str(output)}) != 3):
        raise SignerHandoffError("SIGNER_INPUT_PATH_DENIED")
    if sys.platform != "linux" or os.name != "posix":
        raise SignerHandoffError("SIGNER_PLATFORM_REVIEW_REQUIRED")
    if output.exists() or output.is_symlink():
        raise SignerHandoffError("SIGNER_OUTPUT_EXISTS_DENIED")
    # Upstream signer is an independent TTY-only CLI. Do not spawn it here.
    first = _digest_private_regular(keyring)
    second = _digest_private_regular(request)
    if output.parent != keyring.parent or output.parent != request.parent:
        raise SignerHandoffError("SIGNER_OUTPUT_PARENT_DENIED")
    return SignerHandoff(upstream_commit, first, second)
