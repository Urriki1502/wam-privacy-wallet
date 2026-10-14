"""Read signed WAM Core v0.1.11 ARM64 Mach-O member, never execute it.

The pinned official GPG signature + archive hash are authenticated by the
existing release verifier. Re-read and rehash the exact Mach-O member through
a bounded tar stream and require the signed receipt's node SHA-256.

This is an artifact intake, NOT OS process/loader authenticity or real E2E.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
import struct
import sys
import tarfile

from tools.verify_core_release_official import verify_official_release

_ASSET = "wam-coin-v0.1.11-arm64-apple-darwin.tar.gz"
_MEMBER = "wam-coin-v0.1.11/bin/wamd"
_FINGERPRINT = "4BD4A8D3AFD43F5CBCB500E23798462FE00ADBA4"
_CHUNK = 1024 * 1024
_LIMIT = 128 * 1024 * 1024


class MacCoreIntakeError(ValueError):
    """Fixed redacted errors; no untrusted archive paths or binary bytes."""


def classify_arm64_macho(header: bytes) -> str:
    """Require thin little-endian MH_EXECUTE CPU_TYPE_ARM64 (not a fat or x86 binary)."""
    if type(header) is not bytes or len(header) < 32:
        raise MacCoreIntakeError("CORE_MAC_MACHO_HEADER_DENIED")
    magic, cpu, subtype, filetype, cmds, cmdsize, flags, reserved = struct.unpack(
        "<IiiIIIII", header[:32],
    )
    if (magic != 0xFEEDFACF or cpu != 0x0100000C or filetype != 2
            or cmds > 65536 or cmdsize > _LIMIT or reserved != 0):
        raise MacCoreIntakeError("CORE_MAC_MACHO_ARM64_EXECUTABLE_DENIED")
    return "THIN_MACHO64_ARM64_EXECUTE"


def _hash_exact_member(archive: Path) -> tuple[str, str]:
    try:
        with tarfile.open(archive, mode="r:gz", errorlevel=2) as stream:
            hits = [m for m in stream if m.name == _MEMBER]
            if len(hits) != 1 or not hits[0].isfile() or not 32 <= hits[0].size <= _LIMIT:
                raise MacCoreIntakeError("CORE_MAC_ARCHIVE_MEMBER_DENIED")
            handle = stream.extractfile(hits[0])
            if handle is None:
                raise MacCoreIntakeError("CORE_MAC_ARCHIVE_MEMBER_DENIED")
            with handle:
                hasher = hashlib.sha256()
                prefix = b""
                remaining = hits[0].size
                while remaining:
                    data = handle.read(min(_CHUNK, remaining))
                    if not data:
                        raise MacCoreIntakeError("CORE_MAC_ARCHIVE_STREAM_DENIED")
                    if len(prefix) < 32:
                        prefix += data[:32 - len(prefix)]
                    hasher.update(data)
                    remaining -= len(data)
                if handle.read(1):
                    raise MacCoreIntakeError("CORE_MAC_ARCHIVE_STREAM_DENIED")
            return hasher.hexdigest(), classify_arm64_macho(prefix)
    except MacCoreIntakeError:
        raise
    except (OSError, tarfile.TarError, EOFError, ValueError, MemoryError):
        raise MacCoreIntakeError("CORE_MAC_ARCHIVE_STREAM_DENIED") from None


def review_macos_core_arm64(archive: Path, gpg: Path) -> dict[str, object]:
    if (type(archive) is not type(Path()) or type(gpg) is not type(Path())
            or not archive.is_absolute() or archive.name != _ASSET
            or not gpg.is_absolute() or archive.is_symlink()):
        raise MacCoreIntakeError("CORE_MAC_INPUT_DENIED")
    # Full signed archive and node member are independently checked by the
    # existing verified-release flow; its receipt is never launch authority.
    receipt = verify_official_release(archive=str(archive), gpg=str(gpg))
    if (receipt.get("status") != "SIGNED_ARCHIVE_REVIEW_ONLY"
            or receipt.get("archive_name") != _ASSET
            or receipt.get("node_entry") != _MEMBER
            or receipt.get("signer_fingerprint") != _FINGERPRINT
            or receipt.get("metadata_origin") != "PINNED_WAM_HTTPS_V0_1_11"
            or any(receipt.get(flag) is not False for flag in (
                "core_execution_allowed", "execution_identity_bound",
                "mainnet_allowed", "real_wallet_allowed", "real_regtest_qualified"
            ))):
        raise MacCoreIntakeError("CORE_MAC_SIGNED_RECEIPT_DENIED")
    try:
        before = archive.stat()
        actual_hash, shape = _hash_exact_member(archive)
        after = archive.stat()
        if (not stat.S_ISREG(after.st_mode)
                or before.st_dev != after.st_dev or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or actual_hash != receipt["node_sha256"]):
            raise MacCoreIntakeError("CORE_MAC_MEMBER_SHA_DENIED")
    except (OSError, KeyError, TypeError):
        raise MacCoreIntakeError("CORE_MAC_MEMBER_SHA_DENIED") from None
    return {
        "status": "SIGNED_WAM_V0_1_11_ARM64_MACHO_REVIEW_ONLY",
        "signer_fingerprint": _FINGERPRINT,
        "archive_sha256": receipt["archive_sha256"],
        "node_sha256": actual_hash,
        "macho_shape": shape,
        "core_executed": False,
        "core_execution_allowed": False,
        "real_regtest_qualified": False,
        "process_loader_authenticated": False,
        "wallet_operational": False,
        "signing_allowed": False,
        "broadcast_allowed": False,
        "mainnet_allowed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Signed macOS WAM Core ARM64 intake (NO EXEC)")
    parser.add_argument("--archive", required=True)
    parser.add_argument("--gpg", required=True)
    args = parser.parse_args()
    try:
        result = review_macos_core_arm64(Path(args.archive), Path(args.gpg))
    except Exception:
        # Redacted by design: do not print GPG output, temporary paths or bytes.
        print("CORE_MAC_SIGNED_INTAKE_DENIED", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
