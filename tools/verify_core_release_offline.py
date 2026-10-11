"""Offline entrypoint for authentic WAM v0.1.11 signed Core archive REVIEW.

Takes operator-provided local files; performs real detached GnuPG verification,
full archive SHA-256 staging and non-extracting node-member inspection.
Never downloads, launches or extracts WAM Core and never loads wallet files.

Even a real signed archive does NOT prove which bytes the OS later executes.
CORE_EXECUTION_REVIEW_REQUIRED (#36) remains unconditional.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from wam_privacy_wallet.node.core_archive_inventory import (
    CoreArchiveInventory, CoreArchiveInventoryError, inspect_wam_core_archive,
)
from wam_privacy_wallet.node.core_signed_release import (
    RELEASE_ASSETS, WAM_RELEASE_SIGNING_FINGERPRINT,
    CoreReleaseSignatureError, SignedDistributionEvidence,
    verify_wam_signed_distribution,
)

_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


def _absolute_path(value: str) -> Path:
    if type(value) is not str or not value or "\x00" in value:
        raise CoreReleaseSignatureError("CORE_RECEIPT_PATH_DENIED")
    path = Path(value)
    if not path.is_absolute():
        raise CoreReleaseSignatureError("CORE_RECEIPT_PATH_DENIED")
    return path


def _review_only_receipt(
    signed: SignedDistributionEvidence, inventory: CoreArchiveInventory,
) -> dict[str, object]:
    """Select only bounded public scalar evidence; never issue launch permit."""
    if (type(signed) is not SignedDistributionEvidence
            or type(inventory) is not CoreArchiveInventory
            or signed.archive_name not in RELEASE_ASSETS
            or signed.archive_name != inventory.archive_name
            or signed.signing_fingerprint != WAM_RELEASE_SIGNING_FINGERPRINT
            or signed.status != "SIGNED_DISTRIBUTION_ONLY"
            or type(signed.distribution_sha256) is not str
            or _HEX.fullmatch(signed.distribution_sha256) is None
            or type(inventory.node_sha256) is not str
            or _HEX.fullmatch(inventory.node_sha256) is None
            or type(inventory.node_byte_count) is not int
            or inventory.node_byte_count <= 0
            or inventory.status != "UNTRUSTED_ARCHIVE_INVENTORY"
            or any(getattr(item, flag) is not False
                   for item in (signed, inventory)
                   for flag in ("core_execution_allowed", "mainnet_allowed",
                                "real_wallet_allowed", "execution_identity_bound",
                                "extracted_binary_verified"))):
        raise CoreReleaseSignatureError("CORE_RECEIPT_AUTHORITY_DENIED")
    return {
        "status": "SIGNED_ARCHIVE_REVIEW_ONLY",
        "archive_name": signed.archive_name,
        "signer_fingerprint": WAM_RELEASE_SIGNING_FINGERPRINT,
        "archive_sha256": signed.distribution_sha256,
        "node_entry": inventory.node_entry,
        "node_byte_count": inventory.node_byte_count,
        "node_sha256": inventory.node_sha256,
        "execution_identity_bound": False,
        "core_execution_allowed": False,
        "real_wallet_allowed": False,
        "mainnet_allowed": False,
        "real_regtest_qualified": False,
    }


def qualify_release(
    *,
    archive: str, key: str, checksums: str, signature: str, gpg: str,
) -> dict[str, object]:
    """Verify actual files with pinned GnuPG signature; no synthetic fallback."""
    paths = [_absolute_path(part) for part in
             (archive, key, checksums, signature, gpg)]
    archive_path, key_path, sums_path, sig_path, gpg_path = paths
    if archive_path.name not in RELEASE_ASSETS:
        raise CoreReleaseSignatureError("CORE_RELEASE_ASSET_DENIED")
    signed = verify_wam_signed_distribution(
        signing_key=key_path, sha256sums=sums_path,
        detached_signature=sig_path, archive=archive_path,
        archive_name=archive_path.name, gpg_executable=gpg_path,
    )
    inspection = inspect_wam_core_archive(
        archive=archive_path, signed_receipt=signed,
    )
    return _review_only_receipt(signed, inspection)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only signed WAM Core release review (NO Core execution)",
    )
    for flag in ("archive", "key", "checksums", "signature", "gpg"):
        parser.add_argument("--" + flag, required=True)
    args = parser.parse_args(argv)
    try:
        outcome = qualify_release(
            archive=args.archive, key=args.key, checksums=args.checksums,
            signature=args.signature, gpg=args.gpg,
        )
    except (CoreReleaseSignatureError, CoreArchiveInventoryError) as err:
        # Only stable hardcoded denial code, never print paths or GPG output.
        print(str(err), file=sys.stderr)
        return 2
    print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
