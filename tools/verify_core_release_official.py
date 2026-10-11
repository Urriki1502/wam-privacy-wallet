"""Opt-in genuine HTTPS metadata + GnuPG signed WAM archive review.

Actual official signing metadata is fetched from fixed wamcoin.org HTTPS paths,
then the existing offline verifier authenticates the detached signature and
the operator-owned node archive's signed digest. Never downloads or launches
a Core executable; outputs no execution or wallet authority.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from wam_privacy_wallet.node.core_archive_inventory import CoreArchiveInventoryError
from wam_privacy_wallet.node.core_official_metadata import (
    OfficialMetadataError, official_release_metadata,
)
from wam_privacy_wallet.node.core_signed_release import (
    CoreReleaseSignatureError, RELEASE_ASSETS,
)
from tools.verify_core_release_offline import _absolute_path, qualify_release


def verify_official_release(*, archive: str, gpg: str) -> dict[str, object]:
    """Verify downloaded signed metadata and local release archive, no Core run."""
    archive_path = _absolute_path(archive)
    gpg_path = _absolute_path(gpg)
    if archive_path.name not in RELEASE_ASSETS:
        raise CoreReleaseSignatureError("CORE_RELEASE_ASSET_DENIED")
    # GPG path must be independently trusted by the operator. It is NOT
    # downloaded or discovered from PATH, to avoid accidentally running a
    # GPG lookalike. No action uses the archive as an executable.
    with official_release_metadata() as metadata:
        receipt = qualify_release(
            archive=str(archive_path),
            gpg=str(gpg_path),
            key=str(metadata["key"]),
            checksums=str(metadata["checksums"]),
            signature=str(metadata["signature"]),
        )
    if (receipt.get("core_execution_allowed") is not False
            or receipt.get("mainnet_allowed") is not False
            or receipt.get("real_wallet_allowed") is not False
            or receipt.get("real_regtest_qualified") is not False):
        raise CoreReleaseSignatureError("CORE_RECEIPT_AUTHORITY_DENIED")
    return {
        **receipt,
        "metadata_origin": "PINNED_WAM_HTTPS_V0_1_11",
        "core_execution_allowed": False,
        "real_regtest_qualified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Genuine official WAM signed-release review (NO WAM Core launch)",
    )
    parser.add_argument("--archive", required=True,
                        help="Absolute path to manually obtained official v0.1.11 node archive")
    parser.add_argument("--gpg", required=True,
                        help="Absolute path to independently trusted local GnuPG executable")
    opts = parser.parse_args(argv)
    try:
        result = verify_official_release(archive=opts.archive, gpg=opts.gpg)
    except (OfficialMetadataError, CoreReleaseSignatureError, CoreArchiveInventoryError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
