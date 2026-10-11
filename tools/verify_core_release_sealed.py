"""Verify genuine signed WAM Linux distribution into NOEXEC sealed memfd.

Only the signed archive is operator-supplied; HTTPS metadata/GPG is verified
again for this invocation. This intentionally NEVER calls Core/exec/spawn.
"""
from __future__ import annotations

import argparse
import json
import sys

from wam_privacy_wallet.node.core_official_metadata import (
    OfficialMetadataError, official_release_metadata,
)
from wam_privacy_wallet.node.core_signed_linux_memfd import (
    SignedNodeSealError, sealed_signed_linux_wamd,
)
from wam_privacy_wallet.node.core_signed_release import CoreReleaseSignatureError
from tools.verify_core_release_offline import _absolute_path


def verify_signed_linux_memfd(*, archive: str, gpg: str) -> dict[str, object]:
    archive_path, gpg_path = _absolute_path(archive), _absolute_path(gpg)
    with official_release_metadata() as meta:
        with sealed_signed_linux_wamd(
            archive=archive_path, gpg=gpg_path,
            key=meta["key"], checksums=meta["checksums"],
            signature=meta["signature"],
        ) as sealed:
            sealed.audit()
            p = sealed.evidence
            if (p.execution_identity_bound is not False
                    or p.core_execution_allowed is not False
                    or p.mainnet_allowed is not False):
                raise SignedNodeSealError("CORE_SIGNED_SEAL_AUTHORITY_DENIED")
            return {
                "status": "OFFICIAL_SIGNED_WAMD_LINUX_NOEXEC_MEMFD_REVIEW",
                "node_sha256": p.sha256,
                "node_byte_count": p.byte_count,
                "kernel_seals_verified": p.seal_flags_verified,
                "kernel_noexec_enforced": True,
                "executed_core": False,
                "real_regtest_qualified": False,
                "execution_identity_bound": False,
                "core_execution_allowed": False,
                "real_wallet_allowed": False,
                "mainnet_allowed": False,
            }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify genuine signed Linux node bytes into NOEXEC memfd, never run Core",
    )
    parser.add_argument("--archive", required=True)
    parser.add_argument("--gpg", required=True)
    options = parser.parse_args(argv)
    try:
        receipt = verify_signed_linux_memfd(
            archive=options.archive, gpg=options.gpg,
        )
    except (OfficialMetadataError, SignedNodeSealError,
            CoreReleaseSignatureError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
