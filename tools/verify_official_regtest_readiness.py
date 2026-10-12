"""Authenticated official WAM Core regtest-readiness BLOCKED receipt (NO EXEC).

This is a fresh HTTPS+GnuPG+signed-archive+SHA+real Linux NOEXEC memfd
inspection of official WAM bytes. It never starts a node, exports an exec fd,
claims a process-image binding, or authorizes real funds.
"""
from __future__ import annotations

import argparse
import json
import sys

from wam_privacy_wallet.node.core_elf_preflight import (
    SealedElfError, inspect_sealed_linux_elf,
)
from wam_privacy_wallet.node.core_official_metadata import (
    OfficialMetadataError, official_release_metadata,
)
from wam_privacy_wallet.node.core_signed_linux_memfd import (
    SignedNodeSealError, sealed_signed_linux_wamd,
)
from wam_privacy_wallet.node.core_signed_release import CoreReleaseSignatureError
from tools.verify_core_release_offline import _absolute_path

# Only this independently observed policy denial is a known, documented
# official WAM v0.1.11 hardening HOLD; never mask other ELF parser failures.
_KNOWN_EXEC_STACK_DENIAL = "CORE_ELF_EXECUTABLE_STACK_DENIED"


def inspect_official_regtest_readiness(*, archive: str, gpg: str) -> dict[str, object]:
    archive_path = _absolute_path(archive)
    gpg_path = _absolute_path(gpg)
    reason: str | None = None
    verified_hash = ""
    size = 0
    with official_release_metadata() as meta:
        with sealed_signed_linux_wamd(
            archive=archive_path, gpg=gpg_path,
            key=meta["key"], checksums=meta["checksums"],
            signature=meta["signature"],
        ) as review:
            # The bridge has independently authenticated official SHA256SUMS
            # with pinned publisher fingerprint and rehashed archive/member.
            if (review.audit() is not True
                    or review.evidence.core_execution_allowed is not False
                    or review.evidence.execution_identity_bound is not False
                    or review.evidence.mainnet_allowed is not False):
                raise SignedNodeSealError("CORE_REGTEST_READINESS_AUTHORITY_DENIED")
            verified_hash = review.evidence.sha256
            size = review.evidence.byte_count
            try:
                inspect_sealed_linux_elf(review._descriptor)
            except SealedElfError as exc:
                if str(exc) != _KNOWN_EXEC_STACK_DENIAL:
                    # Unexpected malformed/header/loader policy failure is an
                    # ERROR, not successful qualification or a known HOLD.
                    raise
                reason = _KNOWN_EXEC_STACK_DENIAL
            if review.audit() is not True:
                raise SignedNodeSealError("CORE_REGTEST_READINESS_REAUDIT_DENIED")

    # Even a future ELF clean pass cannot authorize launch without signed
    # DEV approval, proven fd->exec binding, loader/DSO trust and isolated E2E.
    return {
        "status": "OFFICIAL_WAM_CORE_REGTEST_BLOCKED_NO_EXEC",
        "signed_official_member_sha256": verified_hash,
        "signed_official_member_byte_count": size,
        "known_elf_exec_stack_denial": reason is not None,
        "elf_policy_denial": reason or "",
        "official_archive_verified_for_review": True,
        "publisher_build_mapping_approved": False,
        "dynamic_loader_and_dso_authenticated": False,
        "kernel_executed_image_bound": False,
        "dev_wam_binary_approved": False,
        "genuine_two_node_regtest_qualified": False,
        "wam_core_executed": False,
        "wallet_enabled": False,
        "signing_allowed": False,
        "broadcast_allowed": False,
        "mainnet_allowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Authentic WAM v0.1.11 signed Core regtest BLOCKED receipt, NO EXEC"
    )
    parser.add_argument("--archive", required=True)
    parser.add_argument("--gpg", required=True)
    args = parser.parse_args(argv)
    try:
        report = inspect_official_regtest_readiness(
            archive=args.archive, gpg=args.gpg,
        )
    except (OfficialMetadataError, SignedNodeSealError,
            CoreReleaseSignatureError, SealedElfError, ValueError):
        # Never print raw file paths, online metadata or GnuPG messages.
        print("CORE_REGTEST_READINESS_DENIED", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
