"""Verify genuine signed WAM Linux distribution into NOEXEC sealed memfd.

Only the signed archive is operator-supplied; HTTPS metadata/GPG is verified
again for this invocation. This intentionally NEVER calls Core/exec/spawn.
"""
from __future__ import annotations

import argparse
import json
import sys

from wam_privacy_wallet.node.core_elf_preflight import SealedElfError, inspect_sealed_linux_elf
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
    elf_failure: str | None = None
    result: dict[str, object] | None = None
    with official_release_metadata() as meta:
        with sealed_signed_linux_wamd(
            archive=archive_path, gpg=gpg_path,
            key=meta["key"], checksums=meta["checksums"],
            signature=meta["signature"],
        ) as sealed:
            sealed.audit()
            # Do not throw a ValueError through the signed snapshot's yield:
            # its cleanup wrapper deliberately redacts it as a staging error.
            # Record only a fixed ELF denial code, close/audit the fd normally,
            # then raise the code after the sealed review context has exited.
            try:
                layout = inspect_sealed_linux_elf(sealed._descriptor)
            except SealedElfError as exc:
                elf_failure = str(exc)
            else:
                p = sealed.evidence
                if (p.execution_identity_bound is not False
                        or p.core_execution_allowed is not False
                        or p.mainnet_allowed is not False):
                    raise SignedNodeSealError("CORE_SIGNED_SEAL_AUTHORITY_DENIED")
                result = {
                    "status": "OFFICIAL_SIGNED_WAMD_LINUX_NOEXEC_MEMFD_REVIEW",
                    "node_sha256": p.sha256,
                    "node_byte_count": p.byte_count,
                    "elf_class": layout.binary_class,
                    "elf_architecture": layout.architecture,
                    "elf_type": layout.elf_type,
                    "elf_load_segment_count": layout.load_segment_count,
                    "elf_has_interpreter": layout.has_interpreter,
                    "elf_has_dynamic_segment": layout.has_dynamic_segment,
                    "runtime_loader_authenticated": False,
                    "kernel_seals_verified": p.seal_flags_verified,
                    "kernel_noexec_enforced": True,
                    "executed_core": False,
                    "real_regtest_qualified": False,
                    "execution_identity_bound": False,
                    "core_execution_allowed": False,
                    "real_wallet_allowed": False,
                    "mainnet_allowed": False,
                }
    if elf_failure is not None:
        raise SealedElfError(elf_failure)
    if result is None:
        raise SealedElfError("CORE_ELF_READ_DENIED")
    return result

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
            CoreReleaseSignatureError, SealedElfError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
