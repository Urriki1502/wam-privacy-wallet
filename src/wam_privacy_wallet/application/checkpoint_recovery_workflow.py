"""EXPERIMENTAL synthetic/regtest encrypted-checkpoint → WSP → Qt workflow.

Loads two already-encrypted blobs from immutable private Linux files:
upstream WSP-1 scan-only account backup and upstream WSP-1 SQLite checkpoint.
The *injected source-verified upstream library* authenticates/decrypts them.
A fresh temporary real Scanner/SQLite receives the checkpoint; scanner-only
read RPC reattests its synthetic chain; only scalar no-authority summary reaches
the GUI. This is synchronous CI qualification, NOT user-activated wallet code.

Never uses seed/Keyring, signing, mainnet, real keys/funds or WAM Core process.
Does not solve same-UID attackers, rollback of stored checkpoint, protected
long-term SQLite, Qt worker thread, or production source-loader provenance.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from typing import Callable

from wam_privacy_wallet.application.encrypted_scan_backup import (
    load_encrypted_scan_backup,
)
from wam_privacy_wallet.application.encrypted_checkpoint_archive import (
    load_encrypted_checkpoint,
)
from wam_privacy_wallet.application.wsp_scan_coordinator import (
    WspScanSessionSummary, run_consented_wsp_scan,
)
from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import Wsp1ScannerOnlyRpc


class CheckpointRecoveryError(ValueError):
    """Fixed denial code with no attached upstream error chain."""


def recover_checkpoint_scan_preview(
    private_dir: Path,
    password: bytes,
    *,
    import_scan: Callable[[bytes, bytes], tuple[object, ...]],
    scanner_factory: Callable[[Path, tuple[object, ...]], object],
    rpc: Wsp1ScannerOnlyRpc,
    user_consented: bool,
    clear_preview: Callable[[], None],
    present_preview: Callable[[WspScanSessionSummary], None],
    max_blocks: int = 1,
    cancelled: Callable[[], bool] | None = None,
) -> WspScanSessionSummary:
    """Restore and reattest genuine WSP state; only publish untrusted metrics.

    The previous GUI receipt is erased *before* any account decryption.
    Every scan/restore/render failure attempts another wipe. A failed GUI wipe
    itself always denies the operation, never falls back to a stale preview.
    """
    if not callable(clear_preview):
        raise CheckpointRecoveryError("APP_RECOVERY_CLEAR_REQUIRED")
    try:
        clear_preview()
    except Exception:
        raise CheckpointRecoveryError("APP_RECOVERY_CLEAR_DENIED") from None
    if (user_consented is not True
            or type(private_dir) is not type(Path())
            or type(password) is not bytes
            or not 12 <= len(password) <= 1024
            or type(rpc) is not Wsp1ScannerOnlyRpc
            or not callable(import_scan) or not callable(scanner_factory)
            or not callable(present_preview)
            or type(max_blocks) is not int or not 1 <= max_blocks <= 16
            or (cancelled is not None and not callable(cancelled))):
        raise CheckpointRecoveryError("APP_RECOVERY_INPUT_DENIED")
    if cancelled is not None:
        try:
            if cancelled() is not False:
                raise CheckpointRecoveryError("APP_RECOVERY_CANCELLED")
        except CheckpointRecoveryError:
            raise
        except Exception:
            raise CheckpointRecoveryError("APP_RECOVERY_CANCELLED") from None

    try:
        ciphertext = load_encrypted_scan_backup(private_dir)
        checkpoint = load_encrypted_checkpoint(private_dir)
        accounts = import_scan(ciphertext, password)
        if type(accounts) is not tuple or not 1 <= len(accounts) <= 16:
            raise CheckpointRecoveryError("APP_RECOVERY_ACCOUNT_DENIED")
        with TemporaryDirectory(prefix="wsp1-restore-regtest-") as root:
            dirname = Path(root)
            if (os.name == "posix"
                    and stat.S_IMODE(dirname.stat().st_mode) != 0o700):
                raise CheckpointRecoveryError("APP_RECOVERY_PRIVATE_DIR_DENIED")
            scanner = scanner_factory(dirname / "recovered.sqlite", accounts)
            if (not callable(getattr(scanner, "close", None))
                    or not callable(getattr(scanner, "sync", None))
                    or not callable(getattr(
                        getattr(scanner, "store", None),
                        "restore_checkpoint", None,
                    ))):
                raise CheckpointRecoveryError("APP_RECOVERY_SCANNER_DENIED")
            try:
                # Source-pinned Store performs the actual AES-GCM validation,
                # network/account identity check, schema + state validation.
                scanner.store.restore_checkpoint(checkpoint, password)
                summary = run_consented_wsp_scan(
                    scanner, rpc, user_consented=True,
                    max_blocks=max_blocks, cancelled=cancelled,
                )
            finally:
                scanner.close()
        if (type(summary) is not WspScanSessionSummary
                or summary.core_authenticated is not False
                or summary.wallet_operational is not False
                or summary.balance_qualified is not False
                or summary.signer_enabled is not False
                or summary.broadcast_allowed is not False
                or summary.mainnet_allowed is not False):
            raise CheckpointRecoveryError("APP_RECOVERY_AUTHORITY_DENIED")
    except Exception:
        try:
            clear_preview()
        except Exception:
            raise CheckpointRecoveryError("APP_RECOVERY_CLEAR_DENIED") from None
        raise CheckpointRecoveryError("APP_RECOVERY_RESTORE_DENIED") from None
    try:
        present_preview(summary)
    except Exception:
        try:
            clear_preview()
        except Exception:
            raise CheckpointRecoveryError("APP_RECOVERY_CLEAR_DENIED") from None
        raise CheckpointRecoveryError("APP_RECOVERY_RENDER_DENIED") from None
    return summary
