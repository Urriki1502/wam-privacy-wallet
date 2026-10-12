"""Regtest-only real WSP scanner -> sanitized GUI preview lifecycle.

The native CI passes source-verified WSP import_scan/Scanner factories to the
merged disposable account intake (#137). Only scalar results reach the GUI
receipt presenter (#138); Qt never owns scan passwords or account objects.
Synchronous/offscreen test bridge; not an enabled wallet feature or Core E2E.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from wam_privacy_wallet.application.scan_only_account_session import (
    run_disposable_scan_only_backup,
)
from wam_privacy_wallet.application.wsp_scan_coordinator import WspScanSessionSummary
from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import Wsp1ScannerOnlyRpc


class ScanPreviewError(ValueError):
    """Stable error code only; no secret-bearing upstream exceptions."""


def run_disposable_scan_preview(
    encrypted_scan: bytes,
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
    """Clear old UI state, scan disposable WSP account, render no-authority DTO.

    A source-qualified caller is required; never autoload WSP or use fixture
    fallback. Rendering/scan failure clears the old receipt; a broken clear
    prevents any success claim. No signing, broadcast, balances or real funds.
    """
    if not callable(clear_preview):
        raise ScanPreviewError("APP_SCAN_PREVIEW_CLEAR_REQUIRED")
    try:
        clear_preview()
    except Exception:
        raise ScanPreviewError("APP_SCAN_PREVIEW_CLEAR_DENIED") from None
    if user_consented is not True or not callable(present_preview):
        raise ScanPreviewError("APP_SCAN_PREVIEW_INPUT_DENIED")
    try:
        result = run_disposable_scan_only_backup(
            encrypted_scan, password,
            import_scan=import_scan,
            scanner_factory=scanner_factory,
            rpc=rpc,
            user_consented=True,
            max_blocks=max_blocks,
            cancelled=cancelled,
        )
        if (type(result) is not WspScanSessionSummary
                or result.core_authenticated is not False
                or result.wallet_operational is not False
                or result.balance_qualified is not False
                or result.signer_enabled is not False
                or result.broadcast_allowed is not False
                or result.mainnet_allowed is not False):
            raise ScanPreviewError("APP_SCAN_PREVIEW_RESULT_DENIED")
    except Exception:
        try:
            clear_preview()
        except Exception:
            raise ScanPreviewError("APP_SCAN_PREVIEW_CLEAR_DENIED") from None
        raise ScanPreviewError("APP_SCAN_PREVIEW_SCAN_DENIED") from None
    try:
        present_preview(result)
    except Exception:
        try:
            clear_preview()
        except Exception:
            raise ScanPreviewError("APP_SCAN_PREVIEW_CLEAR_DENIED") from None
        raise ScanPreviewError("APP_SCAN_PREVIEW_RENDER_DENIED") from None
    return result
