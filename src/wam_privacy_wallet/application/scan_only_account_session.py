"""Disposable, scan-only encrypted-account intake into the REAL WSP scanner.

EXPERIMENTAL TEST/REGTEST QUALIFICATION ONLY. The caller must separately
authenticate the whole WSP source/dependency environment before supplying its
import_scan and Scanner factories. No implicit imports, wallet seed/Keyring,
spend secret, persistent scan account, default operational GUI or WAM Core launch.

The WSP import_scan decrypts the existing upstream AES-GCM scan envelope; the
application deliberately does not implement or substitute cryptography. Scan
secrets live transiently in upstream objects: Python does NOT promise reliable
memory zeroization. Only non-authorizing scalar metrics leave this boundary.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from typing import Callable

from wam_privacy_wallet.application.wsp_scan_coordinator import (
    ApplicationScanError, WspScanSessionSummary, run_consented_wsp_scan,
)
from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import Wsp1ScannerOnlyRpc

_MAX_ENVELOPE = 1_048_576
_MAX_BLOCKS = 16


class ScanOnlySessionError(ValueError):
    """Fixed refusal code; no path, account, password or upstream error text."""


def run_disposable_scan_only_backup(
    encrypted_scan: bytes,
    password: bytes,
    *,
    import_scan: Callable[[bytes, bytes], tuple[object, ...]],
    scanner_factory: Callable[[Path, tuple[object, ...]], object],
    rpc: Wsp1ScannerOnlyRpc,
    user_consented: bool,
    max_blocks: int = 1,
    cancelled: Callable[[], bool] | None = None,
) -> WspScanSessionSummary:
    """Run one disposable scanner session using a source-qualified WSP import.

    The encrypted scan-only envelope must be prepared upstream; NEVER pass a
    seed or spend-key backup. All SQLite state is intentionally ephemeral.
    This is NOT a user wallet, long-term encrypted account vault or production
    source loader. Its only permitted use is isolated synthetic/regtest review.
    """
    if (
        user_consented is not True
        or type(encrypted_scan) is not bytes
        or not 52 <= len(encrypted_scan) <= _MAX_ENVELOPE
        or type(password) is not bytes or not 12 <= len(password) <= 1024
        or type(rpc) is not Wsp1ScannerOnlyRpc
        or type(max_blocks) is not int or not 1 <= max_blocks <= _MAX_BLOCKS
        or not callable(import_scan) or not callable(scanner_factory)
        or (cancelled is not None and not callable(cancelled))
    ):
        raise ScanOnlySessionError("APP_SCAN_ONLY_INPUT_DENIED")

    if cancelled is not None:
        try:
            if cancelled() is not False:
                raise ScanOnlySessionError("APP_SCAN_ONLY_CANCELLED")
        except ScanOnlySessionError:
            raise
        except Exception:
            raise ScanOnlySessionError("APP_SCAN_ONLY_CANCELLED") from None

    try:
        with TemporaryDirectory(prefix="wsp1-disposable-scan-") as name:
            root = Path(name)
            if os.name == "posix" and stat.S_IMODE(root.stat().st_mode) != 0o700:
                raise ScanOnlySessionError("APP_SCAN_ONLY_TEMP_DIR_DENIED")

            # Actual WSP-1 import_scan authenticates and decrypts a scan-only
            # envelope. Neither wallet seeds nor spend keys enter this API.
            accounts = import_scan(encrypted_scan, password)
            if type(accounts) is not tuple or not 1 <= len(accounts) <= 16:
                raise ScanOnlySessionError("APP_SCAN_ONLY_ACCOUNT_DENIED")

            scanner = scanner_factory(root / "scan-only.sqlite", accounts)
            if not callable(getattr(scanner, "sync", None)) or not callable(
                getattr(scanner, "close", None)
            ):
                raise ScanOnlySessionError("APP_SCAN_ONLY_ENGINE_DENIED")
            try:
                result = run_consented_wsp_scan(
                    scanner, rpc, user_consented=True, max_blocks=max_blocks,
                    cancelled=cancelled,
                )
            finally:
                # Upstream scanner owns its native lease, SQLite and handles.
                # Close failure must invalidate success; temp dir is still
                # cleaned up by the outer context.
                scanner.close()
            return result
    except ScanOnlySessionError:
        raise
    except ApplicationScanError:
        raise ScanOnlySessionError("APP_SCAN_ONLY_SCAN_DENIED") from None
    except Exception:
        raise ScanOnlySessionError("APP_SCAN_ONLY_RUNTIME_DENIED") from None
