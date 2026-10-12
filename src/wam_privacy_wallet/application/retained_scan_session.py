"""Experimental Linux retained WSP-1 scanner state across process restarts.

An upstream source-qualified WSP-1 import_scan/Scanner must be injected. This
module NEVER builds a seed-bearing Keyring or supplies fake scanner fallback.
The encrypted scan-only backup is loaded from the create-once private store.
The real upstream SQLite store handles wallet identity, schema validation,
synchronous commits, exclusive nonblocking file lock and chain reorg.
No WAM Core execution or operating-wallet claim is granted.

WARNING: Upstream WSP SQLite is *not encrypted*. It may contain wallet
metadata and receive/spend graph. This is a review-gated synthetic/regtest
prototype ONLY. No GUI activation, mainnet or real account keys permitted.
Same-UID attackers and race-free pathname handoff to upstream SQLite are NOT
fully mitigated; a production qualified FD/identity path is still required.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Callable

from wam_privacy_wallet.application.encrypted_scan_backup import (
    EncryptedScanBackupError, load_encrypted_scan_backup,
)
from wam_privacy_wallet.application.wsp_scan_coordinator import (
    ApplicationScanError, WspScanSessionSummary, run_consented_wsp_scan,
)
from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import Wsp1ScannerOnlyRpc

_DB = "scan-only-state.sqlite"


class RetainedScanError(ValueError):
    """Redacted, fixed application failure code."""


def _check_existing_db(folder: Path) -> Path:
    target = folder / _DB
    try:
        # Upstream load has just validated the POSIX private directory.
        # Refuse preexisting links/foreign files before the WSP SQLite open.
        # A race-free FD handoff needs separate upstream integration review.
        if not target.exists() and not target.is_symlink():
            return target
        s = target.lstat()
        if (not stat.S_ISREG(s.st_mode)
                or stat.S_IMODE(s.st_mode) != 0o600
                or s.st_uid != os.geteuid()
                or s.st_nlink != 1
                or s.st_size > 1024**3):
            raise RetainedScanError("APP_RETAINED_DB_DENIED")
        return target
    except RetainedScanError:
        raise
    except Exception:
        raise RetainedScanError("APP_RETAINED_DB_DENIED") from None


def run_retained_scan_only(
    private_dir: Path,
    password: bytes,
    *,
    import_scan: Callable[[bytes, bytes], tuple[object, ...]],
    scanner_factory: Callable[[Path, tuple[object, ...]], object],
    rpc: Wsp1ScannerOnlyRpc,
    user_consented: bool,
    max_blocks: int = 1,
    cancelled: Callable[[], bool] | None = None,
) -> WspScanSessionSummary:
    """Re-import encrypted scan account, reopen source-pinned WSP SQLite.

    Each invocation reattests the scanner-only RPC before consuming blocks.
    No balances/coins, account objects, persisted scan secret or write RPC
    escape. This remains synchronous and CI/test-only.
    """
    if (user_consented is not True
            or type(private_dir) is not type(Path())
            or type(password) is not bytes or not 12 <= len(password) <= 1024
            or type(rpc) is not Wsp1ScannerOnlyRpc
            or type(max_blocks) is not int or not 1 <= max_blocks <= 16
            or not callable(import_scan) or not callable(scanner_factory)
            or (cancelled is not None and not callable(cancelled))):
        raise RetainedScanError("APP_RETAINED_INPUT_DENIED")
    if cancelled is not None:
        try:
            if cancelled() is not False:
                raise RetainedScanError("APP_RETAINED_CANCELLED")
        except RetainedScanError:
            raise
        except Exception:
            raise RetainedScanError("APP_RETAINED_CANCELLED") from None
    try:
        envelope = load_encrypted_scan_backup(private_dir)
        accounts = import_scan(envelope, password)
        if type(accounts) is not tuple or not 1 <= len(accounts) <= 16:
            raise RetainedScanError("APP_RETAINED_ACCOUNT_DENIED")
        db = _check_existing_db(private_dir)
        scanner = scanner_factory(db, accounts)
        if (not callable(getattr(scanner, "sync", None))
                or not callable(getattr(scanner, "close", None))):
            raise RetainedScanError("APP_RETAINED_ENGINE_DENIED")
        try:
            result = run_consented_wsp_scan(
                scanner, rpc, user_consented=True,
                max_blocks=max_blocks, cancelled=cancelled,
            )
        finally:
            scanner.close()
        return result
    except RetainedScanError:
        raise
    except (EncryptedScanBackupError, ApplicationScanError):
        raise RetainedScanError("APP_RETAINED_SCAN_DENIED") from None
    except Exception:
        raise RetainedScanError("APP_RETAINED_RUNTIME_DENIED") from None
