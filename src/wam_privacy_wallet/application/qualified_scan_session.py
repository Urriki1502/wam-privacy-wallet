"""Source-qualified, retained scan-only WSP application adapter.

Experimental disposable REGTEST review only. The operational GUI must keep its
Core/WSP approval gates closed; constructing this adapter does not approve them.
No account generation, seed-bearing Keyring, signer, broadcast or Core process.
The caller supplies an existing encrypted scan-only backup and a disposable
test password. Only scanner-owned scan roles persist in memory while open.

Raw source checks and pinned dependency versions are review evidence, not a
production import sandbox, publisher authentication or race-free runtime bind.
The existing private Linux storage boundary is retained without broadening it.
WSP SQLite is unencrypted; same-UID tampering and trusted anti-rollback remain
unqualified (#148/#151). No real user accounts, secrets or funds are permitted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import importlib.metadata
import importlib.util
from pathlib import Path
import re
import struct
import sys
import threading
from typing import Callable

from .encrypted_scan_backup import load_encrypted_scan_backup
from .encrypted_checkpoint_archive import load_encrypted_checkpoint, store_encrypted_checkpoint
from .retained_scan_session import _check_existing_db
from .wsp_scan_coordinator import WspScanSessionSummary, run_consented_wsp_scan
from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import Wsp1ScannerOnlyRpc
from wam_privacy_wallet.integrations.wsp1_source_closure import verify_wsp1_full_source_closure
from wam_privacy_wallet.integrations.wsp1_source_review import PINNED_COMMIT

_SCOPE = "disposable-regtest-review"
_DEPS = (("coincurve", "21.0.0"), ("cryptography", "50.0.0"),
         ("pycryptodome", "3.23.0"))
_CODE = re.compile(r"wamrtsp1[023456789acdefghjklmnpqrstuvwxyz]{100,130}\Z", re.ASCII)
_LIMIT = 1_000_000


class QualifiedScanError(ValueError):
    """Stable refusal codes; never expose secrets, paths or upstream messages."""


def _scope(user_consented: object, scope: object) -> None:
    if user_consented is not True or type(scope) is not str or scope != _SCOPE:
        raise QualifiedScanError("APP_QUALIFIED_SCAN_SCOPE_DENIED")


def _platform() -> None:
    if sys.platform != "linux" or struct.calcsize("P") != 8:
        raise QualifiedScanError("APP_QUALIFIED_SCAN_PLATFORM_UNQUALIFIED")


def _stop(cancelled: Callable[[], bool] | None) -> bool:
    if cancelled is None:
        return False
    try:
        value = cancelled()
        return type(value) is not bool or value
    except Exception:
        return True


@dataclass(frozen=True, slots=True)
class ScanSnapshot:
    """Actual Store scalar projection; amounts are unqualified local reports."""

    tip_height: int
    confirmed_utxo_count: int | None
    unqualified_confirmed_atoms: int | None
    history_count: int | None
    mempool_observed: bool
    mempool_utxo_count: int | None
    unqualified_mempool_atoms: int | None
    mempool_spend_count: int | None
    chain_current: bool = True
    blocks_processed: int = 0
    transactions_processed: int = 0
    rollback_blocks: int = 0
    mempool_transactions_processed: int = 0
    source_commit: str = field(default=PINNED_COMMIT, init=False)
    evidence: str = field(default="PINNED_SCAN_STORE_PROJECTED_UNTRUSTED", init=False)
    scope: str = field(default=_SCOPE, init=False)
    core_authenticated: bool = field(default=False, init=False)
    wallet_operational: bool = field(default=False, init=False)
    balance_qualified: bool = field(default=False, init=False)
    signer_enabled: bool = field(default=False, init=False)
    broadcast_allowed: bool = field(default=False, init=False)
    mainnet_allowed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        for name, maximum in (("tip_height", 100_000_000),
                              ("blocks_processed", 16),
                              ("transactions_processed", 160_000),
                              ("rollback_blocks", 100_000),
                              ("mempool_transactions_processed", 10_000)):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= maximum:
                raise QualifiedScanError("APP_QUALIFIED_SCAN_SNAPSHOT_DENIED")
        if (type(self.mempool_observed) is not bool or type(self.chain_current) is not bool
                or (self.mempool_observed and not self.chain_current)):
            raise QualifiedScanError("APP_QUALIFIED_SCAN_SNAPSHOT_DENIED")
        for name, maximum in (("confirmed_utxo_count", _LIMIT),
                              ("unqualified_confirmed_atoms", 2**63 - 1),
                              ("history_count", _LIMIT)):
            value = getattr(self, name)
            if ((not self.chain_current and value is not None)
                    or (self.chain_current
                        and (type(value) is not int or not 0 <= value <= maximum))):
                raise QualifiedScanError("APP_QUALIFIED_SCAN_SNAPSHOT_DENIED")
        for name, maximum in (("mempool_utxo_count", _LIMIT),
                              ("unqualified_mempool_atoms", 2**63 - 1),
                              ("mempool_spend_count", _LIMIT)):
            value = getattr(self, name)
            if ((not self.mempool_observed and value is not None)
                    or (self.mempool_observed
                        and (type(value) is not int or not 0 <= value <= maximum))):
                raise QualifiedScanError("APP_QUALIFIED_SCAN_SNAPSHOT_DENIED")
        if not self.mempool_observed and self.mempool_transactions_processed != 0:
            raise QualifiedScanError("APP_QUALIFIED_SCAN_SNAPSHOT_DENIED")


@dataclass(frozen=True, slots=True, repr=False)
class PrivateHistoryRow:
    """Actual WSP SQLite history; txid must remain local/private."""
    txid: str
    height: int
    confirmations: int
    credit_atoms: int
    debit_atoms: int

    def __post_init__(self) -> None:
        if (type(self.txid) is not str or re.fullmatch("[0-9a-f]{64}", self.txid) is None
                or any(type(v) is not int for v in (self.height, self.confirmations,
                       self.credit_atoms, self.debit_atoms))
                or not 1 <= self.height <= 100_000_000
                or not 1 <= self.confirmations <= 100_000_000
                or not 0 <= self.credit_atoms <= 22_000_000 * 100_000_000
                or not 0 <= self.debit_atoms <= 22_000_000 * 100_000_000
                or (self.credit_atoms == 0 and self.debit_atoms == 0)):
            raise QualifiedScanError("APP_QUALIFIED_SCAN_HISTORY_DENIED")


@dataclass(frozen=True, slots=True, repr=False)
class PrivateHistoryPage:
    """No Core attestation and no spend authority; NEVER a telemetry DTO."""
    records: tuple[PrivateHistoryRow, ...]
    tip_height: int
    offset: int
    source_commit: str = field(default=PINNED_COMMIT, init=False)
    wallet_operational: bool = field(default=False, init=False)
    signer_enabled: bool = field(default=False, init=False)
    broadcast_allowed: bool = field(default=False, init=False)
    mainnet_allowed: bool = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class ReceiveCode:
    """A public code derived by actual scan-only upstream API; review only."""

    code: str
    source_commit: str = field(default=PINNED_COMMIT, init=False)
    evidence: str = field(default="PINNED_SCAN_ONLY_RECEIVE_CODE_UNTRUSTED", init=False)
    namespace: str = field(default="wamrtsp-draft-regtest", init=False)
    scope: str = field(default=_SCOPE, init=False)
    wallet_operational: bool = field(default=False, init=False)
    signer_enabled: bool = field(default=False, init=False)
    broadcast_allowed: bool = field(default=False, init=False)
    mainnet_allowed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if type(self.code) is not str or _CODE.fullmatch(self.code) is None:
            raise QualifiedScanError("APP_QUALIFIED_SCAN_RECEIVE_DENIED")


class SourceQualifiedScanRuntime:
    """Explicit source/dependency initialization without injectable engines.

    Use a fresh worker process: preloaded WSP modules are rejected. Subsequent
    opens in this runtime recheck raw bytes/dependencies and bind the original
    imported API references. This is not a defense against hostile Python/OS.
    """

    __slots__ = ("_root", "_scanner_class", "_import_scan", "_account_class", "_decode")

    def __init__(self, source_root: Path, *, user_consented: bool,
                 scope: str = _SCOPE) -> None:
        _scope(user_consented, scope)
        _platform()
        if (type(source_root) is not type(Path()) or not source_root.is_absolute()
                or source_root.is_symlink()):
            raise QualifiedScanError("APP_QUALIFIED_SCAN_SOURCE_DENIED")
        self._root = source_root
        if any(name == "wam_sp" or name.startswith("wam_sp.") for name in sys.modules):
            raise QualifiedScanError("APP_QUALIFIED_SCAN_PRELOADED_SOURCE_DENIED")
        self._verify()
        try:
            # Imports occur only after the full exact Git closure, origin,
            # dependency and bytecode checks have succeeded.
            from wam_sp.scanner import Scanner
            from wam_sp.keystore import ScanAccount, import_scan
            from wam_sp.core import decode_address
            self._scanner_class = Scanner
            self._import_scan = import_scan
            self._account_class = ScanAccount
            self._decode = decode_address
        except Exception:
            raise QualifiedScanError("APP_QUALIFIED_SCAN_IMPORT_DENIED") from None

    def _verify(self) -> None:
        try:
            proof = verify_wsp1_full_source_closure(self._root)
            if proof["pinned_commit"] != PINNED_COMMIT:
                raise ValueError
            if any((self._root / "src").rglob("*.pyc")):
                raise ValueError
            for package, version in _DEPS:
                if importlib.metadata.version(package) != version:
                    raise ValueError
            spec = importlib.util.find_spec("wam_sp")
            if (spec is None or spec.origin is None
                    or Path(spec.origin).resolve() != self._root / "src/wam_sp/__init__.py"):
                raise ValueError
        except Exception:
            raise QualifiedScanError("APP_QUALIFIED_SCAN_SOURCE_DENIED") from None

    def open(self, private_dir: Path, password: bytes, *, user_consented: bool,
             scope: str = _SCOPE,
             cancelled: Callable[[], bool] | None = None) -> QualifiedScanSession:
        _scope(user_consented, scope)
        _platform()
        if (type(private_dir) is not type(Path()) or not private_dir.is_absolute()
                or type(password) is not bytes or not 12 <= len(password) <= 1024
                or (cancelled is not None and not callable(cancelled))):
            raise QualifiedScanError("APP_QUALIFIED_SCAN_INPUT_DENIED")
        if _stop(cancelled):
            raise QualifiedScanError("APP_QUALIFIED_SCAN_CANCELLED")
        self._verify()
        scanner = None
        try:
            envelope = load_encrypted_scan_backup(private_dir)
            accounts = self._import_scan(envelope, password)
            if (type(accounts) is not tuple or not 1 <= len(accounts) <= 16
                    or any(type(account) is not self._account_class for account in accounts)):
                raise ValueError
            if _stop(cancelled):
                raise QualifiedScanError("APP_QUALIFIED_SCAN_CANCELLED")
            scanner = self._scanner_class(_check_existing_db(private_dir), accounts)
            # Scanner owns scan-only roles. No duplicate decrypted tuple or
            # password is retained by the runtime or returned to a presenter.
            del accounts, envelope
            if _stop(cancelled):
                raise QualifiedScanError("APP_QUALIFIED_SCAN_CANCELLED")
            return QualifiedScanSession(scanner, self._decode, _token=_SESSION_TOKEN)
        except Exception as error:
            if scanner is not None:
                try:
                    scanner.close()
                except Exception:
                    pass
            if type(error) is QualifiedScanError:
                raise error from None
            raise QualifiedScanError("APP_QUALIFIED_SCAN_OPEN_DENIED") from None

    def restore(self, private_dir: Path, password: bytes, *,
                user_consented: bool, scope: str = _SCOPE) -> QualifiedScanSession:
        """Restore pinned AES-GCM checkpoint into a fresh empty WSP Store.

        Never marks restored chain data current; requires a NEW actual RPC sync.
        External trusted anti-rollback is NOT qualified (#148/#151).
        """
        _scope(user_consented, scope)
        session = self.open(private_dir, password, user_consented=True, scope=scope)
        try:
            ciphertext = load_encrypted_checkpoint(private_dir)
            with session._scanner._lease():
                session._scanner.store.restore_checkpoint(ciphertext, password)
            if session._scanner.ready or session._scanner.mempool_ready:
                raise ValueError("RESTORED_AUTHORITY")
            return session
        except Exception:
            try:
                session.close()
            except Exception:
                pass
            raise QualifiedScanError("APP_QUALIFIED_SCAN_RESTORE_DENIED") from None


_SESSION_TOKEN = object()


class QualifiedScanSession:
    """Single-operation session; failure/cancellation closes and poisons it."""

    __slots__ = ("_scanner", "_decode", "_lock", "_cancel", "_closed", "_scanned")

    def __init__(self, scanner: object, decoder: object, *, _token: object) -> None:
        if _token is not _SESSION_TOKEN:
            raise QualifiedScanError("APP_QUALIFIED_SCAN_ENGINE_DENIED")
        self._scanner = scanner
        self._decode = decoder
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._closed = False
        self._scanned = False

    @property
    def closed(self) -> bool:
        return self._closed

    def cancel(self) -> None:
        """Thread-safe stop request; do not close SQLite during native work."""
        self._cancel.set()

    def _enter(self) -> None:
        if not self._lock.acquire(blocking=False):
            self.cancel()
            raise QualifiedScanError("APP_QUALIFIED_SCAN_BUSY")
        if self._closed or self._cancel.is_set():
            self._lock.release()
            raise QualifiedScanError("APP_QUALIFIED_SCAN_CLOSED")

    def _close_owned(self) -> None:
        self._closed = True
        self._cancel.set()
        self._decode = None
        if self._scanner is not None:
            # Keep a poisoned private handle if close fails so explicit close
            # can retry cleanup; it can never be used for another operation.
            self._scanner.close()
            self._scanner = None

    def close(self) -> None:
        self.cancel()
        if not self._lock.acquire(blocking=False):
            raise QualifiedScanError("APP_QUALIFIED_SCAN_BUSY")
        try:
            self._close_owned()
        except Exception:
            raise QualifiedScanError("APP_QUALIFIED_SCAN_CLOSE_DENIED") from None
        finally:
            self._lock.release()

    def _failure(self, code: str) -> None:
        try:
            self._close_owned()
        except Exception:
            raise QualifiedScanError("APP_QUALIFIED_SCAN_CLOSE_DENIED") from None
        raise QualifiedScanError(code) from None

    def _project(self, summary: WspScanSessionSummary | None = None) -> ScanSnapshot:
        scanner = self._scanner
        # Reuse the real upstream lease and transaction. A cached mempool on
        # restart is never displayed before a new actual sync_mempool succeeds.
        with scanner._lease(), scanner.store.transaction():
            current = scanner.ready is True
            if current:
                scanner.assert_current()
            db = scanner.store.db
            height = scanner.store.tip()[0]
            count = amount = history = None
            if current:
                count, amount = db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(atoms),0) FROM coins WHERE spent IS NULL"
                ).fetchone()
                history = db.execute("SELECT COUNT(*) FROM history").fetchone()[0]
            observed = current and scanner.mempool_ready is True
            pending_count = pending_amount = pending_spends = None
            if observed:
                pending_count, pending_amount = db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(atoms),0) FROM mempool_coins"
                ).fetchone()
                pending_spends = db.execute("SELECT COUNT(*) FROM mempool_spends").fetchone()[0]
            return ScanSnapshot(
                height, count, amount, history, observed, pending_count,
                pending_amount, pending_spends,
                chain_current=current,
                blocks_processed=0 if summary is None else summary.blocks_processed,
                transactions_processed=0 if summary is None else summary.transactions_processed,
                rollback_blocks=0 if summary is None else summary.rollback_blocks,
                mempool_transactions_processed=0 if summary is None else summary.mempool_transactions_processed,
            )

    def scan(self, rpc: Wsp1ScannerOnlyRpc, *, user_consented: bool,
             max_blocks: int = 1, include_mempool: bool = False,
             cancelled: Callable[[], bool] | None = None) -> ScanSnapshot:
        _scope(user_consented, _SCOPE)
        if (type(rpc) is not Wsp1ScannerOnlyRpc
                or type(max_blocks) is not int or not 1 <= max_blocks <= 16
                or type(include_mempool) is not bool
                or (cancelled is not None and not callable(cancelled))):
            raise QualifiedScanError("APP_QUALIFIED_SCAN_INPUT_DENIED")
        self._enter()
        try:
            def stopped() -> bool:
                return self._cancel.is_set() or _stop(cancelled)
            if stopped():
                self._failure("APP_QUALIFIED_SCAN_CANCELLED")
            summary = run_consented_wsp_scan(
                self._scanner, rpc, user_consented=True, max_blocks=max_blocks,
                include_mempool=include_mempool, cancelled=stopped,
            )
            if stopped():
                self._failure("APP_QUALIFIED_SCAN_CANCELLED")
            self._scanned = True
            return self._project(summary)
        except QualifiedScanError as error:
            self._failure(str(error))
        except Exception:
            self._failure("APP_QUALIFIED_SCAN_SCAN_DENIED")
        finally:
            self._lock.release()

    def snapshot(self, *, user_consented: bool) -> ScanSnapshot:
        _scope(user_consented, _SCOPE)
        self._enter()
        try:
            if not self._scanned:
                self._failure("APP_QUALIFIED_SCAN_NOT_CURRENT")
            result = self._project()
            if self._cancel.is_set():
                self._failure("APP_QUALIFIED_SCAN_CANCELLED")
            return result
        except Exception:
            self._failure("APP_QUALIFIED_SCAN_NOT_CURRENT")
        finally:
            self._lock.release()


    def history(self, *, user_consented: bool, limit: int = 50,
                offset: int = 0) -> PrivateHistoryPage:
        """Real source-pinned SQLite history under native scanner lease."""
        _scope(user_consented, _SCOPE)
        if (type(limit) is not int or not 1 <= limit <= 100
                or type(offset) is not int or not 0 <= offset <= 100_000):
            raise QualifiedScanError("APP_QUALIFIED_SCAN_HISTORY_INPUT_DENIED")
        self._enter()
        try:
            if not self._scanned:
                self._failure("APP_QUALIFIED_SCAN_NOT_CURRENT")
            scanner = self._scanner
            with scanner._lease(), scanner.store.transaction():
                scanner.assert_current()
                tip = scanner.store.tip()[0]
                records = scanner.store.db.execute(
                    "SELECT txid,height,credit,debit FROM history "
                    "ORDER BY height DESC,txid DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
                page = PrivateHistoryPage(tuple(
                    PrivateHistoryRow(r["txid"], r["height"],
                                      tip - r["height"] + 1, r["credit"], r["debit"])
                    for r in records
                ), tip, offset)
                scanner.assert_current()
            if self._cancel.is_set():
                self._failure("APP_QUALIFIED_SCAN_CANCELLED")
            return page
        except QualifiedScanError as error:
            self._failure(str(error))
        except Exception:
            self._failure("APP_QUALIFIED_SCAN_HISTORY_DENIED")
        finally:
            self._lock.release()

    def save_checkpoint(self, private_dir: Path, password: bytes, *,
                        user_consented: bool) -> None:
        """Actual WSP-1 Store.export_checkpoint AES-GCM + create-once archive."""
        _scope(user_consented, _SCOPE)
        if (type(private_dir) is not type(Path()) or not private_dir.is_absolute()
                or type(password) is not bytes or not 12 <= len(password) <= 1024):
            raise QualifiedScanError("APP_QUALIFIED_SCAN_CHECKPOINT_INPUT_DENIED")
        self._enter()
        try:
            if not self._scanned:
                self._failure("APP_QUALIFIED_SCAN_NOT_CURRENT")
            scanner = self._scanner
            if private_dir != scanner.store.path.parent:
                self._failure("APP_QUALIFIED_SCAN_CHECKPOINT_PATH_DENIED")
            with scanner._lease():
                scanner.assert_current()
                ciphertext = scanner.checkpoint(password)
                scanner.assert_current()
                if self._cancel.is_set():
                    self._failure("APP_QUALIFIED_SCAN_CANCELLED")
                store_encrypted_checkpoint(private_dir, ciphertext)
            if self._cancel.is_set():
                self._failure("APP_QUALIFIED_SCAN_CANCELLED")
        except QualifiedScanError as error:
            self._failure(str(error))
        except Exception:
            self._failure("APP_QUALIFIED_SCAN_CHECKPOINT_DENIED")
        finally:
            self._lock.release()

    def receive_code(self, *, user_consented: bool, account_index: int = 0) -> ReceiveCode:
        _scope(user_consented, _SCOPE)
        if type(account_index) is not int or not 0 <= account_index < 16:
            raise QualifiedScanError("APP_QUALIFIED_SCAN_INPUT_DENIED")
        self._enter()
        try:
            code = self._scanner.accounts[account_index].payment_code()
            result = ReceiveCode(code)
            self._decode(code, hrp="wamrtsp")
            if self._cancel.is_set():
                self._failure("APP_QUALIFIED_SCAN_CANCELLED")
            return result
        except Exception:
            self._failure("APP_QUALIFIED_SCAN_RECEIVE_DENIED")
        finally:
            self._lock.release()
