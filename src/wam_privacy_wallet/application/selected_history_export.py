"""One-shot local disclosure of selected WSP observations; no proof or keys.

Only the existing private history projection is accepted. This does not import
shielded research, open a wallet, read secrets, contact Core or grant authority.
The originating scanner and Core qualifications remain separate.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
import json
import re
from threading import Lock
from time import monotonic

from .qualified_scan_session import PrivateHistoryPage, PrivateHistoryRow
from ..integrations.wsp1_source_review import PINNED_COMMIT

_TXID = re.compile(r"[0-9a-f]{64}\Z")
_FIELDS = frozenset(("height", "confirmations", "credit_atoms", "debit_atoms"))


class LocalHistoryExportError(ValueError):
    """Fixed redacted failure; never rows, paths, amounts or consent digests."""


@dataclass(frozen=True, slots=True, repr=False)
class LocalHistoryExportPreview:
    """Private data for local review only, never a logging/telemetry receipt."""
    payload: bytes
    approval_sha256: str


class LocalHistoryExport:
    """In-memory one-use consent; expires after 120 monotonic seconds.

    The approval hash binds exact preview bytes, not a cryptographic wallet
    proof. Cancellation clears a pending export, never already copied data.
    A caller cannot widen an existing selection; create a new review instead.
    """
    __slots__ = ("_payload", "_digest", "_expires", "_lock")

    def __init__(self, page: object, *, selected_txids: object,
                 fields: object, user_consented: object):
        try:
            if (user_consented is not True or type(selected_txids) is not tuple
                    or not 1 <= len(selected_txids) <= 20
                    or any(type(x) is not str or _TXID.fullmatch(x) is None for x in selected_txids)
                    or len(set(selected_txids)) != len(selected_txids)
                    or type(fields) is not tuple or not 1 <= len(fields) <= 4
                    or any(type(x) is not str or x not in _FIELDS for x in fields)
                    or len(set(fields)) != len(fields)):
                raise ValueError
            if (type(page) is not PrivateHistoryPage
                    or type(page.records) is not tuple or not 1 <= len(page.records) <= 100
                    or type(page.tip_height) is not int or not 1 <= page.tip_height <= 100_000_000
                    or type(page.offset) is not int or not 0 <= page.offset <= 100_000
                    or type(page.source_commit) is not str or page.source_commit != PINNED_COMMIT
                    or any(getattr(page, x) is not False for x in (
                        "wallet_operational", "signer_enabled", "broadcast_allowed", "mainnet_allowed"))):
                raise ValueError
            records = {}
            for row in page.records:
                if type(row) is not PrivateHistoryRow:
                    raise ValueError
                # Revalidate frozen values: an untrusted caller can still forge
                # a DTO or mutate via object.__setattr__. No provenance inferred.
                checked = PrivateHistoryRow(row.txid, row.height, row.confirmations,
                                            row.credit_atoms, row.debit_atoms)
                if (checked.txid in records or checked.height > page.tip_height
                        or checked.confirmations != page.tip_height - checked.height + 1):
                    raise ValueError
                records[checked.txid] = checked
            if not set(selected_txids) <= set(records):
                raise ValueError  # never silently drop missing rows or export all
            rows = [dict(txid=txid, **{name: getattr(records[txid], name)
                                     for name in sorted(fields)})
                    for txid in sorted(selected_txids)]
            self._payload = json.dumps({
                "schema": "wam-local-history-export/v1",
                "scope": "disposable-regtest-review",
                "source_commit": PINNED_COMMIT,
                "evidence": "LOCAL_WSP_HISTORY_OBSERVATION_UNQUALIFIED",
                "tip_height": page.tip_height, "rows": rows,
                "proof_verified": False, "spend_authorized": False,
            }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            self._digest = sha256(self._payload).hexdigest()
            self._expires = monotonic() + 120
            self._lock = Lock()
        except Exception:
            raise LocalHistoryExportError("APP_LOCAL_HISTORY_EXPORT_DENIED") from None

    def _clear(self):
        self._payload = None
        self._digest = None

    def cancel(self) -> None:
        with self._lock:
            self._clear()

    def preview(self, *, user_consented: object) -> LocalHistoryExportPreview:
        with self._lock:
            if user_consented is not True or self._payload is None or monotonic() >= self._expires:
                self._clear()
                raise LocalHistoryExportError("APP_LOCAL_HISTORY_EXPORT_DENIED")
            return LocalHistoryExportPreview(self._payload, self._digest)

    def export(self, *, approved_sha256: object, user_consented: object) -> bytes:
        with self._lock:
            try:
                if (user_consented is not True or self._payload is None
                        or monotonic() >= self._expires
                        or type(approved_sha256) is not str
                        or _TXID.fullmatch(approved_sha256) is None
                        or not compare_digest(approved_sha256, self._digest)):
                    raise ValueError
                return self._payload
            except Exception:
                raise LocalHistoryExportError("APP_LOCAL_HISTORY_EXPORT_DENIED") from None
            finally:
                self._clear()  # every final attempt consumes approval
