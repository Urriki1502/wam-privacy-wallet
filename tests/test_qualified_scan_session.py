"""Adversarial adapter boundaries; no mocked engine is integration evidence.

Actual source-pinned Linux Scanner/SQLite positives live in the separate native
runner. Scalar DTO construction here proves its protocol shape only.
"""
from __future__ import annotations

from dataclasses import fields
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import qualified_scan_session as app


class StringSubclass(str):
    def __eq__(self, other):
        raise AssertionError("untrusted equality callback invoked")


class FailingEngine:
    """Fault fixture only: cannot return a successful scan or Store snapshot."""
    def __init__(self):
        self.closed = False
        self.accounts = ()

    def close(self):
        self.closed = True

    def _lease(self):
        raise ValueError("private path and scan key must not escape")


class QualifiedScanBoundaryTests(unittest.TestCase):
    def runtime(self, **changes):
        kwargs = dict(user_consented=True)
        kwargs.update(changes)
        return app.SourceQualifiedScanRuntime(Path.cwd(), **kwargs)

    def session(self):
        engine = FailingEngine()
        session = app.QualifiedScanSession(engine, lambda *_: None,
                                           _token=app._SESSION_TOKEN)
        self.addCleanup(session.close)
        return engine, session

    def test_no_consent_denied_before_source_or_dependency_read(self):
        with patch.object(app, "verify_wsp1_full_source_closure") as source:
            for consent in (False, 1, "yes", None):
                with self.subTest(consent=consent), self.assertRaisesRegex(
                    app.QualifiedScanError, "^APP_QUALIFIED_SCAN_SCOPE_DENIED$",
                ):
                    self.runtime(user_consented=consent)
            source.assert_not_called()

    def test_other_network_or_production_scope_denied_before_source(self):
        with patch.object(app, "verify_wsp1_full_source_closure") as source:
            for scope in ("mainnet", "regtest", "production", None,
                          StringSubclass("disposable-regtest-review")):
                with self.subTest(scope=type(scope).__name__), self.assertRaises(
                    app.QualifiedScanError,
                ):
                    self.runtime(scope=scope)
            source.assert_not_called()

    def test_non_linux_persistence_denied_before_source(self):
        with patch.object(app, "verify_wsp1_full_source_closure") as source:
            for platform in ("darwin", "win32", "unknown"):
                with patch.object(app.sys, "platform", platform), self.assertRaisesRegex(
                    app.QualifiedScanError, "^APP_QUALIFIED_SCAN_PLATFORM_UNQUALIFIED$",
                ):
                    self.runtime()
            source.assert_not_called()

    def test_linux_32bit_denied_before_source(self):
        with (patch.object(app.sys, "platform", "linux"),
              patch.object(app.struct, "calcsize", return_value=4),
              patch.object(app, "verify_wsp1_full_source_closure") as source,
              self.assertRaisesRegex(app.QualifiedScanError,
                                     "^APP_QUALIFIED_SCAN_PLATFORM_UNQUALIFIED$")):
            self.runtime()
        source.assert_not_called()

    def test_cached_upstream_denied_without_native_source_execution(self):
        with (patch.object(app.sys, "platform", "linux"),
              patch.object(app.struct, "calcsize", return_value=8),
              patch.dict(sys.modules, {"wam_sp.injected": object()}),
              patch.object(app, "verify_wsp1_full_source_closure") as source,
              self.assertRaisesRegex(app.QualifiedScanError,
                                     "^APP_QUALIFIED_SCAN_PRELOADED_SOURCE_DENIED$")):
            self.runtime()
        source.assert_not_called()

    def test_wrong_source_path_denied_before_closure(self):
        with (patch.object(app.sys, "platform", "linux"),
              patch.object(app.struct, "calcsize", return_value=8),
              patch.object(app, "verify_wsp1_full_source_closure") as source):
            for root in ("/source", Path("relative"), None):
                with self.subTest(root=type(root).__name__), self.assertRaises(
                    app.QualifiedScanError,
                ):
                    app.SourceQualifiedScanRuntime(root, user_consented=True)
            source.assert_not_called()

    def test_source_failure_redacted_and_no_wsp_import(self):
        before = {name for name in sys.modules if name.startswith("wam_sp")}
        with (patch.object(app.sys, "platform", "linux"),
              patch.object(app.struct, "calcsize", return_value=8),
              patch.object(app, "verify_wsp1_full_source_closure",
                           side_effect=ValueError("private source path")),
              self.assertRaisesRegex(app.QualifiedScanError,
                                     "^APP_QUALIFIED_SCAN_SOURCE_DENIED$")):
            self.runtime()
        self.assertEqual(before, {name for name in sys.modules if name.startswith("wam_sp")})

    def test_open_rejects_secret_input_shape_before_disk(self):
        runtime = object.__new__(app.SourceQualifiedScanRuntime)
        with (patch.object(app, "_platform"),
              patch.object(app, "load_encrypted_scan_backup") as disk):
            for password in ("password", b"", b"x" * 11, b"x" * 1025, bytearray(b"x"*12)):
                with self.subTest(kind=type(password).__name__), self.assertRaises(
                    app.QualifiedScanError,
                ):
                    runtime.open(Path.cwd(), password, user_consented=True)
            disk.assert_not_called()

    def test_open_precancel_or_bad_callback_denied_before_source_disk(self):
        runtime = object.__new__(app.SourceQualifiedScanRuntime)
        with (patch.object(app, "_platform"),
              patch.object(app, "load_encrypted_scan_backup") as disk):
            for callback in (lambda: True, lambda: None, lambda: 1):
                with self.assertRaisesRegex(app.QualifiedScanError,
                                           "^APP_QUALIFIED_SCAN_CANCELLED$"):
                    runtime.open(Path.cwd(), b"test-password", user_consented=True,
                                 cancelled=callback)
            disk.assert_not_called()

    def test_session_cannot_accept_an_injected_public_engine(self):
        with self.assertRaisesRegex(app.QualifiedScanError,
                                   "^APP_QUALIFIED_SCAN_ENGINE_DENIED$"):
            app.QualifiedScanSession(object(), object(), _token=object())

    def test_snapshot_failure_closes_and_redacts(self):
        engine, session = self.session()
        with self.assertRaisesRegex(app.QualifiedScanError,
                                   "^APP_QUALIFIED_SCAN_NOT_CURRENT$"):
            session.snapshot(user_consented=True)
        self.assertTrue(engine.closed)
        self.assertTrue(session.closed)
        with self.assertRaisesRegex(app.QualifiedScanError,
                                   "^APP_QUALIFIED_SCAN_CLOSED$"):
            session.snapshot(user_consented=True)

    def test_receive_failure_closes_without_address_or_account_leak(self):
        engine, session = self.session()
        with self.assertRaisesRegex(app.QualifiedScanError,
                                   "^APP_QUALIFIED_SCAN_RECEIVE_DENIED$"):
            session.receive_code(user_consented=True)
        self.assertTrue(engine.closed)
        self.assertTrue(session.closed)

    def test_no_consent_snapshot_does_not_touch_engine(self):
        engine, session = self.session()
        with self.assertRaisesRegex(app.QualifiedScanError,
                                   "^APP_QUALIFIED_SCAN_SCOPE_DENIED$"):
            session.snapshot(user_consented=False)
        self.assertFalse(engine.closed)

    def test_cancel_and_idempotent_close(self):
        engine, session = self.session()
        session.cancel()
        with self.assertRaisesRegex(app.QualifiedScanError,
                                   "^APP_QUALIFIED_SCAN_CLOSED$"):
            session.receive_code(user_consented=True)
        session.close()
        session.close()
        self.assertTrue(engine.closed)

    def test_close_during_work_requests_cancel_without_concurrent_sqlite_close(self):
        engine, session = self.session()
        session._lock.acquire()
        try:
            with self.assertRaisesRegex(app.QualifiedScanError,
                                       "^APP_QUALIFIED_SCAN_BUSY$"):
                session.close()
            self.assertFalse(engine.closed)
            self.assertTrue(session._cancel.is_set())
        finally:
            session._lock.release()
        session.close()
        self.assertTrue(engine.closed)

    def test_scalar_protocol_never_grants_wallet_authority_or_leaks_secrets(self):
        # Protocol-only DTO shape, not evidence of real upstream execution.
        receipt = app.ScanSnapshot(0, 0, 0, 0, False, None, None, None)
        names = {item.name for item in fields(receipt)}
        self.assertFalse({"password", "scan_secret", "accounts", "txid", "tweak", "scanner"} & names)
        for name in ("core_authenticated", "wallet_operational", "balance_qualified",
                     "signer_enabled", "broadcast_allowed", "mainnet_allowed"):
            self.assertIs(getattr(receipt, name), False)

    def test_invalid_snapshot_counts_and_stale_mempool_denied(self):
        for kwargs in ({"tip_height": True}, {"unqualified_confirmed_atoms": -1},
                       {"confirmed_utxo_count": 1_000_001},
                       {"mempool_utxo_count": 1},
                       {"mempool_observed": True},
                       {"mempool_transactions_processed": 1}):
            data = dict(tip_height=0, confirmed_utxo_count=0,
                        unqualified_confirmed_atoms=0, history_count=0,
                        mempool_observed=False, mempool_utxo_count=None,
                        unqualified_mempool_atoms=None, mempool_spend_count=None)
            data.update(kwargs)
            with self.subTest(changes=kwargs), self.assertRaises(app.QualifiedScanError):
                app.ScanSnapshot(**data)

    def test_mainnet_and_malformed_receive_namespace_denied(self):
        for code in ("sp1" + "q"*120, "tsps1" + "q"*120, "wamrtsp1" + "q"*500,
                     StringSubclass("wamrtsp1" + "q"*120), None):
            with self.subTest(code_type=type(code).__name__), self.assertRaises(
                app.QualifiedScanError,
            ):
                app.ReceiveCode(code)


if __name__ == "__main__":
    unittest.main()
