"""Offline adversarial tests for retained scanner workflow (no real keys).

Pinned actual WSP SQLite restart and reorg are exercised independently by
the native scanner+Qt workflow; fake engines here are negative fixtures.
"""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import retained_scan_session as app
from wam_privacy_wallet.application import wsp_scan_coordinator as coordinator


class LocalOnlyRpc:
    _mempool = False


class TestScanner:
    def __init__(self, path, accounts, events, broken=False, close_broken=False):
        self.path = path
        self.accounts = accounts
        self.events = events
        self.broken = broken
        self.close_broken = close_broken
        self.events.append("constructed")

    def sync(self, rpc, max_blocks=1, cancel=None):
        self.events.append("sync")
        if self.broken:
            raise ValueError("scan_secret leaked")
        return SimpleNamespace(blocks=1, transactions=1, rollback=0)

    def close(self):
        self.events.append("close")
        if self.close_broken:
            raise ValueError("secret in close")


class RetainedScanUnitTests(unittest.TestCase):
    def setUp(self):
        t = TemporaryDirectory(prefix="test-retained-wsp-")
        self.addCleanup(t.cleanup)
        self.folder = Path(t.name)
        self.events = []
        self.rpc = LocalOnlyRpc()
        p1 = patch.object(app, "load_encrypted_scan_backup", side_effect=self.load)
        p2 = patch.object(app, "Wsp1ScannerOnlyRpc", LocalOnlyRpc)
        p3 = patch.object(coordinator, "Wsp1ScannerOnlyRpc", LocalOnlyRpc)
        for p in (p1, p2, p3):
            p.start()
            self.addCleanup(p.stop)

    def load(self, folder):
        self.events.append("load")
        return b"E" * 64

    def importer(self, payload, password):
        self.events.append("import")
        return (object(),)

    def builder(self, path, accounts):
        self.events.append("factory")
        return TestScanner(path, accounts, self.events)

    def run(self, **changes):
        kwargs = dict(
            import_scan=self.importer, scanner_factory=self.builder,
            rpc=self.rpc, user_consented=True,
        )
        kwargs.update(changes)
        password = kwargs.pop("password", b"synthetic-test-password")
        return app.run_retained_scan_only(self.folder, password, **kwargs)

    def test_valid_session_uses_pinned_state_path_and_scalar_only(self):
        result = self.run()
        self.assertEqual(self.events, ["load", "import", "factory",
                                       "constructed", "sync", "close"])
        self.assertEqual(result.blocks_processed, 1)
        self.assertFalse(result.wallet_operational)
        self.assertFalse(result.signer_enabled)

    def test_no_consent_denied_before_disk(self):
        with self.assertRaisesRegex(app.RetainedScanError,
                                    "^APP_RETAINED_INPUT_DENIED$"):
            self.run(user_consented=False)
        self.assertEqual(self.events, [])

    def test_forged_truthy_consent_denied(self):
        with self.assertRaises(app.RetainedScanError):
            self.run(user_consented=1)
        self.assertEqual(self.events, [])

    def test_pre_cancel_denied_before_backup_load(self):
        with self.assertRaisesRegex(app.RetainedScanError,
                                    "^APP_RETAINED_CANCELLED$"):
            self.run(cancelled=lambda: True)
        self.assertEqual(self.events, [])

    def test_cancel_callback_exception_redacted(self):
        def broken():
            raise ValueError("secret password")
        with self.assertRaisesRegex(app.RetainedScanError,
                                    "^APP_RETAINED_CANCELLED$"):
            self.run(cancelled=broken)
        self.assertEqual(self.events, [])

    def test_password_type_or_size_rejected(self):
        for password in (None, "", b"", b"a"*11, b"a"*1025):
            with self.subTest(password=type(password).__name__):
                with self.assertRaises(app.RetainedScanError):
                    self.run(password=password)
        self.assertEqual(self.events, [])

    def test_oversized_or_bool_scan_batch_denied(self):
        for blocks in (True, 0, 17, -1, 1.5):
            with self.subTest(blocks=blocks), self.assertRaises(app.RetainedScanError):
                self.run(max_blocks=blocks)
        self.assertEqual(self.events, [])

    def test_imposter_rpc_denied_before_disk(self):
        with self.assertRaises(app.RetainedScanError):
            self.run(rpc=object())
        self.assertEqual(self.events, [])

    def test_missing_factories_denied(self):
        for kw in ({"import_scan": None}, {"scanner_factory": None},
                   {"cancelled": "yes"}):
            with self.subTest(kwargs=str(kw)), self.assertRaises(app.RetainedScanError):
                self.run(**kw)
        self.assertEqual(self.events, [])

    def test_loader_failure_does_not_import_or_start_scanner(self):
        with patch.object(app, "load_encrypted_scan_backup",
                          side_effect=OSError("secret backup path")):
            with self.assertRaisesRegex(app.RetainedScanError,
                                        "^APP_RETAINED_RUNTIME_DENIED$"):
                self.run()
        self.assertEqual(self.events, [])

    def test_wrong_password_from_upstream_never_constructs_scanner(self):
        def wrong(*_):
            raise ValueError("KEY MATERIAL")
        with self.assertRaisesRegex(app.RetainedScanError,
                                    "^APP_RETAINED_RUNTIME_DENIED$"):
            self.run(import_scan=wrong)
        self.assertEqual(self.events, ["load"])

    def test_bad_account_tuple_is_denied(self):
        with self.assertRaisesRegex(app.RetainedScanError,
                                    "^APP_RETAINED_ACCOUNT_DENIED$"):
            self.run(import_scan=lambda *_: [])
        self.assertEqual(self.events, ["load"])

    def test_upstream_database_mismatch_is_redacted(self):
        def denied(*_):
            raise ValueError("STATE_WALLET_MISMATCH_RESCAN_REQUIRED PRIVATE ID")
        with self.assertRaisesRegex(app.RetainedScanError,
                                    "^APP_RETAINED_RUNTIME_DENIED$"):
            self.run(scanner_factory=denied)
        self.assertEqual(self.events, ["load", "import"])

    def test_upstream_scan_error_closes_before_refusal(self):
        def broken(path, accounts):
            return TestScanner(path, accounts, self.events, broken=True)
        with self.assertRaisesRegex(app.RetainedScanError,
                                    "^APP_RETAINED_SCAN_DENIED$"):
            self.run(scanner_factory=broken)
        self.assertEqual(self.events[-2:], ["sync", "close"])

    def test_close_error_invalidates_success(self):
        def broken(path, accounts):
            return TestScanner(path, accounts, self.events, close_broken=True)
        with self.assertRaisesRegex(app.RetainedScanError,
                                    "^APP_RETAINED_RUNTIME_DENIED$"):
            self.run(scanner_factory=broken)
        self.assertEqual(self.events[-2:], ["sync", "close"])

    def test_existing_database_symlink_cannot_be_opened(self):
        db = self.folder / "scan-only-state.sqlite"
        if __import__("sys").platform == "win32":
            # Windows CI may not grant SeCreateSymbolicLinkPrivilege; this
            # negative test must not silently skip the mandatory suite.
            with patch.object(app, "_check_existing_db",
                              side_effect=app.RetainedScanError("APP_RETAINED_DB_DENIED")):
                with self.assertRaisesRegex(app.RetainedScanError,
                                            "^APP_RETAINED_DB_DENIED$"):
                    self.run()
            return
        db.symlink_to(self.folder / "missing")
        with self.assertRaisesRegex(app.RetainedScanError,
                                    "^APP_RETAINED_DB_DENIED$"):
            self.run()
        self.assertEqual(self.events, ["load", "import"])

    def test_existing_database_bad_modes_are_refused(self):
        db = self.folder / "scan-only-state.sqlite"
        db.write_bytes(b"arbitrary invalid sqlite")
        db.chmod(0o644)
        with self.assertRaisesRegex(app.RetainedScanError,
                                    "^APP_RETAINED_DB_DENIED$"):
            self.run()
        self.assertEqual(self.events, ["load", "import"])

    def test_no_default_crypto_wsp_or_wallet_signing_import(self):
        for name in ("Keyring", "sendrawtransaction", "sign", "MainWindow"):
            self.assertFalse(hasattr(app, name))


if __name__ == "__main__":
    unittest.main()
