"""Fail-closed WSP->GUI orchestration regressions (synthetic test doubles).

The native WSP+Qt workflow separately proves the same path with actual pinned
WSP Scanner, SQLite, crypto and offscreen MainWindow.
"""
from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import scan_preview_workflow as app
from wam_privacy_wallet.application import scan_only_account_session as session
from wam_privacy_wallet.application import wsp_scan_coordinator as coordinator


class TestRpc:
    _mempool = False


class TestScanner:
    def __init__(self, path, accounts, events, fail=False, fail_close=False):
        self.path = path
        self.events = events
        self.fail = fail
        self.fail_close = fail_close
        events.append("constructed")

    def sync(self, rpc, max_blocks=1, cancel=None):
        self.events.append("scan")
        if self.fail:
            raise ValueError("SECRET SCAN ACCOUNT")
        self.path.write_text("throwaway test database")
        return SimpleNamespace(blocks=1, transactions=1, rollback=0)

    def close(self):
        self.events.append("closed")
        if self.fail_close:
            raise ValueError("SECRET CLOSE")


class ScanPreviewWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.rpc = TestRpc()
        for mod in (session, coordinator):
            p = patch.object(mod, "Wsp1ScannerOnlyRpc", TestRpc)
            p.start()
            self.addCleanup(p.stop)

    def clear(self):
        self.events.append("clear")

    def present(self, result):
        self.events.append("present")
        self.result = result

    def importer(self, envelope, password):
        self.events.append("import")
        return (object(),)

    def scanner_factory(self, path, accounts):
        return TestScanner(path, accounts, self.events)

    def invoke(self, **changes):
        opts = dict(import_scan=self.importer, scanner_factory=self.scanner_factory,
                    rpc=self.rpc, user_consented=True, clear_preview=self.clear,
                    present_preview=self.present)
        opts.update(changes)
        return app.run_disposable_scan_preview(
            b"E" * 52, b"only-test-passphrase", **opts,
        )

    def test_full_app_scan_to_presentation_order_and_scalar_receipt(self):
        r = self.invoke()
        self.assertEqual(self.events,
                         ["clear", "import", "constructed", "scan", "closed", "present"])
        self.assertIs(r, self.result)
        self.assertEqual((r.blocks_processed, r.transactions_processed), (1, 1))

    def test_denied_consent_clears_without_import(self):
        with self.assertRaisesRegex(app.ScanPreviewError,
                                    "^APP_SCAN_PREVIEW_INPUT_DENIED$"):
            self.invoke(user_consented=False)
        self.assertEqual(self.events, ["clear"])

    def test_forged_consent_is_denied(self):
        with self.assertRaises(app.ScanPreviewError):
            self.invoke(user_consented=1)
        self.assertEqual(self.events, ["clear"])

    def test_missing_clear_denies_before_wallet_io(self):
        with self.assertRaisesRegex(app.ScanPreviewError,
                                    "^APP_SCAN_PREVIEW_CLEAR_REQUIRED$"):
            self.invoke(clear_preview=None)
        self.assertEqual(self.events, [])

    def test_initial_clear_failure_aborts_before_import(self):
        def fail_clear():
            raise ValueError("SECRET")
        with self.assertRaisesRegex(app.ScanPreviewError,
                                    "^APP_SCAN_PREVIEW_CLEAR_DENIED$"):
            self.invoke(clear_preview=fail_clear)
        self.assertEqual(self.events, [])

    def test_missing_presenter_denies_before_import(self):
        with self.assertRaisesRegex(app.ScanPreviewError,
                                    "^APP_SCAN_PREVIEW_INPUT_DENIED$"):
            self.invoke(present_preview=None)
        self.assertEqual(self.events, ["clear"])

    def test_decrypt_failure_erases_old_receipt_and_redacts(self):
        def broken(*_):
            raise ValueError("SECRET PASSWORD")
        with self.assertRaisesRegex(app.ScanPreviewError,
                                    "^APP_SCAN_PREVIEW_SCAN_DENIED$") as error:
            self.invoke(import_scan=broken)
        self.assertEqual(self.events, ["clear", "clear"])
        self.assertNotIn("SECRET", str(error.exception))

    def test_cancellation_clears_before_import(self):
        with self.assertRaisesRegex(app.ScanPreviewError,
                                    "^APP_SCAN_PREVIEW_SCAN_DENIED$"):
            self.invoke(cancelled=lambda: True)
        self.assertEqual(self.events, ["clear", "clear"])

    def test_scanner_failure_closes_and_no_mock_fallback(self):
        def broken(path, accounts):
            return TestScanner(path, accounts, self.events, fail=True)
        with self.assertRaises(app.ScanPreviewError):
            self.invoke(scanner_factory=broken)
        self.assertEqual(self.events[-2:], ["closed", "clear"])
        self.assertNotIn("present", self.events)

    def test_render_failure_clears_previous_evidence(self):
        def broken(_):
            self.events.append("render_failure")
            raise ValueError("SECRET GUI ERROR")
        with self.assertRaisesRegex(app.ScanPreviewError,
                                    "^APP_SCAN_PREVIEW_RENDER_DENIED$") as error:
            self.invoke(present_preview=broken)
        self.assertEqual(self.events[-2:], ["render_failure", "clear"])
        self.assertNotIn("SECRET", str(error.exception))

    def test_render_and_clear_both_fail_blocks_status(self):
        attempts = [0]
        def bad_clear():
            attempts[0] += 1
            if attempts[0] == 2:
                raise ValueError("SECRET")
            self.events.append("clear")
        with self.assertRaisesRegex(app.ScanPreviewError,
                                    "^APP_SCAN_PREVIEW_CLEAR_DENIED$"):
            self.invoke(clear_preview=bad_clear,
                        present_preview=lambda _: 1 / 0)
        self.assertEqual(attempts[0], 2)

    def test_failed_scanner_close_erases_preview(self):
        def broken(path, accounts):
            return TestScanner(path, accounts, self.events, fail_close=True)
        with self.assertRaises(app.ScanPreviewError):
            self.invoke(scanner_factory=broken)
        self.assertEqual(self.events[-2:], ["closed", "clear"])

    def test_invalid_password_type_no_import(self):
        with self.assertRaises(app.ScanPreviewError):
            self.invoke(password="not bytes")
        self.assertEqual(self.events, ["clear", "clear"])

    def test_no_wallet_spend_or_core_authority_leaks(self):
        r = self.invoke()
        for flag in ("core_authenticated", "wallet_operational",
                     "balance_qualified", "signer_enabled",
                     "broadcast_allowed", "mainnet_allowed"):
            self.assertIs(getattr(r, flag), False)
        self.assertFalse({"password", "scanner", "rpc", "account", "seed"}
                         & set(r.__dataclass_fields__))

    def test_no_implicit_wsp_gui_or_signer_imports(self):
        self.assertFalse(hasattr(app, "Keyring"))
        self.assertFalse(hasattr(app, "MainWindow"))
        self.assertFalse(hasattr(app, "sendrawtransaction"))


if __name__ == "__main__":
    unittest.main()
