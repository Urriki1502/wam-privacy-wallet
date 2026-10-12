"""Fail-closed disposable WSP scan-only import contract.

These dummy engines are NEGATIVE tests only. The native WSP CI invokes real
source-pinned import_scan, Scanner, SQLite and loopback synthetic-regtest RPC.
"""
from __future__ import annotations

from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import scan_only_account_session as m
from wam_privacy_wallet.application import wsp_scan_coordinator as coordinator


class OnlyRpc:
    _mempool = False


class FakeScanner:
    def __init__(self, path, accounts):
        self.path = path
        self.accounts = accounts
        self.closed = False
        self.fail = False
        self.close_fail = False

    def sync(self, rpc, max_blocks=1, cancel=None):
        self.path.write_text("disposable TEST fixture")
        if self.fail:
            raise ValueError("scan_secret: private fixture")
        return SimpleNamespace(blocks=1, transactions=0, rollback=0)

    def close(self):
        self.closed = True
        if self.close_fail:
            raise ValueError("scan_secret: close failure")


class DisposableScanOnlyTests(unittest.TestCase):
    def setUp(self):
        self.rpc = OnlyRpc()
        self.calls = []
        self.created = []

        def importer(encrypted, password):
            self.calls.append(("import", encrypted, password))
            return (object(),)

        def build(path, accounts):
            self.calls.append(("factory", path, accounts))
            scanner = FakeScanner(path, accounts)
            self.created.append(scanner)
            return scanner

        self.importer = importer
        self.builder = build
        self.patchers = (
            patch.object(m, "Wsp1ScannerOnlyRpc", OnlyRpc),
            patch.object(coordinator, "Wsp1ScannerOnlyRpc", OnlyRpc),
        )
        for p in self.patchers:
            p.start()
            self.addCleanup(p.stop)

    def invoke(self, **changes):
        kwargs = {
            "import_scan": self.importer,
            "scanner_factory": self.builder,
            "rpc": self.rpc,
            "user_consented": True,
        }
        kwargs.update(changes)
        test_password = kwargs.pop("password", b"test-only-password")
        return m.run_disposable_scan_only_backup(
            b"E" * 52, test_password, **kwargs
        )

    def test_consent_denied_before_any_decryption_or_io(self):
        with self.assertRaisesRegex(m.ScanOnlySessionError,
                                    "^APP_SCAN_ONLY_INPUT_DENIED$"):
            self.invoke(user_consented=False)
        self.assertEqual(self.calls, [])

    def test_invalid_envelope_type_and_size_denied_before_import(self):
        for value in ("backup", bytearray(b"E"*52), b"", b"A"*51, b"A"*1_048_577):
            with self.subTest(kind=str(type(value))), self.assertRaises(
                m.ScanOnlySessionError,
            ):
                m.run_disposable_scan_only_backup(
                    value, b"test-only-password", import_scan=self.importer,
                    scanner_factory=self.builder, rpc=self.rpc,
                    user_consented=True,
                )
        self.assertEqual(self.calls, [])

    def test_invalid_passphrase_boundaries_denied(self):
        for value in (None, "not bytes", b"", b"a"*11, b"a"*1025):
            with self.subTest(kind=str(type(value))), self.assertRaises(
                m.ScanOnlySessionError,
            ):
                self.invoke(password=value)
        self.assertEqual(self.calls, [])

    def test_bool_and_oversized_block_limits_denied(self):
        for value in (True, 0, 17, 1.5):
            with self.subTest(value=value), self.assertRaises(
                m.ScanOnlySessionError,
            ):
                self.invoke(max_blocks=value)
        self.assertEqual(self.calls, [])

    def test_scanner_callbacks_and_exact_rpc_required(self):
        for changes in (
            {"import_scan": None}, {"scanner_factory": None},
            {"rpc": object()}, {"cancelled": object()},
        ):
            with self.subTest(changes=str(changes)), self.assertRaises(
                m.ScanOnlySessionError,
            ):
                self.invoke(**changes)
        self.assertEqual(self.calls, [])

    def test_cancelled_preimport_denies_before_decryption(self):
        with self.assertRaisesRegex(m.ScanOnlySessionError,
                                    "^APP_SCAN_ONLY_CANCELLED$"):
            self.invoke(cancelled=lambda: True)
        self.assertEqual(self.calls, [])

    def test_faulty_cancel_callback_redacted_before_import(self):
        def bad():
            raise RuntimeError("real password would leak")
        with self.assertRaisesRegex(m.ScanOnlySessionError,
                                    "^APP_SCAN_ONLY_CANCELLED$") as raised:
            self.invoke(cancelled=bad)
        self.assertNotIn("password", str(raised.exception))
        self.assertEqual(self.calls, [])

    def test_decryption_failure_fails_closed_without_scanner(self):
        def wrong_password(*_):
            raise ValueError("key data and passphrase")
        with self.assertRaisesRegex(m.ScanOnlySessionError,
                                    "^APP_SCAN_ONLY_RUNTIME_DENIED$") as raised:
            self.invoke(import_scan=wrong_password)
        self.assertNotIn("passphrase", str(raised.exception))
        self.assertEqual(self.created, [])

    def test_wrong_account_collection_shape_denied(self):
        for output in ([], (), [object()], tuple(object() for _ in range(17))):
            with self.subTest(kind=type(output).__name__), self.assertRaises(
                m.ScanOnlySessionError,
            ):
                self.invoke(import_scan=lambda *_: output)
        self.assertEqual(self.created, [])

    def test_disposable_database_path_is_removed_and_scanner_closed(self):
        summary = self.invoke()
        self.assertEqual(len(self.created), 1)
        scanner = self.created[0]
        self.assertTrue(scanner.closed)
        self.assertFalse(scanner.path.exists())
        self.assertFalse(scanner.path.parent.exists())
        self.assertEqual(summary.blocks_processed, 1)

    def test_only_untrusted_scalar_summary_leaves_session(self):
        summary = self.invoke()
        self.assertEqual(summary.status, "WSP1_SCAN_EXECUTED_UNTRUSTED_CORE")
        self.assertFalse(summary.wallet_operational)
        self.assertFalse(summary.signer_enabled)
        self.assertFalse(summary.broadcast_allowed)
        self.assertFalse(summary.mainnet_allowed)
        self.assertFalse({"scan_secret", "password", "account", "rpc", "scanner"}
                         & {item.name for item in fields(summary)})

    def test_upstream_scan_error_redacts_and_still_closes(self):
        def failing_builder(path, accounts):
            s = FakeScanner(path, accounts)
            s.fail = True
            self.created.append(s)
            return s
        with self.assertRaisesRegex(m.ScanOnlySessionError,
                                    "^APP_SCAN_ONLY_SCAN_DENIED$"):
            self.invoke(scanner_factory=failing_builder)
        self.assertTrue(self.created[0].closed)

    def test_failed_close_invalidates_success_and_cleans_tempfile(self):
        def bad_close(path, accounts):
            s = FakeScanner(path, accounts)
            s.close_fail = True
            self.created.append(s)
            return s
        with self.assertRaisesRegex(m.ScanOnlySessionError,
                                    "^APP_SCAN_ONLY_RUNTIME_DENIED$"):
            self.invoke(scanner_factory=bad_close)
        self.assertFalse(self.created[0].path.parent.exists())

    def test_no_default_wsp_auto_import_or_signing_method(self):
        self.assertNotIn("wam_sp", m.__dict__)
        self.assertFalse(hasattr(m, "sendrawtransaction"))
        self.assertFalse(hasattr(m, "construct_spend"))


if __name__ == "__main__":
    unittest.main()
