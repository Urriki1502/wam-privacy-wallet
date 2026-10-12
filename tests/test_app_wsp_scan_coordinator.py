"""Dependency-free app controller checks; the native WSP CI uses REAL Scanner.

Mocks here are tests only. Production module never creates a fake engine or
falls back to mock RPC on genuine scanner failures.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import wsp_scan_coordinator as app


class LocalScannerRpc:
    _mempool = False


class LocalMempoolRpc:
    _mempool = True


class SyntheticScanEngine:
    def __init__(self):
        self.calls = []
        self.ready = True
        self.blocks = 1
        self.transactions = 2
        self.rollback = 0
        self.mempool_result = 3
        self.fail = False

    def sync(self, rpc, max_blocks=None, cancel=None):
        self.calls.append(("sync", max_blocks, rpc))
        if self.fail:
            raise RuntimeError("secret wallet state must not leak")
        if cancel():
            raise ValueError("SCAN_CANCELLED hidden private input")
        return SimpleNamespace(blocks=self.blocks,
                               transactions=self.transactions,
                               rollback=self.rollback)

    def sync_mempool(self, rpc):
        self.calls.append(("mempool", None, rpc))
        return self.mempool_result


class AppWspScanCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.scanner = SyntheticScanEngine()
        self.rpc = LocalScannerRpc()
        self.mem = LocalMempoolRpc()
        patcher = patch.object(app, "Wsp1ScannerOnlyRpc", LocalScannerRpc)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_consent_is_required_before_any_scanner_method(self):
        with self.assertRaisesRegex(app.ApplicationScanError,
                                    "^APP_WSP_SCAN_INPUT_DENIED$"):
            app.run_consented_wsp_scan(
                self.scanner, self.rpc, user_consented=False
            )
        self.assertEqual(self.scanner.calls, [])

    def test_default_real_engine_contract_returns_only_scalar_untrusted_summary(self):
        result = app.run_consented_wsp_scan(
            self.scanner, self.rpc, user_consented=True, max_blocks=2
        )
        self.assertEqual((result.blocks_processed, result.transactions_processed,
                          result.rollback_blocks, result.mempool_transactions_processed),
                         (1, 2, 0, 0))
        self.assertEqual(self.scanner.calls, [("sync", 2, self.rpc)])
        self.assertEqual(result.status, "WSP1_SCAN_EXECUTED_UNTRUSTED_CORE")

    def test_no_wallet_spending_or_consensus_authority_ever_returned(self):
        result = app.run_consented_wsp_scan(
            self.scanner, self.rpc, user_consented=True
        )
        for name in ("core_authenticated", "wallet_operational",
                     "balance_qualified", "signer_enabled",
                     "broadcast_allowed", "mainnet_allowed"):
            self.assertIs(getattr(result, name), False)
        self.assertFalse({"scanner", "rpc", "account", "keys", "password",
                          "balance", "transactions", "txid"}
                         & {field.name for field in fields(result)})
        with self.assertRaises(FrozenInstanceError):
            result.blocks_processed = 999

    def test_invalid_types_and_oversized_batches_rejected_before_engine(self):
        invalid = (
            {"max_blocks": 0}, {"max_blocks": 17},
            {"max_blocks": True}, {"max_blocks": 1.0},
            {"include_mempool": 1}, {"cancelled": object()},
            {"user_consented": 1}, {"user_consented": "yes"},
        )
        for args in invalid:
            with self.subTest(args=args), self.assertRaisesRegex(
                app.ApplicationScanError, "^APP_WSP_SCAN_INPUT_DENIED$",
            ):
                app.run_consented_wsp_scan(
                    self.scanner, self.rpc, user_consented=True, **args
                ) if "user_consented" not in args else app.run_consented_wsp_scan(
                    self.scanner, self.rpc, **args
                )
        self.assertEqual(self.scanner.calls, [])

    def test_no_engine_and_imposter_rpc_denied_without_side_effect(self):
        with self.assertRaisesRegex(
            app.ApplicationScanError, "^APP_WSP_SCAN_ENGINE_REQUIRED$",
        ):
            app.run_consented_wsp_scan(None, self.rpc, user_consented=True)
        with self.assertRaisesRegex(
            app.ApplicationScanError, "^APP_WSP_SCAN_INPUT_DENIED$",
        ):
            app.run_consented_wsp_scan(
                self.scanner, self.mem, user_consented=True
            )
        self.assertEqual(self.scanner.calls, [])

    def test_pre_cancel_denies_before_scan_sync(self):
        with self.assertRaisesRegex(
            app.ApplicationScanError, "^APP_WSP_SCAN_CANCELLED$",
        ):
            app.run_consented_wsp_scan(
                self.scanner, self.rpc, user_consented=True,
                cancelled=lambda: True,
            )
        self.assertEqual(self.scanner.calls, [])

    def test_bad_cancel_callback_result_also_denies(self):
        with self.assertRaisesRegex(
            app.ApplicationScanError, "^APP_WSP_SCAN_CANCELLED$",
        ):
            app.run_consented_wsp_scan(
                self.scanner, self.rpc, user_consented=True,
                cancelled=lambda: "yes",
            )
        self.assertEqual(self.scanner.calls, [])

    def test_callback_runtime_failure_redacts_sensitive_context(self):
        def broken_callback():
            raise RuntimeError("real key contents")
        with self.assertRaisesRegex(
            app.ApplicationScanError, "^APP_WSP_SCAN_CANCELLED$",
        ) as observed:
            app.run_consented_wsp_scan(
                self.scanner, self.rpc, user_consented=True,
                cancelled=broken_callback,
            )
        self.assertNotIn("real key", str(observed.exception))
        self.assertEqual(self.scanner.calls, [])

    def test_upstream_failure_denied_no_mock_success_fallback(self):
        self.scanner.fail = True
        with self.assertRaisesRegex(
            app.ApplicationScanError, "^APP_WSP_SCAN_RUNTIME_DENIED$",
        ) as observed:
            app.run_consented_wsp_scan(
                self.scanner, self.rpc, user_consented=True
            )
        self.assertNotIn("secret wallet state", repr(observed.exception))
        self.assertEqual(len(self.scanner.calls), 1)

    def test_mempool_opt_in_requires_dedicated_rpc_before_engine(self):
        with self.assertRaisesRegex(
            app.ApplicationScanError, "^APP_WSP_SCAN_MEMPOOL_SCOPE_DENIED$",
        ):
            app.run_consented_wsp_scan(
                self.scanner, self.rpc, user_consented=True,
                include_mempool=True,
            )
        self.assertEqual(self.scanner.calls, [])

    def test_mempool_active_only_after_completed_scan(self):
        # A strict stand-in for the two separately class-bound RPC capabilities.
        with patch.object(app, "Wsp1ScannerOnlyRpc", LocalMempoolRpc):
            self.scanner.ready = False
            with self.assertRaisesRegex(
                app.ApplicationScanError, "^APP_WSP_SCAN_INCOMPLETE$",
            ):
                app.run_consented_wsp_scan(
                    self.scanner, self.mem, user_consented=True,
                    include_mempool=True,
                )
            self.assertEqual([v[0] for v in self.scanner.calls], ["sync"])

    def test_complete_scan_enables_only_explicit_mempool_read(self):
        with patch.object(app, "Wsp1ScannerOnlyRpc", LocalMempoolRpc):
            result = app.run_consented_wsp_scan(
                self.scanner, self.mem, user_consented=True,
                include_mempool=True,
            )
        self.assertEqual(result.mempool_transactions_processed, 3)
        self.assertEqual([v[0] for v in self.scanner.calls],
                         ["sync", "mempool"])
        self.assertIs(result.broadcast_allowed, False)

    def test_forged_result_boolean_and_negative_counts_denied(self):
        for values in (
            {"blocks": True}, {"blocks": -1}, {"blocks": 17},
            {"transactions": True}, {"transactions": -1},
            {"transactions": 160_001}, {"rollback": True},
            {"rollback": -1}, {"rollback": 100_001},
        ):
            self.scanner.blocks = 1
            self.scanner.transactions = 2
            self.scanner.rollback = 0
            for key, value in values.items():
                setattr(self.scanner, key, value)
            with self.subTest(values=values), self.assertRaisesRegex(
                app.ApplicationScanError, "^APP_WSP_SCAN_RESULT_DENIED$",
            ):
                app.run_consented_wsp_scan(
                    self.scanner, self.rpc, user_consented=True,
                )

    def test_mempool_oversize_and_bool_counts_denied(self):
        with patch.object(app, "Wsp1ScannerOnlyRpc", LocalMempoolRpc):
            for forged in (True, -1, 10_001, [], 1.5):
                self.scanner.mempool_result = forged
                with self.subTest(value=str(forged)[:30]), self.assertRaisesRegex(
                    app.ApplicationScanError, "^APP_WSP_SCAN_RESULT_DENIED$",
                ):
                    app.run_consented_wsp_scan(
                        self.scanner, self.mem, user_consented=True,
                        include_mempool=True,
                    )

    def test_no_upstream_wsp_import_or_fake_fallback_in_application_module(self):
        self.assertNotIn("wam_sp.scanner", sys.modules)
        # This offline suite intentionally never imports external WSP; the
        # separate native-source CI verifies the real pinned scanner path.
        self.assertTrue(callable(app.run_consented_wsp_scan))


if __name__ == "__main__":
    unittest.main()
