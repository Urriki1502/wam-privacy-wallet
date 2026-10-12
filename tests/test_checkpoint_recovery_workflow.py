"""Fail-closed negative recovery tests; native CI proves actual WSP crypto.

No wallet keys, transaction signing or WAM Core are used by these fixtures.
"""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import checkpoint_recovery_workflow as mod
from wam_privacy_wallet.application import wsp_scan_coordinator as coordinator


class FakeRpc:
    _mempool = False


class FakeStore:
    def __init__(self, events, fail=False):
        self.events = events
        self.fail = fail
    def restore_checkpoint(self, data, password):
        self.events.append("restore")
        if self.fail:
            raise ValueError("SECRET_CHECKPOINT_ERROR")


class FakeScanner:
    def __init__(self, path, events, fail=False):
        self.path = path
        self.events = events
        self.store = FakeStore(events, fail)
        events.append("scanner")
    def sync(self, rpc, max_blocks=1, cancel=None):
        self.events.append("sync")
        self.path.write_bytes(b"fake sqlite only in failure tests")
        return SimpleNamespace(blocks=0, transactions=0, rollback=0)
    def close(self):
        self.events.append("close")


class RecoveryWorkflowNegativeTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory(prefix="test-recovery-negative-")
        self.addCleanup(tmp.cleanup)
        self.directory = Path(tmp.name)
        self.rpc = FakeRpc()
        self.events = []
        self.receipt = None
        for obj,name,side in ((mod, "Wsp1ScannerOnlyRpc", FakeRpc),
                              (coordinator, "Wsp1ScannerOnlyRpc", FakeRpc)):
            p = patch.object(obj, name, side)
            p.start()
            self.addCleanup(p.stop)
        for attr, callback in (
            ("load_encrypted_scan_backup", self.load_account),
            ("load_encrypted_checkpoint", self.load_checkpoint),
        ):
            p = patch.object(mod, attr, side_effect=callback)
            p.start()
            self.addCleanup(p.stop)

    def load_account(self, path):
        self.events.append("account_file")
        return b"E"*64

    def load_checkpoint(self, path):
        self.events.append("checkpoint_file")
        return b"C"*64

    def importer(self, envelope, password):
        self.events.append("import")
        return (object(),)

    def scanner_factory(self, path, accounts):
        return FakeScanner(path, self.events)

    def clear(self):
        self.events.append("clear")
        self.receipt = None

    def present(self, summary):
        self.events.append("present")
        self.receipt = summary

    def invoke(self, **changes):
        options = dict(import_scan=self.importer,
                       scanner_factory=self.scanner_factory,
                       rpc=self.rpc, user_consented=True,
                       clear_preview=self.clear, present_preview=self.present)
        options.update(changes)
        password = options.pop("password", b"synthetic-only-password")
        return mod.recover_checkpoint_scan_preview(
            self.directory, password, **options
        )

    def test_expected_real_workflow_stage_order(self):
        r = self.invoke()
        self.assertEqual(self.events,
            ["clear","account_file","checkpoint_file","import","scanner",
             "restore","sync","close","present"])
        self.assertIs(r,self.receipt)
        self.assertFalse(r.wallet_operational)

    def test_denies_missing_clear_without_io(self):
        with self.assertRaisesRegex(mod.CheckpointRecoveryError,
                                    "^APP_RECOVERY_CLEAR_REQUIRED$"):
            self.invoke(clear_preview=None)
        self.assertEqual(self.events, [])

    def test_denies_initial_clear_exception_without_io(self):
        def bad():
            raise ValueError("SECRET")
        with self.assertRaisesRegex(mod.CheckpointRecoveryError,
                                    "^APP_RECOVERY_CLEAR_DENIED$"):
            self.invoke(clear_preview=bad)
        self.assertEqual(self.events, [])

    def test_denies_false_consent_without_loading_anything(self):
        with self.assertRaisesRegex(mod.CheckpointRecoveryError,
                                    "^APP_RECOVERY_INPUT_DENIED$"):
            self.invoke(user_consented=False)
        self.assertEqual(self.events, ["clear"])

    def test_denies_integer_truthy_consent(self):
        with self.assertRaises(mod.CheckpointRecoveryError):
            self.invoke(user_consented=1)
        self.assertEqual(self.events, ["clear"])

    def test_wrong_password_input_types_rejected_early(self):
        for pw in (None, "text", b"", b"A"*11, b"A"*1025):
            with self.subTest(kind=str(type(pw))):
                self.events.clear()
                with self.assertRaises(mod.CheckpointRecoveryError):
                    self.invoke(password=pw)
                self.assertEqual(self.events, ["clear"])

    def test_no_operational_scanner_or_presenter_fallback(self):
        for opts in ({"import_scan":None},{"scanner_factory":None},
                     {"rpc":object()},{"present_preview":None}):
            with self.subTest(opts=str(opts)):
                self.events.clear()
                with self.assertRaises(mod.CheckpointRecoveryError):
                    self.invoke(**opts)
                self.assertEqual(self.events,["clear"])

    def test_bool_and_out_of_bound_block_limits_denied(self):
        for value in (True,0,17,3.14):
            with self.subTest(value=value):
                self.events.clear()
                with self.assertRaises(mod.CheckpointRecoveryError):
                    self.invoke(max_blocks=value)
                self.assertEqual(self.events,["clear"])

    def test_cancel_before_archive_read(self):
        with self.assertRaisesRegex(mod.CheckpointRecoveryError,
                                    "^APP_RECOVERY_CANCELLED$"):
            self.invoke(cancelled=lambda:True)
        self.assertEqual(self.events, ["clear"])

    def test_broken_cancel_callback_is_redacted(self):
        with self.assertRaisesRegex(mod.CheckpointRecoveryError,
                                    "^APP_RECOVERY_CANCELLED$"):
            self.invoke(cancelled=lambda: 1/0)
        self.assertEqual(self.events, ["clear"])

    def test_account_file_failure_erases_receipt(self):
        with patch.object(mod,"load_encrypted_scan_backup",
                          side_effect=OSError("SECRET_SCAN_ACCOUNT")):
            with self.assertRaisesRegex(mod.CheckpointRecoveryError,
                                        "^APP_RECOVERY_RESTORE_DENIED$"):
                self.invoke()
        self.assertEqual(self.events,["clear","clear"])

    def test_checkpoint_failure_erasable_without_rpc(self):
        with patch.object(mod,"load_encrypted_checkpoint",
                          side_effect=OSError("SECRET_CHECKPOINT")):
            with self.assertRaises(mod.CheckpointRecoveryError):
                self.invoke()
        self.assertEqual(self.events,
                         ["clear","account_file","clear"])

    def test_bad_account_import_prevents_scanner_and_view(self):
        def broken(*_):
            raise ValueError("SECRET_KEY")
        with self.assertRaisesRegex(mod.CheckpointRecoveryError,
                                    "^APP_RECOVERY_RESTORE_DENIED$"):
            self.invoke(import_scan=broken)
        self.assertEqual(self.events[-1],"clear")
        self.assertNotIn("scanner",self.events)

    def test_checkpoint_aead_refusal_always_closes_scanner(self):
        def fail(path,accounts):
            return FakeScanner(path, self.events,fail=True)
        with self.assertRaisesRegex(mod.CheckpointRecoveryError,
                                    "^APP_RECOVERY_RESTORE_DENIED$"):
            self.invoke(scanner_factory=fail)
        self.assertEqual(self.events[-2:],["close","clear"])

    def test_missing_real_store_refuses_without_presenting(self):
        def broken(path,accounts):
            s=FakeScanner(path,self.events)
            s.store=object()
            return s
        with self.assertRaises(mod.CheckpointRecoveryError):
            self.invoke(scanner_factory=broken)
        self.assertNotIn("present",self.events)

    def test_gui_present_failure_clears_before_return(self):
        def fail(summary):
            self.events.append("failed_present")
            raise ValueError("SENSITIVE_QT_STACK")
        with self.assertRaisesRegex(mod.CheckpointRecoveryError,
                                    "^APP_RECOVERY_RENDER_DENIED$"):
            self.invoke(present_preview=fail)
        self.assertEqual(self.events[-2:],["failed_present","clear"])

    def test_failed_clear_after_presentation_is_hard_denial(self):
        attempts=[0]
        def unreliable():
            attempts[0]+=1
            if attempts[0]==2:
                raise ValueError("SECRET_GUI")
            self.events.append("clear")
        with self.assertRaisesRegex(mod.CheckpointRecoveryError,
                                    "^APP_RECOVERY_CLEAR_DENIED$"):
            self.invoke(clear_preview=unreliable,
                        present_preview=lambda _:1/0)
        self.assertEqual(attempts[0],2)

    def test_no_signing_or_mainnet_authorization_exposed(self):
        self.invoke()
        for flag in ("core_authenticated", "balance_qualified",
                     "wallet_operational", "signer_enabled",
                     "broadcast_allowed", "mainnet_allowed"):
            self.assertIs(getattr(self.receipt,flag),False)
        for name in ("Keyring","sendrawtransaction","MainWindow","sign"):
            self.assertFalse(hasattr(mod,name))

if __name__ == "__main__":
    unittest.main()
