"""Negative snapshot-chain / crash preflight qualification; no real funds."""
from __future__ import annotations

from pathlib import Path
from functools import wraps
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import versioned_checkpoint_journal as journal
from wam_privacy_wallet.application import snapshot_lineage_preflight as mod

_LINUX = __import__("sys").platform == "linux"
_SCOPE = "a" * 64
_TIP = "b" * 64
_BLOB = b"WAMSP02\x00" + b"Z" * 56


def linux_storage_or_deny(fn):
    @wraps(fn)
    def checked(self):
        if not _LINUX:
            # Mandatory non-Linux checks fail closed rather than skip coverage.
            with self.assertRaisesRegex(mod.SnapshotLineageError,
                                        "^LINEAGE_CRASH_OR_FILE_DENIED$"):
                self.run_preview(1)
            return
        return fn(self)
    return checked


class SnapshotLineagePreflightTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory(prefix="test-wsp-lineage-preflight-")
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name)

    def version(self, generation, predecessor, scope=_SCOPE):
        return journal.write_unanchored_regtest_generation(
            self.path, generation, _BLOB, scope_digest=scope,
            tip_height=generation, tip_hash=_TIP,
            predecessor_digest=predecessor,
        )

    def chain(self, generations=2):
        if not _LINUX:
            return None
        previous = "0" * 64
        for i in range(1, generations+1):
            previous = self.version(i, previous)
        return previous

    def run_preview(self, generation=2):
        return mod.inspect_untrusted_generation_lineage(
            self.path, generation, allow_unanchored_synthetic=True,
        )

    def test_default_denies_before_any_snapshot_read(self):
        with patch.object(mod, "read_unanchored_regtest_generation",
                          side_effect=AssertionError("must not read")):
            with self.assertRaisesRegex(mod.SnapshotLineageError,
                                        "^LINEAGE_INDEPENDENT_ANCHOR_REQUIRED$"):
                mod.inspect_untrusted_generation_lineage(self.path, 2)

    def test_forged_bool_or_large_generation_denied(self):
        for n in (0, True, -1, 33, 1.5):
            with self.subTest(n=n), self.assertRaisesRegex(
                mod.SnapshotLineageError, "^LINEAGE_EXPECTED_GENERATION_DENIED$"
            ):
                mod.inspect_untrusted_generation_lineage(
                    self.path, n, allow_unanchored_synthetic=True,
                )

    def test_false_like_consent_not_accepted(self):
        for x in (1, "true", False, None):
            with self.subTest(value=str(x)), self.assertRaisesRegex(
                mod.SnapshotLineageError,
                "^LINEAGE_INDEPENDENT_ANCHOR_REQUIRED$",
            ):
                mod.inspect_untrusted_generation_lineage(
                    self.path, 1, allow_unanchored_synthetic=x,
                )

    def test_no_callable_or_local_hash_claim_can_be_trusted_anchor(self):
        r = mod.SyntheticLineageReceipt(1,"a"*64,"b"*64)
        for fake in (object(), "a"*64, lambda:True, {"generation":1}, None):
            with self.subTest(fake=type(fake).__name__), self.assertRaisesRegex(
                mod.SnapshotLineageError,
                "^LINEAGE_INDEPENDENT_ANCHOR_REQUIRED$",
            ):
                mod.evaluate_trusted_rollback_status(
                    r, independent_anchor_proof=fake,
                )

    def test_invalid_receipt_also_denied(self):
        with self.assertRaisesRegex(mod.SnapshotLineageError,
                                    "^LINEAGE_RECEIPT_DENIED$"):
            mod.evaluate_trusted_rollback_status(object())

    def test_no_spending_or_source_loader_api(self):
        for key in ("sign", "Keyring", "wallet_balance", "sendrawtransaction"):
            self.assertFalse(hasattr(mod,key))

    def test_missing_disk_chain_is_refused_not_fallback(self):
        with self.assertRaises(mod.SnapshotLineageError):
            self.run_preview(1)

    @linux_storage_or_deny
    def test_genuine_two_generation_chain_yields_non_authorizing_receipt(self):
        expected = self.chain()
        r=self.run_preview()
        self.assertEqual(r.manifest_digest,expected)
        self.assertEqual(r.scope_digest,_SCOPE)
        self.assertEqual(r.protection,"UNANCHORED_SYNTHETIC_REGTEST_ONLY")
        for flag in ("trusted_anchor_verified", "wallet_operational",
                     "signer_enabled","broadcast_allowed","mainnet_allowed"):
            self.assertIs(getattr(r,flag),False)

    @linux_storage_or_deny
    def test_missing_second_generation_not_auto_downgraded(self):
        self.chain(1)
        with self.assertRaisesRegex(mod.SnapshotLineageError,
                                    "^LINEAGE_CRASH_OR_FILE_DENIED$"):
            self.run_preview()

    @linux_storage_or_deny
    def test_version_ready_marker_missing_denies(self):
        self.chain()
        (self.path/"versions"/"0000000000000002"/"ready.sha256").unlink()
        with self.assertRaises(mod.SnapshotLineageError):
            self.run_preview()

    @linux_storage_or_deny
    def test_wrong_predecessor_even_if_manifest_self_hash_consistent(self):
        self.chain(1)
        self.version(2,"c"*64)
        with self.assertRaisesRegex(mod.SnapshotLineageError,
                                    "^LINEAGE_PREDECESSOR_DENIED$"):
            self.run_preview()

    @linux_storage_or_deny
    def test_wrong_account_scope_denies_without_exposing_scope(self):
        self.chain(1)
        old=journal.read_unanchored_regtest_generation(
            self.path,1,allow_unanchored_synthetic=True)[0]
        from hashlib import sha256
        import json
        digest=sha256(json.dumps(old,sort_keys=True,
            separators=(",",":"),ensure_ascii=True).encode("ascii")).hexdigest()
        self.version(2,digest,scope="e"*64)
        with self.assertRaisesRegex(mod.SnapshotLineageError,
                                    "^LINEAGE_ACCOUNT_SCOPE_DENIED$") as e:
            self.run_preview()
        self.assertNotIn("eeee",str(e.exception))

    @linux_storage_or_deny
    def test_corrupted_old_generation_blocks_newer_even_if_new_valid(self):
        self.chain()
        p=self.path/"versions"/"0000000000000001"/"manifest.json"
        p.write_bytes(p.read_bytes()+b"x")
        with self.assertRaises(mod.SnapshotLineageError):
            self.run_preview()

    @linux_storage_or_deny
    def test_deliberate_full_directory_rollback_cannot_claim_security(self):
        self.chain(2)
        # Locally valid previous state can be replayed with its files.
        # The check stays unusable for operational anti-rollback.
        synthetic=self.run_preview(1)
        with self.assertRaisesRegex(mod.SnapshotLineageError,
                                    "^LINEAGE_INDEPENDENT_ANCHOR_REQUIRED$"):
            mod.evaluate_trusted_rollback_status(synthetic)
