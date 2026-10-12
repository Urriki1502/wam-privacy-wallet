"""Adversarial encrypted WSP scan-envelope persistence contract.

The real upstream WSP crypto import/export roundtrip is separately executed
in Linux native WSP scanner+Qt CI. These are OS filesystem attack tests.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import encrypted_scan_backup as vault


_LINUX = sys.platform == "linux"


class ScanBackupVaultTests(unittest.TestCase):
    def setUp(self):
        self.root = TemporaryDirectory(prefix="wsp-encrypted-vault-test-")
        self.addCleanup(self.root.cleanup)
        self.path = Path(self.root.name)
        self.payload = b"E" * 64

    def store(self, content=None):
        vault.provision_encrypted_scan_backup(
            self.path, self.payload if content is None else content,
        )

    def test_rejects_bad_input_before_directory_io(self):
        for bad in (None, "secret", bytearray(b"X"*64), b"", b"a"*51,
                    b"b"*1_048_577):
            with self.subTest(t=str(type(bad))), self.assertRaises(
                vault.EncryptedScanBackupError,
            ):
                self.store(bad)
        self.assertFalse((self.path / "scan-only.wsp.enc").exists())

    def test_rejects_relative_paths_even_when_directory_exists(self):
        with self.assertRaisesRegex(vault.EncryptedScanBackupError,
                                    "^SCAN_BACKUP_PLATFORM_OR_PATH_DENIED$"):
            vault.load_encrypted_scan_backup(Path("."))
        with self.assertRaises(vault.EncryptedScanBackupError):
            vault.provision_encrypted_scan_backup(Path("."), self.payload)

    def test_refuses_unsupported_platform_without_touching_disk(self):
        with patch.object(vault.sys, "platform", "win32"):
            with self.assertRaisesRegex(vault.EncryptedScanBackupError,
                                        "^SCAN_BACKUP_PLATFORM_OR_PATH_DENIED$"):
                self.store()
        self.assertFalse((self.path / "scan-only.wsp.enc").exists())

    def test_fixed_api_never_contains_keys_crypto_or_signing(self):
        self.assertFalse(hasattr(vault, "Keyring"))
        self.assertFalse(hasattr(vault, "export_scan"))
        self.assertFalse(hasattr(vault, "sign"))
        self.assertFalse(hasattr(vault, "sendrawtransaction"))

    @unittest.skipUnless(_LINUX, "native Linux filesystem contract")
    def test_create_and_load_identical_opaque_encrypted_backup(self):
        self.store()
        self.assertEqual(vault.load_encrypted_scan_backup(self.path), self.payload)
        f = self.path / "scan-only.wsp.enc"
        self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)
        self.assertEqual(f.stat().st_nlink, 1)
        self.assertEqual([p.name for p in self.path.iterdir()], [f.name])

    @unittest.skipUnless(_LINUX, "native Linux filesystem contract")
    def test_overwrite_is_never_allowed_and_original_ciphertext_survives(self):
        self.store()
        with self.assertRaisesRegex(vault.EncryptedScanBackupError,
                                    "^SCAN_BACKUP_STORE_DENIED$"):
            self.store(b"Z" * 64)
        self.assertEqual(vault.load_encrypted_scan_backup(self.path), self.payload)

    @unittest.skipUnless(_LINUX, "native Linux filesystem contract")
    def test_missing_canonical_name_fails_closed(self):
        with self.assertRaises(vault.EncryptedScanBackupError):
            vault.load_encrypted_scan_backup(self.path)

    @unittest.skipUnless(_LINUX, "native Linux filesystem contract")
    def test_world_readable_parent_is_refused_before_any_file_write(self):
        self.path.chmod(0o755)
        with self.assertRaisesRegex(vault.EncryptedScanBackupError,
                                    "^SCAN_BACKUP_PRIVATE_DIR_DENIED$"):
            self.store()
        self.assertFalse((self.path / "scan-only.wsp.enc").exists())

    @unittest.skipUnless(_LINUX, "native Linux filesystem contract")
    def test_symlinked_parent_directory_is_refused(self):
        link = self.path.with_name(self.path.name + "-link")
        link.symlink_to(self.path, target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaises(vault.EncryptedScanBackupError):
            vault.provision_encrypted_scan_backup(link, self.payload)
        self.assertFalse((self.path / "scan-only.wsp.enc").exists())

    @unittest.skipUnless(_LINUX, "native Linux filesystem contract")
    def test_canonical_symlink_is_not_followed_for_read_or_write(self):
        victim = self.path / "victim"
        victim.write_bytes(b"DO NOT CHANGE")
        target = self.path / "scan-only.wsp.enc"
        target.symlink_to(victim)
        for fn in (lambda: self.store(),
                   lambda: vault.load_encrypted_scan_backup(self.path)):
            with self.assertRaises(vault.EncryptedScanBackupError):
                fn()
        self.assertEqual(victim.read_bytes(), b"DO NOT CHANGE")

    @unittest.skipUnless(_LINUX, "native Linux filesystem contract")
    def test_hardlinked_ciphertext_denied(self):
        outside = self.path / "original"
        outside.write_bytes(self.payload)
        outside.chmod(0o600)
        os.link(outside, self.path / "scan-only.wsp.enc")
        with self.assertRaisesRegex(vault.EncryptedScanBackupError,
                                    "^SCAN_BACKUP_FILE_DENIED$"):
            vault.load_encrypted_scan_backup(self.path)

    @unittest.skipUnless(_LINUX, "native Linux filesystem contract")
    def test_permissive_ciphertext_mode_denied(self):
        self.store()
        (self.path / "scan-only.wsp.enc").chmod(0o644)
        with self.assertRaises(vault.EncryptedScanBackupError):
            vault.load_encrypted_scan_backup(self.path)

    @unittest.skipUnless(_LINUX, "native Linux filesystem contract")
    def test_short_or_truncated_ciphertext_denied(self):
        self.store()
        (self.path / "scan-only.wsp.enc").write_bytes(b"x"*30)
        with self.assertRaises(vault.EncryptedScanBackupError):
            vault.load_encrypted_scan_backup(self.path)

    @unittest.skipUnless(_LINUX, "native Linux filesystem contract")
    def test_excessive_file_size_denied_without_read(self):
        self.store()
        with (self.path / "scan-only.wsp.enc").open("r+b") as f:
            f.truncate(1_048_577)
        with self.assertRaises(vault.EncryptedScanBackupError):
            vault.load_encrypted_scan_backup(self.path)

    @unittest.skipUnless(_LINUX, "native Linux filesystem contract")
    def test_fifo_never_blocks_and_is_rejected(self):
        os.mkfifo(self.path / "scan-only.wsp.enc", 0o600)
        with self.assertRaises(vault.EncryptedScanBackupError):
            vault.load_encrypted_scan_backup(self.path)

    @unittest.skipUnless(_LINUX, "native Linux filesystem contract")
    def test_concurrent_writers_one_wins_no_overwrite(self):
        outcome = []
        barrier = threading.Barrier(2)
        def attempt(data):
            barrier.wait()
            try:
                vault.provision_encrypted_scan_backup(self.path, data)
                outcome.append("success")
            except vault.EncryptedScanBackupError:
                outcome.append("denied")
        t1 = threading.Thread(target=attempt, args=(b"A"*64,))
        t2 = threading.Thread(target=attempt, args=(b"B"*64,))
        t1.start()
        t2.start()
        t1.join(5)
        t2.join(5)
        self.assertFalse(t1.is_alive() or t2.is_alive())
        self.assertEqual(sorted(outcome), ["denied", "success"])
        self.assertIn(vault.load_encrypted_scan_backup(self.path),
                      (b"A"*64, b"B"*64))

    @unittest.skipUnless(_LINUX, "native Linux filesystem contract")
    def test_partial_write_failure_cannot_publish_canonical_file(self):
        original = vault.os.write
        calls = [0]
        def partial(fd, data):
            calls[0] += 1
            if calls[0] > 1:
                raise OSError("injected fs error contains secret")
            return original(fd, data[:1])
        with patch.object(vault.os, "write", side_effect=partial):
            with self.assertRaisesRegex(vault.EncryptedScanBackupError,
                                        "^SCAN_BACKUP_STORE_DENIED$"):
                self.store()
        self.assertFalse((self.path / "scan-only.wsp.enc").exists())
        self.assertEqual(list(self.path.iterdir()), [])

    @unittest.skipUnless(_LINUX, "native Linux filesystem contract")
    def test_no_existing_directory_is_autocreated(self):
        missing = self.path / "missing"
        with self.assertRaises(vault.EncryptedScanBackupError):
            vault.provision_encrypted_scan_backup(missing, self.payload)
        self.assertFalse(missing.exists())

    @unittest.skipUnless(_LINUX, "native Linux filesystem contract")
    def test_empty_data_and_redundant_staging_are_never_accepted(self):
        self.store()
        with self.assertRaises(vault.EncryptedScanBackupError):
            self.store(b"")
        self.assertEqual(len(list(self.path.iterdir())), 1)


if __name__ == "__main__":
    unittest.main()
