"""Filesystem threat tests for the immutable encrypted checkpoint archive.

No test contains real wallet credentials, keys, chain funds or live Core.
The native pinned WSP CI separately exports and restores *real* AES-GCM state.
"""
from __future__ import annotations

from functools import wraps
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import encrypted_checkpoint_archive as m

_LINUX = sys.platform == "linux"
_CONTENT = b"WAMSP02\x00" + b"R" * 56
_NAME = "wsp-checkpoint-v1.enc"
_DEFAULT = object()


def require_linux_or_deny(f):
    @wraps(f)
    def wrapped(self):
        if not _LINUX:
            with self.assertRaisesRegex(m.EncryptedCheckpointArchiveError,
                                        "^CHECKPOINT_PLATFORM_OR_PATH_DENIED$"):
                m.load_encrypted_checkpoint(self.folder)
            return
        f(self)
    return wrapped


class CheckpointArchiveTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory(prefix="wsp-encrypted-checkpoint-test-")
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)

    def save(self, content=_DEFAULT):
        m.store_encrypted_checkpoint(
            self.folder, _CONTENT if content is _DEFAULT else content
        )

    def test_wrong_format_and_invalid_sizes_denied(self):
        for data in ("secret", bytearray(_CONTENT), b"", b"E" * 80,
                     b"WAMSP02\x00", b"WAMSP02\x00" + b"A" * (33 * 1024 * 1024)):
            with self.subTest(kind=str(type(data))):
                with self.assertRaises(m.EncryptedCheckpointArchiveError):
                    self.save(data)
        self.assertFalse((self.folder / _NAME).exists())

    def test_requires_absolute_path(self):
        with self.assertRaises(m.EncryptedCheckpointArchiveError):
            m.store_encrypted_checkpoint(Path("."), _CONTENT)

    def test_mac_windows_fail_closed(self):
        for platform in ("darwin", "win32"):
            with patch.object(m.sys, "platform", platform):
                with self.assertRaisesRegex(m.EncryptedCheckpointArchiveError,
                                            "^CHECKPOINT_PLATFORM_OR_PATH_DENIED$"):
                    self.save()

    def test_no_signer_or_own_crypto(self):
        for name in ("Keyring", "import_scan", "AESGCM", "sign", "sendrawtransaction"):
            self.assertFalse(hasattr(m, name))

    @require_linux_or_deny
    def test_create_read_exact_ciphertext_and_modes(self):
        self.save()
        self.assertEqual(m.load_encrypted_checkpoint(self.folder), _CONTENT)
        p = self.folder / _NAME
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertEqual(p.stat().st_nlink, 1)

    @require_linux_or_deny
    def test_create_once_never_overwrites_encrypted_checkpoint(self):
        self.save()
        with self.assertRaisesRegex(m.EncryptedCheckpointArchiveError,
                                    "^CHECKPOINT_STORE_DENIED$"):
            self.save(b"WAMSP02\x00" + b"X"*56)
        self.assertEqual(m.load_encrypted_checkpoint(self.folder), _CONTENT)

    @require_linux_or_deny
    def test_missing_file_denied(self):
        with self.assertRaises(m.EncryptedCheckpointArchiveError):
            m.load_encrypted_checkpoint(self.folder)

    @require_linux_or_deny
    def test_parent_world_readable_denied(self):
        self.folder.chmod(0o755)
        with self.assertRaises(m.EncryptedCheckpointArchiveError):
            self.save()
        self.assertFalse((self.folder / _NAME).exists())

    @require_linux_or_deny
    def test_parent_symlink_denied(self):
        link = self.folder.with_name(self.folder.name+"-symlink")
        link.symlink_to(self.folder, target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaises(m.EncryptedCheckpointArchiveError):
            m.store_encrypted_checkpoint(link, _CONTENT)

    @require_linux_or_deny
    def test_canonical_file_symlink_denied_without_write(self):
        victim = self.folder / "untouched"
        victim.write_bytes(b"DO NOT TOUCH")
        (self.folder / _NAME).symlink_to(victim)
        with self.assertRaises(m.EncryptedCheckpointArchiveError):
            self.save()
        with self.assertRaises(m.EncryptedCheckpointArchiveError):
            m.load_encrypted_checkpoint(self.folder)
        self.assertEqual(victim.read_bytes(), b"DO NOT TOUCH")

    @require_linux_or_deny
    def test_hardlink_denied_on_load(self):
        original = self.folder / "original"
        original.write_bytes(_CONTENT)
        original.chmod(0o600)
        os.link(original, self.folder / _NAME)
        with self.assertRaisesRegex(m.EncryptedCheckpointArchiveError,
                                    "^CHECKPOINT_FILE_DENIED$"):
            m.load_encrypted_checkpoint(self.folder)

    @require_linux_or_deny
    def test_permissive_archive_file_denied(self):
        self.save()
        (self.folder / _NAME).chmod(0o644)
        with self.assertRaises(m.EncryptedCheckpointArchiveError):
            m.load_encrypted_checkpoint(self.folder)

    @require_linux_or_deny
    def test_truncated_archive_denied(self):
        self.save()
        (self.folder / _NAME).write_bytes(b"WAMSP02\x00" + b"short")
        with self.assertRaises(m.EncryptedCheckpointArchiveError):
            m.load_encrypted_checkpoint(self.folder)

    @require_linux_or_deny
    def test_fifo_denied_without_blocking(self):
        os.mkfifo(self.folder / _NAME, mode=0o600)
        with self.assertRaises(m.EncryptedCheckpointArchiveError):
            m.load_encrypted_checkpoint(self.folder)

    @require_linux_or_deny
    def test_parallel_publishers_only_one_succeeds(self):
        barrier = threading.Barrier(2)
        results = []
        def publish(content):
            barrier.wait()
            try:
                self.save(content)
                results.append("ok")
            except m.EncryptedCheckpointArchiveError:
                results.append("denied")
        a = threading.Thread(target=publish, args=(_CONTENT,))
        b = threading.Thread(target=publish,
                             args=(b"WAMSP02\x00"+b"X"*56,))
        a.start()
        b.start()
        a.join(5)
        b.join(5)
        self.assertFalse(a.is_alive() or b.is_alive())
        self.assertEqual(sorted(results), ["denied", "ok"])
        self.assertIn(m.load_encrypted_checkpoint(self.folder),
                      (_CONTENT, b"WAMSP02\x00"+b"X"*56))

    @require_linux_or_deny
    def test_short_write_cannot_publish_canonical_name(self):
        actual = m.os.write
        calls = [0]
        def fail(fd, data):
            calls[0] += 1
            if calls[0] > 1:
                raise OSError("private secret must not leak")
            return actual(fd, data[:1])
        with patch.object(m.os, "write", side_effect=fail):
            with self.assertRaisesRegex(m.EncryptedCheckpointArchiveError,
                                        "^CHECKPOINT_STORE_DENIED$"):
                self.save()
        self.assertFalse((self.folder / _NAME).exists())
        self.assertEqual(list(self.folder.iterdir()), [])

    @require_linux_or_deny
    def test_missing_directory_never_autocreated(self):
        bad = self.folder / "missing"
        with self.assertRaises(m.EncryptedCheckpointArchiveError):
            m.store_encrypted_checkpoint(bad, _CONTENT)
        self.assertFalse(bad.exists())


    @require_linux_or_deny
    def test_cleanup_unlink_failure_after_publish_denies_success(self):
        original = m.os.unlink
        def bad_unlink(name, *args, **kwargs):
            if isinstance(name, str) and name.startswith(".wsp-checkpoint-stage-"):
                raise OSError("SENSITIVE_STAGING_UNLINK_FAILURE")
            return original(name, *args, **kwargs)
        with patch.object(m.os, "unlink", side_effect=bad_unlink):
            with self.assertRaisesRegex(m.EncryptedCheckpointArchiveError, "^CHECKPOINT_STORE_DENIED$") as caught:
                self.save()
        self.assertNotIn("SENSITIVE", str(caught.exception))
        self.assertEqual((self.folder / "wsp-checkpoint-v1.enc").stat().st_nlink, 2)
        with self.assertRaisesRegex(m.EncryptedCheckpointArchiveError, "^CHECKPOINT_FILE_DENIED$"):
            m.load_encrypted_checkpoint(self.folder)

    @require_linux_or_deny
    def test_directory_fsync_failure_after_unlink_denies_success(self):
        original = m.os.fsync
        def bad_sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("SENSITIVE_DURABILITY_FAILURE")
            return original(fd)
        with patch.object(m.os, "fsync", side_effect=bad_sync):
            with self.assertRaisesRegex(m.EncryptedCheckpointArchiveError, "^CHECKPOINT_STORE_DENIED$") as caught:
                self.save()
        self.assertNotIn("SENSITIVE", str(caught.exception))
        self.assertEqual([p.name for p in self.folder.iterdir()],
                         ["wsp-checkpoint-v1.enc"])

    @require_linux_or_deny
    def test_preexisting_canonical_survives_failed_staging_cleanup(self):
        self.save()
        previous = m.load_encrypted_checkpoint(self.folder)
        original = m.os.unlink
        def bad_unlink(name, *args, **kwargs):
            if isinstance(name, str) and name.startswith(".wsp-checkpoint-stage-"):
                raise OSError("STAGING_CLEANUP_FAILED")
            return original(name, *args, **kwargs)
        with patch.object(m.os, "unlink", side_effect=bad_unlink):
            with self.assertRaisesRegex(m.EncryptedCheckpointArchiveError, "^CHECKPOINT_STORE_DENIED$"):
                self.save(b"WAMSP02\x00" + b"Z" * 56)
        self.assertEqual(m.load_encrypted_checkpoint(self.folder), previous)

    @require_linux_or_deny
    def test_directory_fsync_runs_after_staging_unlink(self):
        events = []
        real_unlink = m.os.unlink
        real_fsync = m.os.fsync
        def trace_unlink(name, *args, **kwargs):
            if isinstance(name, str) and name.startswith(".wsp-checkpoint-stage-"):
                events.append("unlink")
            return real_unlink(name, *args, **kwargs)
        def trace_fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                events.append("sync")
            return real_fsync(fd)
        with patch.object(m.os, "unlink", side_effect=trace_unlink):
            with patch.object(m.os, "fsync", side_effect=trace_fsync):
                self.save()
        self.assertEqual(events, ["unlink", "sync"])


if __name__ == "__main__":
    unittest.main()
