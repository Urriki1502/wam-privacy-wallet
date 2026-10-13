"""Native macOS opaque-envelope filesystem threats; no keys or Core."""
from contextlib import contextmanager
from functools import wraps
import os
from pathlib import Path
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import macos_encrypted_scan_backup as m

_NATIVE = sys.platform == "darwin"
_BODY = b"WAMSP02\x00" + b"F" * 56
_NAME = "scan-only.wsp.enc"


def native_or_deny(method):
    @wraps(method)
    def run(self):
        if not _NATIVE:
            with patch.object(m, "open_macos_private_directory", side_effect=AssertionError("NO_IO")):
                with self.assertRaisesRegex(m.MacosEncryptedScanBackupError, "CAPABILITY_DENIED$"):
                    m.load_macos_encrypted_scan_backup(self.root)
            return
        return method(self)
    return run


@contextmanager
def syscall(name, callback):
    # Preserve real capability membership while instrumenting one syscall.
    original = getattr(os, name)
    support, follow = os.supports_dir_fd, os.supports_follow_symlinks
    with patch.object(m.os, name, side_effect=callback) as mocked:
        with patch.object(m.os, "supports_dir_fd", support | ({mocked} if original in support else set())), \
             patch.object(m.os, "supports_follow_symlinks", follow | ({mocked} if original in follow else set())):
            yield mocked


class MacosEncryptedScanBackupTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="macos-envelope-",
                                       dir="/private/tmp" if _NATIVE else None)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.file = self.root / _NAME

    def store(self, payload=_BODY, directory=None):
        return m.provision_macos_encrypted_scan_backup(self.root if directory is None else directory, payload)

    def load(self, directory=None):
        return m.load_macos_encrypted_scan_backup(self.root if directory is None else directory)

    def fixture(self, content=_BODY):
        self.file.write_bytes(content)
        self.file.chmod(0o600)

    def deny_store(self):
        return self.assertRaisesRegex(m.MacosEncryptedScanBackupError, "^MACOS_SCAN_BACKUP_STORE_DENIED$")

    def deny_load(self):
        return self.assertRaisesRegex(m.MacosEncryptedScanBackupError, "^MACOS_SCAN_BACKUP_LOAD_DENIED$")

    def test_unsupported_platform_refuses_before_directory_io(self):
        for platform in ("linux", "win32", "unknown"):
            with self.subTest(platform=platform), patch.object(m.sys, "platform", platform), \
                 patch.object(m, "open_macos_private_directory", side_effect=AssertionError("NO_IO")):
                with self.assertRaisesRegex(m.MacosEncryptedScanBackupError, "CAPABILITY_DENIED$"):
                    self.store()
                with self.assertRaisesRegex(m.MacosEncryptedScanBackupError, "CAPABILITY_DENIED$"):
                    self.load()

    @native_or_deny
    def test_bad_envelope_type_magic_and_size_refused_before_io(self):
        with patch.object(m, "open_macos_private_directory", side_effect=AssertionError("NO_IO")):
            for payload in (None, "private", bytearray(_BODY), b"", b"WAMSP02\x00" + b"F" * 43,
                            b"E" * 64, b"WAMSP02\x00" + b"F" * (1_048_576 - 7)):
                with self.subTest(kind=type(payload).__name__), \
                     self.assertRaisesRegex(m.MacosEncryptedScanBackupError, "INPUT_DENIED$"):
                    self.store(payload)

    @native_or_deny
    def test_missing_full_flush_capability_refuses_before_io(self):
        original = m.fcntl.F_FULLFSYNC
        try:
            del m.fcntl.F_FULLFSYNC
            with patch.object(m, "open_macos_private_directory", side_effect=AssertionError("NO_IO")):
                with self.assertRaisesRegex(m.MacosEncryptedScanBackupError, "CAPABILITY_DENIED$"):
                    self.store()
        finally:
            m.fcntl.F_FULLFSYNC = original

    @native_or_deny
    def test_missing_link_or_nofollow_capability_refuses_before_io(self):
        for field in ("supports_dir_fd", "supports_follow_symlinks"):
            with patch.object(m.os, field, set()), \
                 patch.object(m, "open_macos_private_directory", side_effect=AssertionError("NO_IO")):
                with self.assertRaisesRegex(m.MacosEncryptedScanBackupError, "CAPABILITY_DENIED$"):
                    self.store()

    @native_or_deny
    def test_native_roundtrip_returns_exact_ciphertext_private_single_link(self):
        self.store()
        self.assertEqual(self.load(), _BODY)
        info = self.file.stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual(info.st_uid, os.geteuid())
        self.assertEqual([p.name for p in self.root.iterdir()], [_NAME])

    @native_or_deny
    def test_native_minimum_and_maximum_envelope_sizes(self):
        for size in (52, 1_048_576):
            directory = self.root / str(size)
            directory.mkdir(mode=0o700)
            payload = b"WAMSP02\x00" + b"P" * (size - 8)
            self.store(payload, directory)
            self.assertEqual(self.load(directory), payload)

    @native_or_deny
    def test_create_once_never_overwrites_original_ciphertext(self):
        self.store()
        with self.deny_store():
            self.store(b"WAMSP02\x00" + b"R" * 56)
        self.assertEqual(self.load(), _BODY)
        self.assertEqual([p.name for p in self.root.iterdir()], [_NAME])

    @native_or_deny
    def test_two_concurrent_publishers_only_one_succeeds(self):
        barrier = threading.Barrier(2)
        result = []
        def run():
            barrier.wait(timeout=5)
            try:
                self.store()
                result.append("written")
            except m.MacosEncryptedScanBackupError:
                result.append("denied")
        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sorted(result), ["denied", "written"])
        self.assertEqual(self.load(), _BODY)

    @native_or_deny
    def test_directory_access_acl_refused_without_file_publication(self):
        subprocess.run(["/bin/chmod", "+a", "everyone allow list,search", str(self.root)],
                       check=True, capture_output=True, timeout=5)
        self.addCleanup(subprocess.run, ["/bin/chmod", "-N", str(self.root)],
                        check=True, capture_output=True, timeout=5)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        with self.deny_store():
            self.store()
        self.assertFalse(self.file.exists())

    @native_or_deny
    def test_file_access_acl_refused_even_with_mode_0600(self):
        self.store()
        subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(self.file)],
                       check=True, capture_output=True, timeout=5)
        self.addCleanup(subprocess.run, ["/bin/chmod", "-N", str(self.file)],
                        check=True, capture_output=True, timeout=5)
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o600)
        with self.deny_load():
            self.load()

    @native_or_deny
    def test_ancestor_and_final_directory_symlinks_refused(self):
        actual = self.root / "actual"
        actual.mkdir(mode=0o700)
        (actual / "private").mkdir(mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(actual, target_is_directory=True)
        for directory in (alias, alias / "private"):
            with self.deny_store():
                self.store(directory=directory)
        self.assertEqual(list((actual / "private").iterdir()), [])

    @native_or_deny
    def test_canonical_file_symlink_refused_without_target_change(self):
        target = self.root / "outside"
        target.write_bytes(_BODY)
        target.chmod(0o600)
        self.file.symlink_to(target)
        with self.deny_store():
            self.store()
        with self.deny_load():
            self.load()
        self.assertEqual(target.read_bytes(), _BODY)

    @native_or_deny
    def test_hardlinked_canonical_file_refused(self):
        self.store()
        os.link(self.file, self.root / "second-link")
        with self.deny_load():
            self.load()

    @native_or_deny
    def test_fifo_refused_without_blocking(self):
        os.mkfifo(self.file, mode=0o600)
        with self.deny_load():
            self.load()

    @native_or_deny
    def test_nonprivate_file_mode_refused(self):
        self.store()
        for mode in (0o644, 0o640, 0o700, 0o1600):
            self.file.chmod(mode)
            with self.deny_load():
                self.load()

    @native_or_deny
    def test_wrong_file_owner_refused_without_chown(self):
        self.store()
        real = os.fstat
        def foreign(fd):
            value = real(fd)
            if stat.S_ISREG(value.st_mode):
                return SimpleNamespace(**{name: (value.st_uid + 1 if name == "st_uid" else getattr(value, name))
                                          for name in ("st_mode", "st_uid", "st_nlink")})
            return value
        with patch.object(m.os, "fstat", side_effect=foreign), self.deny_load():
            self.load()

    @native_or_deny
    def test_oversize_truncated_or_wrong_magic_files_refused(self):
        for payload in (b"", b"WAMSP02\x00" + b"X" * 43, b"X" * 64,
                        b"WAMSP02\x00" + b"X" * 1_048_576):
            self.fixture(payload)
            with self.deny_load():
                self.load()

    @native_or_deny
    def test_early_eof_during_bounded_read_refused(self):
        self.store()
        with patch.object(m.os, "read", return_value=b""), self.deny_load():
            self.load()

    @native_or_deny
    def test_same_size_mutation_during_read_refused(self):
        self.store()
        real = os.read
        def mutate(fd, count):
            part = real(fd, count)
            self.file.write_bytes(b"WAMSP02\x00" + b"M" * 56)
            return part
        with patch.object(m.os, "read", side_effect=mutate), self.deny_load():
            self.load()

    @native_or_deny
    def test_canonical_replacement_during_read_refused(self):
        self.store()
        real = os.read
        def replace(fd, count):
            part = real(fd, count)
            self.file.rename(self.root / "original")
            self.fixture(b"WAMSP02\x00" + b"R" * 56)
            return part
        with patch.object(m.os, "read", side_effect=replace), self.deny_load():
            self.load()

    @native_or_deny
    def test_partial_writes_complete_exact_envelope_before_flush(self):
        real = os.write
        with patch.object(m.os, "write", side_effect=lambda fd, data: real(fd, data[:5])):
            self.store()
        self.assertEqual(self.load(), _BODY)

    @native_or_deny
    def test_zero_or_invalid_write_count_refuses_without_publication(self):
        for count in (0, -1, 65):
            with patch.object(m.os, "write", return_value=count), self.deny_store():
                self.store()
            self.assertEqual(list(self.root.iterdir()), [])

    @native_or_deny
    def test_native_full_flush_precedes_link_and_directory_fsync(self):
        events = []
        flush, link, sync = m._full_flush, os.link, os.fsync
        def full(fd):
            self.assertEqual(os.fstat(fd).st_size, len(_BODY))
            flush(fd)
            events.append("full-flush")
        def publish(*args, **kwargs):
            events.append("publish")
            return link(*args, **kwargs)
        def directory_sync(fd):
            self.assertTrue(stat.S_ISDIR(os.fstat(fd).st_mode))
            events.append("directory-fsync")
            return sync(fd)
        with patch.object(m, "_full_flush", side_effect=full), syscall("link", publish), \
             patch.object(m.os, "fsync", side_effect=directory_sync):
            self.store()
        self.assertEqual(events, ["full-flush", "publish", "directory-fsync"])

    @native_or_deny
    def test_full_flush_failure_refuses_before_publication_and_redacts(self):
        with patch.object(m.fcntl, "fcntl", side_effect=OSError("private-flush-detail")), self.deny_store():
            self.store()
        self.assertEqual(list(self.root.iterdir()), [])

    @native_or_deny
    def test_directory_fsync_failure_denies_but_preserves_published_file(self):
        with patch.object(m.os, "fsync", side_effect=OSError("private-fsync-detail")), self.deny_store():
            self.store()
        self.assertTrue(self.file.exists())
        self.assertEqual(self.load(), _BODY)
        with self.deny_store():
            self.store()

    @native_or_deny
    def test_stage_cleanup_failure_denies_and_reader_rejects_extra_link(self):
        real = os.unlink
        def refuse(name, **kwargs):
            if name.startswith(".macos-scan-stage-"):
                raise OSError("private-unlink-detail")
            return real(name, **kwargs)
        with syscall("unlink", refuse), self.deny_store():
            self.store()
        self.assertEqual(self.file.stat().st_nlink, 2)
        with self.deny_load():
            self.load()

    @native_or_deny
    def test_stage_replacement_before_link_detected_without_deleting_replacement(self):
        real = os.link
        replacement = b"WAMSP02\x00" + b"R" * 56
        def replace(source, target, **kwargs):
            stage = self.root / source
            stage.unlink()
            stage.write_bytes(replacement)
            stage.chmod(0o600)
            return real(source, target, **kwargs)
        with syscall("link", replace), self.deny_store():
            self.store()
        staged = [p for p in self.root.iterdir() if p.name.startswith(".macos-scan-stage-")]
        self.assertEqual(len(staged), 1)
        self.assertEqual(staged[0].read_bytes(), replacement)
        with self.deny_load():
            self.load()

    @native_or_deny
    def test_stage_replacement_before_unlink_never_deletes_foreign_inode(self):
        real = m._remove_owned_stage
        replaced = False
        def replace(directory, name, fd):
            nonlocal replaced
            if not replaced:
                replaced = True
                stage = self.root / name
                stage.rename(self.root / "moved-stage")
                stage.write_bytes(b"untouched")
            return real(directory, name, fd)
        with patch.object(m, "_remove_owned_stage", side_effect=replace), self.deny_store():
            self.store()
        staged = [p for p in self.root.iterdir() if p.name.startswith(".macos-scan-stage-")]
        self.assertEqual([p.read_bytes() for p in staged], [b"untouched"])

    @native_or_deny
    def test_directory_replacement_remains_bound_to_original_descriptor(self):
        directory = self.root / "private"
        directory.mkdir(mode=0o700)
        moved = self.root / "moved"
        validate = m.validate_macos_private_directory
        replaced = False
        def replace(fd):
            nonlocal replaced
            validate(fd)
            if not replaced:
                replaced = True
                directory.rename(moved)
                directory.mkdir(mode=0o700)
                (directory / "sentinel").write_bytes(b"untouched")
        with patch.object(m, "validate_macos_private_directory", side_effect=replace):
            self.store(directory=directory)
        self.assertEqual(self.load(moved), _BODY)
        self.assertFalse((directory / _NAME).exists())
        self.assertEqual((directory / "sentinel").read_bytes(), b"untouched")

    @native_or_deny
    def test_post_fsync_canonical_replacement_denies_success(self):
        real = os.fsync
        def replace(fd):
            real(fd)
            self.file.rename(self.root / "original")
            self.fixture(b"WAMSP02\x00" + b"R" * 56)
        with patch.object(m.os, "fsync", side_effect=replace), self.deny_store():
            self.store()
        self.assertEqual((self.root / "original").read_bytes(), _BODY)

    @native_or_deny
    def test_close_failure_invalidates_success_without_unlinking_canonical(self):
        real = os.close
        def refuse(fd):
            regular = stat.S_ISREG(os.fstat(fd).st_mode)
            real(fd)
            if regular:
                raise OSError("private-close-detail")
        with patch.object(m.os, "close", side_effect=refuse), self.deny_store():
            self.store()
        self.assertEqual(self.load(), _BODY)
        with patch.object(m.os, "close", side_effect=refuse), self.deny_load():
            self.load()

    @native_or_deny
    def test_relative_directory_and_nonprivate_directory_denied(self):
        with self.deny_store():
            self.store(directory=Path("."))
        self.root.chmod(0o755)
        with self.deny_store():
            self.store()
        self.assertFalse(self.file.exists())

    @native_or_deny
    def test_inherited_stage_acl_or_mode_change_denies_before_publish(self):
        real = m._full_flush
        def change(fd):
            real(fd)
            os.fchmod(fd, 0o644)
        with patch.object(m, "_full_flush", side_effect=change), self.deny_store():
            self.store()
        self.assertFalse(self.file.exists())
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
