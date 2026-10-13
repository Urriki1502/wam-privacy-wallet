"""Native descriptor/ancestor attack tests; no wallet keys or Core process."""
from functools import wraps
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import private_checkpoint_directory as m

LINUX = sys.platform == 'linux'


def native_or_deny(method):
    @wraps(method)
    def test(self):
        if not LINUX:
            with self.assertRaises(m.PrivateCheckpointDirectoryError):
                m.open_private_checkpoint_directory(self.root)
            return
        method(self)
    return test


class PrivateCheckpointDirectoryTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory(prefix='checkpoint-descriptor-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_absolute_typed_path_required_before_any_open(self):
        class UnsafePath:
            def __fspath__(self):
                raise AssertionError('MUST_NOT_INVOKE')
        with patch.object(m.os, 'open', side_effect=AssertionError('NO_IO')):
            for value in (None, str(self.root), Path('.'), UnsafePath()):
                with self.assertRaises(m.PrivateCheckpointDirectoryError):
                    m.open_private_checkpoint_directory(value)

    def test_unsupported_platform_denied_before_io(self):
        for platform in ('win32', 'darwin'):
            with patch.object(m.sys, 'platform', platform), \
                 patch.object(m.os, 'open', side_effect=AssertionError('NO_IO')):
                with self.assertRaises(m.PrivateCheckpointDirectoryError):
                    m.open_private_checkpoint_directory(self.root)

    @native_or_deny
    def test_missing_nofollow_capability_denied_before_io(self):
        with patch.object(m.os, 'open', side_effect=AssertionError('NO_IO')):
            original = m.os.O_NOFOLLOW
            try:
                del m.os.O_NOFOLLOW
                with self.assertRaises(m.PrivateCheckpointDirectoryError):
                    m.open_private_checkpoint_directory(self.root)
            finally:
                m.os.O_NOFOLLOW = original

    @native_or_deny
    def test_dotdot_denied_before_io(self):
        with patch.object(m.os, 'open', side_effect=AssertionError('NO_IO')):
            with self.assertRaises(m.PrivateCheckpointDirectoryError):
                m.open_private_checkpoint_directory(self.root / '..' / self.root.name)

    @native_or_deny
    def test_final_descriptor_is_owned_directory_and_cloexec(self):
        fd = m.open_private_checkpoint_directory(self.root)
        try:
            info = os.fstat(fd)
            self.assertTrue(stat.S_ISDIR(info.st_mode))
            self.assertEqual(info.st_ino, self.root.stat().st_ino)
            self.assertEqual(info.st_uid, os.geteuid())
            self.assertFalse(os.get_inheritable(fd))
        finally:
            os.close(fd)

    @native_or_deny
    def test_every_component_is_opened_relative_and_nofollow(self):
        opened = []
        original = m.os.open
        def observe(path, flags, **kw):
            opened.append((path, flags, kw))
            return original(path, flags, **kw)
        with patch.object(m.os, 'open', side_effect=observe):
            fd = m.open_private_checkpoint_directory(self.root)
        os.close(fd)
        self.assertEqual(opened[0][0], '/')
        self.assertEqual([p for p, _, _ in opened[1:]], list(self.root.parts[1:]))
        for _, flags, kw in opened[1:]:
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertTrue(flags & os.O_DIRECTORY)
            self.assertTrue(flags & os.O_CLOEXEC)
            self.assertIn('dir_fd', kw)

    @native_or_deny
    def test_ancestor_symlink_refused_even_when_final_directory_is_private(self):
        real = self.root / 'real'
        real.mkdir(mode=0o700)
        (real / 'private').mkdir(mode=0o700)
        alias = self.root / 'alias'
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaises(m.PrivateCheckpointDirectoryError):
            m.open_private_checkpoint_directory(alias / 'private')

    @native_or_deny
    def test_final_symlink_and_regular_file_are_refused(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        regular = self.root / 'regular'
        regular.write_bytes(b'fixture')
        for path in (alias, regular):
            with self.assertRaises(m.PrivateCheckpointDirectoryError):
                m.open_private_checkpoint_directory(path)

    @native_or_deny
    def test_final_nonprivate_modes_refused(self):
        for mode in (0o755, 0o750, 0o777):
            self.root.chmod(mode)
            with self.assertRaises(m.PrivateCheckpointDirectoryError):
                m.open_private_checkpoint_directory(self.root)

    @native_or_deny
    def test_fstat_failure_closes_all_acquired_descriptors(self):
        opened = []
        original_open, original_stat = os.open, os.fstat
        def observe(*args, **kw):
            fd = original_open(*args, **kw)
            opened.append(fd)
            return fd
        with patch.object(m.os, 'open', side_effect=observe), \
             patch.object(m.os, 'fstat', side_effect=OSError('private-detail')):
            with self.assertRaisesRegex(m.PrivateCheckpointDirectoryError,
                                       '^PRIVATE_CHECKPOINT_DIRECTORY_DENIED$'):
                m.open_private_checkpoint_directory(self.root)
        for fd in set(opened):
            with self.assertRaises(OSError):
                original_stat(fd)

    @native_or_deny
    def test_component_open_failure_closes_prior_descriptor_and_redacts(self):
        opened = []
        original_open, original_stat = os.open, os.fstat
        count = 0
        def observe(*args, **kw):
            nonlocal count
            count += 1
            if count == 3:
                raise OSError('private-detail')
            fd = original_open(*args, **kw)
            opened.append(fd)
            return fd
        with patch.object(m.os, 'open', side_effect=observe):
            with self.assertRaisesRegex(m.PrivateCheckpointDirectoryError,
                                       '^PRIVATE_CHECKPOINT_DIRECTORY_DENIED$'):
                m.open_private_checkpoint_directory(self.root)
        for fd in set(opened):
            with self.assertRaises(OSError):
                original_stat(fd)

    @native_or_deny
    def test_held_descriptor_not_redirected_by_directory_replacement(self):
        folder = self.root / 'private'
        folder.mkdir(mode=0o700)
        fd = m.open_private_checkpoint_directory(folder)
        try:
            moved = self.root / 'original'
            folder.rename(moved)
            folder.mkdir(mode=0o700)
            (folder / 'sentinel').write_bytes(b'untouched')
            file_fd = os.open('ciphertext', os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                              0o600, dir_fd=fd)
            os.close(file_fd)
            self.assertTrue((moved / 'ciphertext').exists())
            self.assertFalse((folder / 'ciphertext').exists())
            self.assertEqual((folder / 'sentinel').read_bytes(), b'untouched')
        finally:
            os.close(fd)


if __name__ == '__main__':
    unittest.main()
