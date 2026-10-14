"""Native macOS custody and ACL adversaries; no wallet secrets or Core."""
from functools import wraps
import ctypes
import errno
import os
from pathlib import Path
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from wam_privacy_wallet.application import macos_private_directory as m

_NATIVE = sys.platform == "darwin"


def native_or_deny(method):
    @wraps(method)
    def run(self):
        if not _NATIVE:
            with patch.object(m, "_load_acl_api", side_effect=AssertionError("NO_NATIVE_LOAD")), \
                 patch.object(m.os, "open", side_effect=AssertionError("NO_IO")):
                with self.assertRaisesRegex(m.MacosPrivateDirectoryError,
                                           "^MACOS_PRIVATE_DIRECTORY_CAPABILITY_DENIED$"):
                    m.open_macos_private_directory(self.root)
            return
        return method(self)
    return run


class MacosPrivateDirectoryTests(unittest.TestCase):
    def setUp(self):
        # Do not silently resolve symlinks inside the implementation. Darwin's
        # explicit /private/tmp is used because /tmp itself is a system symlink.
        temporary = TemporaryDirectory(prefix="macos-directory-custody-",
                                       dir="/private/tmp" if _NATIVE else None)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def opened(self):
        fd = m.open_macos_private_directory(self.root)
        self.addCleanup(os.close, fd)
        return fd

    def assert_closed(self, descriptors):
        for fd in set(descriptors):
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_wrong_platform_denied_before_disk_or_library_load(self):
        for platform in ("linux", "win32", "unknown"):
            with self.subTest(platform=platform), patch.object(m.sys, "platform", platform), \
                 patch.object(m.os, "open", side_effect=AssertionError("NO_IO")), \
                 patch.object(m, "_load_acl_api", side_effect=AssertionError("NO_LOAD")):
                with self.assertRaisesRegex(m.MacosPrivateDirectoryError,
                                           "^MACOS_PRIVATE_DIRECTORY_CAPABILITY_DENIED$"):
                    m.open_macos_private_directory(self.root)

    @native_or_deny
    def test_absolute_exact_type_and_root_shape_required_before_open(self):
        class UnsafePath:
            def __fspath__(self):
                raise AssertionError("DO_NOT_INVOKE")
        with patch.object(m, "_open_component", side_effect=AssertionError("NO_IO")):
            for path in (None, str(self.root), Path("."), Path("/"),
                         Path("//private/tmp"), UnsafePath()):
                with self.subTest(kind=type(path).__name__), self.assertRaises(m.MacosPrivateDirectoryError):
                    m.open_macos_private_directory(path)

    @native_or_deny
    def test_dotdot_and_excess_components_denied_before_open(self):
        with patch.object(m, "_open_component", side_effect=AssertionError("NO_IO")):
            for path in (self.root / ".." / self.root.name,
                         Path("/" + "/".join("component" for _ in range(256)))):
                with self.assertRaisesRegex(m.MacosPrivateDirectoryError,
                                           "^MACOS_PRIVATE_DIRECTORY_PATH_DENIED$"):
                    m.open_macos_private_directory(path)

    @native_or_deny
    def test_missing_nofollow_or_cloexec_capability_denied_before_io(self):
        for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC"):
            with self.subTest(name=name), patch.object(m, "_open_component", side_effect=AssertionError("NO_IO")):
                original = getattr(m.os, name)
                try:
                    delattr(m.os, name)
                    with self.assertRaisesRegex(m.MacosPrivateDirectoryError, "CAPABILITY_DENIED$"):
                        m.open_macos_private_directory(self.root)
                finally:
                    setattr(m.os, name, original)

    @native_or_deny
    def test_missing_dir_fd_support_denied_before_io(self):
        for support in (set(), None):
            with self.subTest(support=support), patch.object(m.os, "supports_dir_fd", support), \
                 patch.object(m, "_open_component", side_effect=AssertionError("NO_IO")):
                with self.assertRaisesRegex(m.MacosPrivateDirectoryError, "CAPABILITY_DENIED$"):
                    m.open_macos_private_directory(self.root)

    @native_or_deny
    def test_missing_native_metadata_function_denied_before_io(self):
        with patch.object(m.os, "geteuid", None), \
             patch.object(m, "_open_component", side_effect=AssertionError("NO_IO")):
            with self.assertRaisesRegex(m.MacosPrivateDirectoryError, "CAPABILITY_DENIED$"):
                m.open_macos_private_directory(self.root)

    @native_or_deny
    def test_native_owned_private_descriptor_is_not_inheritable(self):
        fd = self.opened()
        info = os.fstat(fd)
        self.assertTrue(stat.S_ISDIR(info.st_mode))
        self.assertEqual((info.st_dev, info.st_ino),
                         (self.root.stat().st_dev, self.root.stat().st_ino))
        self.assertEqual(info.st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
        self.assertFalse(os.get_inheritable(fd))

    @native_or_deny
    def test_all_components_use_held_parent_and_nofollow_flags(self):
        observed = []
        original = os.open
        def observe(name, flags, **options):
            fd = original(name, flags, **options)
            observed.append((name, flags, options["dir_fd"], fd))
            return fd
        support = os.supports_dir_fd
        with patch.object(m.os, "open", side_effect=observe) as mocked_open, \
             patch.object(m.os, "supports_dir_fd", support | {mocked_open}):
            fd = self.opened()
        self.assertEqual([entry[0] for entry in observed], list(self.root.parts))
        self.assertIsNone(observed[0][2])
        for _, flags, _, _ in observed:
            for required in (os.O_DIRECTORY, os.O_NOFOLLOW, os.O_CLOEXEC):
                self.assertTrue(flags & required)
        for previous, current in zip(observed, observed[1:]):
            self.assertEqual(previous[3], current[2])
        self.assert_closed([entry[3] for entry in observed[:-1]])
        self.assertEqual(os.fstat(fd).st_ino, self.root.stat().st_ino)

    @native_or_deny
    def test_ancestor_symlink_refused_even_with_private_final_directory(self):
        actual = self.root / "actual"
        actual.mkdir(mode=0o700)
        (actual / "private").mkdir(mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(m.MacosPrivateDirectoryError):
            m.open_macos_private_directory(alias / "private")

    @native_or_deny
    def test_final_symlink_regular_file_and_fifo_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        regular = self.root / "regular"
        regular.write_bytes(b"public-fixture")
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (alias, regular, fifo):
            with self.subTest(name=path.name), self.assertRaises(m.MacosPrivateDirectoryError):
                m.open_macos_private_directory(path)

    @native_or_deny
    def test_nonprivate_and_special_mode_bits_are_refused(self):
        for mode in (0o755, 0o750, 0o777, 0o1700):
            self.root.chmod(mode)
            with self.subTest(mode=mode), self.assertRaisesRegex(m.MacosPrivateDirectoryError, "METADATA_DENIED$"):
                m.open_macos_private_directory(self.root)

    @native_or_deny
    def test_wrong_owner_is_refused_without_changing_owner(self):
        with patch.object(m.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(m.MacosPrivateDirectoryError, "METADATA_DENIED$"):
                m.open_macos_private_directory(self.root)

    @native_or_deny
    def test_inheritable_descriptor_is_refused(self):
        with patch.object(m.os, "get_inheritable", return_value=True):
            with self.assertRaisesRegex(m.MacosPrivateDirectoryError, "METADATA_DENIED$"):
                m.open_macos_private_directory(self.root)

    @native_or_deny
    def test_fstat_error_closes_all_acquired_descriptors_and_redacts(self):
        opened = []
        original = m._open_component
        def observe(*args):
            fd = original(*args)
            opened.append(fd)
            return fd
        with patch.object(m, "_open_component", side_effect=observe), \
             patch.object(m.os, "fstat", side_effect=OSError("private-detail")):
            with self.assertRaisesRegex(m.MacosPrivateDirectoryError,
                                       "^MACOS_PRIVATE_DIRECTORY_INSPECTION_DENIED$"):
                m.open_macos_private_directory(self.root)
        self.assert_closed(opened)

    @native_or_deny
    def test_component_open_error_closes_prior_descriptors_and_redacts(self):
        opened = []
        original = m._open_component
        def observe(*args):
            if len(opened) == 2:
                raise OSError("private-detail")
            fd = original(*args)
            opened.append(fd)
            return fd
        with patch.object(m, "_open_component", side_effect=observe):
            with self.assertRaisesRegex(m.MacosPrivateDirectoryError,
                                       "^MACOS_PRIVATE_DIRECTORY_OPEN_DENIED$"):
                m.open_macos_private_directory(self.root)
        self.assert_closed(opened)

    @native_or_deny
    def test_missing_acl_library_or_symbols_closes_descriptors(self):
        original = m._open_component
        for failure in (OSError("private-library-detail"), AttributeError("missing-symbol")):
            opened = []
            def observe(*args):
                fd = original(*args)
                opened.append(fd)
                return fd
            with self.subTest(error=type(failure).__name__), \
                 patch.object(m, "_open_component", side_effect=observe), \
                 patch.object(m, "_load_acl_api", side_effect=failure):
                with self.assertRaisesRegex(m.MacosPrivateDirectoryError,
                                           "^MACOS_PRIVATE_DIRECTORY_INSPECTION_DENIED$"):
                    m.open_macos_private_directory(self.root)
            self.assert_closed(opened)

    @native_or_deny
    def test_acl_read_errors_never_mean_absent_acl(self):
        for error in (0, errno.EACCES, errno.EBADF, errno.ENOTSUP, errno.EINVAL):
            def fail(fd, kind):
                ctypes.set_errno(error)
                return None
            api = SimpleNamespace(acl_get_fd_np=Mock(side_effect=fail), acl_free=Mock())
            with self.subTest(errno=error), patch.object(m, "_load_acl_api", return_value=api):
                with self.assertRaisesRegex(m.MacosPrivateDirectoryError, "ACL_DENIED$"):
                    m.open_macos_private_directory(self.root)
            api.acl_free.assert_not_called()

    @native_or_deny
    def test_returned_acl_is_always_freed_and_rejected(self):
        api = SimpleNamespace(acl_get_fd_np=Mock(return_value=1234), acl_free=Mock(return_value=0))
        with patch.object(m, "_load_acl_api", return_value=api):
            with self.assertRaisesRegex(m.MacosPrivateDirectoryError, "ACL_DENIED$"):
                m.open_macos_private_directory(self.root)
        api.acl_free.assert_called_once_with(1234)

    @native_or_deny
    def test_native_access_acl_refused_even_when_mode_remains_0700(self):
        subprocess.run(["/bin/chmod", "+a", "everyone allow list,search", str(self.root)],
                       check=True, capture_output=True, timeout=5)
        self.addCleanup(subprocess.run, ["/bin/chmod", "-N", str(self.root)],
                        check=True, capture_output=True, timeout=5)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        with self.assertRaisesRegex(m.MacosPrivateDirectoryError, "ACL_DENIED$"):
            m.open_macos_private_directory(self.root)

    @native_or_deny
    def test_native_inherited_acl_refused_on_private_child(self):
        subprocess.run(["/bin/chmod", "+a", "everyone allow list,search,directory_inherit",
                        str(self.root)], check=True, capture_output=True, timeout=5)
        self.addCleanup(subprocess.run, ["/bin/chmod", "-RN", str(self.root)],
                        check=True, capture_output=True, timeout=5)
        child = self.root / "inherited"
        child.mkdir(mode=0o700)
        self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o700)
        with self.assertRaisesRegex(m.MacosPrivateDirectoryError, "ACL_DENIED$"):
            m.open_macos_private_directory(child)

    @native_or_deny
    def test_invalid_descriptor_types_and_regular_fd_denied(self):
        for descriptor in (True, -1, None, "private-fd"):
            with self.assertRaisesRegex(m.MacosPrivateDirectoryError, "DESCRIPTOR_DENIED$"):
                m.validate_macos_private_directory(descriptor)
        regular = self.root / "regular"
        regular.write_bytes(b"public-fixture")
        fd = os.open(regular, os.O_RDONLY | os.O_CLOEXEC)
        try:
            with self.assertRaisesRegex(m.MacosPrivateDirectoryError, "METADATA_DENIED$"):
                m.validate_macos_private_directory(fd)
        finally:
            os.close(fd)

    @native_or_deny
    def test_held_descriptor_not_redirected_by_final_directory_replacement(self):
        child = self.root / "private"
        child.mkdir(mode=0o700)
        fd = m.open_macos_private_directory(child)
        try:
            moved = self.root / "original"
            child.rename(moved)
            child.mkdir(mode=0o700)
            (child / "sentinel").write_bytes(b"untouched")
            marker = os.open("public-fixture", os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                             0o600, dir_fd=fd)
            os.close(marker)
            self.assertTrue((moved / "public-fixture").exists())
            self.assertFalse((child / "public-fixture").exists())
            self.assertEqual((child / "sentinel").read_bytes(), b"untouched")
        finally:
            os.close(fd)

    @native_or_deny
    def test_ancestor_replacement_during_walk_stays_bound_to_held_inode(self):
        ancestor = self.root / "ancestor"
        ancestor.mkdir(mode=0o700)
        (ancestor / "private").mkdir(mode=0o700)
        original_inode = (ancestor / "private").stat().st_ino
        moved = self.root / "moved"
        original = m._open_component
        def swap(name, parent):
            fd = original(name, parent)
            if name == "ancestor":
                ancestor.rename(moved)
                ancestor.mkdir(mode=0o700)
                (ancestor / "private").symlink_to(self.root, target_is_directory=True)
            return fd
        with patch.object(m, "_open_component", side_effect=swap):
            fd = m.open_macos_private_directory(ancestor / "private")
        try:
            self.assertEqual(os.fstat(fd).st_ino, original_inode)
        finally:
            os.close(fd)

    @native_or_deny
    def test_metadata_change_during_acl_inspection_is_denied(self):
        original = m._require_absent_acl
        def change(fd):
            original(fd)
            os.fchmod(fd, 0o755)
        with patch.object(m, "_require_absent_acl", side_effect=change):
            with self.assertRaisesRegex(m.MacosPrivateDirectoryError, "CHANGED$"):
                m.open_macos_private_directory(self.root)

    @native_or_deny
    def test_close_failure_denies_and_closes_return_candidate(self):
        opened = []
        real_open = m._open_component
        real_close = os.close
        def observe(*args):
            fd = real_open(*args)
            opened.append(fd)
            return fd
        def fail_once(fd):
            real_close(fd)
            if fd == opened[0]:
                raise OSError("private-close-detail")
        with patch.object(m, "_open_component", side_effect=observe), \
             patch.object(m.os, "close", side_effect=fail_once):
            with self.assertRaisesRegex(m.MacosPrivateDirectoryError, "CLOSE_DENIED$"):
                m.open_macos_private_directory(self.root)
        self.assert_closed(opened)


if __name__ == "__main__":
    unittest.main()
