"""Static ELF64/x86-64 parser tests on kernel NOEXEC sealed synthetic bytes.

Real WAM ELF is inspected separately by official signed-release workflow.
No subprocess, dynamic loader or WAM Core execution in these tests.
"""
from __future__ import annotations

import os
from pathlib import Path
import struct
import sys
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from wam_privacy_wallet.node import core_elf_preflight as elf
from tools import verify_core_release_sealed as cli

_HEADER = struct.Struct("<HHIQQQIHHHHHH")
_PH = struct.Struct("<IIQQQQQQ")
_INTERP = b"/lib64/ld-linux-x86-64.so.2\x00"


def _binary(*, machine=62, byteorder=1, etype=2, phnum=2,
            interp=_INTERP, load_flags=5, stack_exec=False):
    buf = bytearray(512)
    buf[:16] = b"\x7fELF" + bytes([2, byteorder, 1]) + bytes(9)
    buf[16:64] = _HEADER.pack(
        etype, machine, 1, 0x401000, 64, 0, 0, 64, 56, phnum, 0, 0, 0,
    )
    buf[64:120] = _PH.pack(1, load_flags, 0, 0x400000, 0, 512, 512, 0x1000)
    buf[120:176] = _PH.pack(3, 4, 256, 0, 0, len(interp), len(interp), 1)
    buf[256:256 + len(interp)] = interp
    if stack_exec:
        buf[120:176] = _PH.pack(0x6474E551, 7, 0, 0, 0, 0, 0, 0)
    return bytes(buf)


@contextmanager
def _kernel_fd(payload, *, noexec=True, seals=True):
    flags = os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC
    if noexec:
        flags |= 0x0008
    fd = os.memfd_create("elf-test-no-core", flags)
    try:
        os.write(fd, payload)
        if seals:
            f = elf.fcntl
            bits = f.F_SEAL_WRITE | f.F_SEAL_GROW | f.F_SEAL_SHRINK | f.F_SEAL_SEAL
            f.fcntl(fd, f.F_ADD_SEALS, bits)
        yield fd
    finally:
        os.close(fd)


class SealedElfStaticTests(unittest.TestCase):
    def _linux(self):
        return sys.platform == "linux" and elf.fcntl is not None and hasattr(os, "memfd_create")

    def _unsupported(self):
        with self.assertRaisesRegex(elf.SealedElfError, "^CORE_ELF_PLATFORM_OR_FD_DENIED$"):
            elf.inspect_sealed_linux_elf(-1)

    def test_real_kernel_sealed_x86_64_elf_headers(self):
        if not self._linux():
            self._unsupported()
            return
        with _kernel_fd(_binary()) as fd:
            result = elf.inspect_sealed_linux_elf(fd)
            self.assertEqual(result.architecture, "x86_64")
            self.assertEqual(result.elf_type, "ET_EXEC")
            self.assertTrue(result.has_interpreter)
            self.assertEqual(result.load_segment_count, 1)

    def test_elf_pie_type_and_no_loader_claim(self):
        if not self._linux():
            self._unsupported()
            return
        with _kernel_fd(_binary(etype=3)) as fd:
            result = elf.inspect_sealed_linux_elf(fd)
        self.assertEqual(result.elf_type, "ET_DYN")
        self.assertIs(result.loader_trusted, False)
        self.assertIs(result.process_image_bound, False)

    def test_all_execution_wallet_and_build_claims_remain_false(self):
        if not self._linux():
            self._unsupported()
            return
        with _kernel_fd(_binary()) as fd:
            p = elf.inspect_sealed_linux_elf(fd)
        for field in ("image_loaded", "loader_trusted",
                      "source_build_authenticated", "process_image_bound",
                      "core_execution_allowed", "mainnet_allowed"):
            self.assertIs(getattr(p, field), False)

    def test_unsealed_memfd_is_denied_before_elf_parse(self):
        if not self._linux():
            self._unsupported()
            return
        with _kernel_fd(_binary(), noexec=False, seals=False) as fd:
            with self.assertRaisesRegex(
                elf.SealedElfError, "^CORE_ELF_NOEXEC_REQUIRED$",
            ):
                elf.inspect_sealed_linux_elf(fd)

    def test_sealed_but_executable_memfd_is_denied(self):
        if not self._linux():
            self._unsupported()
            return
        with _kernel_fd(_binary(), noexec=False) as fd:
            with self.assertRaisesRegex(
                elf.SealedElfError, "^CORE_ELF_NOEXEC_REQUIRED$",
            ):
                elf.inspect_sealed_linux_elf(fd)

    def test_non_linux_platform_fails_before_kernel_use(self):
        with patch.object(elf.sys, "platform", "win32"):
            with self.assertRaisesRegex(
                elf.SealedElfError, "^CORE_ELF_PLATFORM_OR_FD_DENIED$",
            ):
                elf.inspect_sealed_linux_elf(3)

    def test_invalid_fd_and_bool_denied(self):
        for fd in (-1, True, False, "1", None):
            with self.subTest(fd=fd), self.assertRaises(elf.SealedElfError):
                elf.inspect_sealed_linux_elf(fd)

    def test_wrong_elf_machine_denied(self):
        if not self._linux():
            self._unsupported()
            return
        with _kernel_fd(_binary(machine=183)) as fd:
            with self.assertRaisesRegex(elf.SealedElfError, "^CORE_ELF_HEADER_DENIED$"):
                elf.inspect_sealed_linux_elf(fd)

    def test_wrong_elf_endianness_denied(self):
        if not self._linux():
            self._unsupported()
            return
        with _kernel_fd(_binary(byteorder=2)) as fd:
            with self.assertRaisesRegex(elf.SealedElfError, "^CORE_ELF_HEADER_DENIED$"):
                elf.inspect_sealed_linux_elf(fd)

    def test_program_header_bounds_denied(self):
        if not self._linux():
            self._unsupported()
            return
        with _kernel_fd(_binary(phnum=200)) as fd:
            with self.assertRaisesRegex(elf.SealedElfError, "^CORE_ELF_HEADER_DENIED$"):
                elf.inspect_sealed_linux_elf(fd)

    def test_writable_executable_load_denied(self):
        if not self._linux():
            self._unsupported()
            return
        with _kernel_fd(_binary(load_flags=7)) as fd:
            with self.assertRaisesRegex(elf.SealedElfError, "^CORE_ELF_WX_LOAD_DENIED$"):
                elf.inspect_sealed_linux_elf(fd)

    def test_bad_interpreter_string_denied_without_leak(self):
        if not self._linux():
            self._unsupported()
            return
        with _kernel_fd(_binary(interp=b"/tmp/untrusted\x00/evil")) as fd:
            with self.assertRaises(elf.SealedElfError) as caught:
                elf.inspect_sealed_linux_elf(fd)
        self.assertEqual(str(caught.exception), "CORE_ELF_INTERP_DENIED")
        self.assertNotIn("untrusted", str(caught.exception))

    def test_executable_stack_segment_denied(self):
        if not self._linux():
            self._unsupported()
            return
        with _kernel_fd(_binary(stack_exec=True)) as fd:
            with self.assertRaisesRegex(elf.SealedElfError, "^CORE_ELF_EXECUTABLE_STACK_DENIED$"):
                elf.inspect_sealed_linux_elf(fd)


class RedactedSignedElfCliBoundaryTests(unittest.TestCase):
    def test_elf_denial_survives_memfd_cleanup_without_leaking_binary(self):
        closed = []
        class Review:
            _descriptor = 9
            def audit(self):
                return True
        @contextmanager
        def metadata():
            try:
                root = Path.cwd()
                yield {"key": root / "key", "checksums": root / "sums",
                       "signature": root / "sig"}
            finally:
                closed.append("metadata")
        @contextmanager
        def snapshot(**kwargs):
            try:
                yield Review()
            finally:
                closed.append("fd")
        with patch.object(cli, "official_release_metadata", side_effect=metadata), \
             patch.object(cli, "sealed_signed_linux_wamd", side_effect=snapshot), \
             patch.object(cli, "inspect_sealed_linux_elf",
                          side_effect=elf.SealedElfError("CORE_ELF_HEADER_DENIED")):
            with self.assertRaisesRegex(elf.SealedElfError, "^CORE_ELF_HEADER_DENIED$"):
                cli.verify_signed_linux_memfd(
                    archive=str(Path.cwd() / "official.tar.gz"),
                    gpg=str(Path.cwd() / "gpg"),
                )
        self.assertEqual(closed, ["fd", "metadata"])


if __name__ == "__main__":
    unittest.main()
