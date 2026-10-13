"""Read-only ELF64 x86-64 layout audit of a sealed Linux NOEXEC fd.

This inspection never loads the ELF, launches a subprocess, supplies a loader
path or grants execution. The fd must already be kernel-sealed and NOEXEC.
An ELF header shape is not trusted publisher, build or process identity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
import stat
import struct
import sys

from .core_linux_sealed_snapshot import fcntl

_HEADER = struct.Struct("<HHIQQQIHHHHHH")
_PROGRAM = struct.Struct("<IIQQQQQQ")
_PT_LOAD = 1
_PT_DYNAMIC = 2
_PT_INTERP = 3
_PT_GNU_STACK = 0x6474E551
_SEAL_EXEC = 0x0020
_MAX_BYTES = 128 * 1024 * 1024


class SealedElfError(ValueError):
    """Fixed code; never leaks parser bytes or ELF interpreter path."""


@dataclass(frozen=True, slots=True)
class SealedElfObservation:
    """Scalar non-authorizing ELF layout summary."""

    binary_class: str
    architecture: str
    elf_type: str
    load_segment_count: int
    has_interpreter: bool
    has_dynamic_segment: bool
    executable_stack_requested: bool
    status: str = field(default="NOEXEC_SEALED_ELF_STATIC_ONLY", init=False)
    image_loaded: bool = field(default=False, init=False)
    loader_trusted: bool = field(default=False, init=False)
    source_build_authenticated: bool = field(default=False, init=False)
    process_image_bound: bool = field(default=False, init=False)
    core_execution_allowed: bool = field(default=False, init=False)
    mainnet_allowed: bool = field(default=False, init=False)


def inspect_sealed_linux_elf(fd: int) -> SealedElfObservation:
    """Parse only ELF and program headers from already-sealed NOEXEC memfd."""
    if (sys.platform != "linux" or fcntl is None
            or not hasattr(os, "pread") or type(fd) is not int or fd < 0):
        raise SealedElfError("CORE_ELF_PLATFORM_OR_FD_DENIED")
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode)
                or not 64 <= info.st_size <= _MAX_BYTES
                or info.st_mode & 0o111):
            raise SealedElfError("CORE_ELF_NOEXEC_REQUIRED")
        required = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                    | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL | _SEAL_EXEC)
        if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & required != required:
            raise SealedElfError("CORE_ELF_NOEXEC_REQUIRED")
        raw = os.pread(fd, 64, 0)
        if (len(raw) != 64 or raw[:4] != b"\x7fELF"
                or raw[4:7] != b"\x02\x01\x01"):
            raise SealedElfError("CORE_ELF_HEADER_DENIED")
        fields = _HEADER.unpack(raw[16:64])
        (etype, machine, version, entry, phoff, _shoff, _flags,
         ehsize, phentsize, phnum, _shentsize, _shnum, _shstrndx) = fields
        if (etype not in (2, 3) or machine != 62 or version != 1
                or entry == 0 or ehsize != 64
                or phentsize != _PROGRAM.size or not 1 <= phnum <= 128
                or phoff < 64 or phoff + phentsize * phnum > info.st_size):
            raise SealedElfError("CORE_ELF_HEADER_DENIED")
        program_table = os.pread(fd, phentsize * phnum, phoff)
        if len(program_table) != phentsize * phnum:
            raise SealedElfError("CORE_ELF_PROGRAM_DENIED")
        load = interp = dynamic = 0
        exec_stack = False
        stack_headers = 0
        for i in range(phnum):
            (kind, flags, offset, _vaddr, _paddr, filesz,
             memsz, _align) = _PROGRAM.unpack_from(
                program_table, i * phentsize,
            )
            if offset > info.st_size or filesz > info.st_size - offset:
                raise SealedElfError("CORE_ELF_PROGRAM_DENIED")
            if kind == _PT_LOAD:
                if filesz > memsz:
                    raise SealedElfError("CORE_ELF_LOAD_SIZE_DENIED")
                if flags & 0x3 == 0x3:
                    raise SealedElfError("CORE_ELF_WX_LOAD_DENIED")
                load += 1
            elif kind == _PT_DYNAMIC:
                dynamic += 1
            elif kind == _PT_INTERP:
                interp += 1
                if (interp > 1 or filesz < 3 or filesz > 4096):
                    raise SealedElfError("CORE_ELF_INTERP_DENIED")
                content = os.pread(fd, filesz, offset)
                if (len(content) != filesz or content[:1] != b"/"
                        or content[-1:] != b"\x00" or b"\x00" in content[:-1]
                        or any(c < 33 or c > 126 for c in content[:-1])):
                    raise SealedElfError("CORE_ELF_INTERP_DENIED")
            elif kind == _PT_GNU_STACK:
                stack_headers += 1
                if stack_headers > 1:
                    raise SealedElfError("CORE_ELF_STACK_DUPLICATE_DENIED")
                exec_stack = bool(flags & 0x1)
                if not exec_stack and flags != 0x6:
                    # Match the inert successor archive policy: one explicit
                    # RW (non-X) stack. Missing/unknown flag semantics cannot
                    # be reported as a non-executable-stack observation.
                    raise SealedElfError("CORE_ELF_STACK_MODE_DENIED")
        if load == 0:
            raise SealedElfError("CORE_ELF_NO_LOAD_DENIED")
        if dynamic > 1:
            raise SealedElfError("CORE_ELF_DYNAMIC_DENIED")
        if exec_stack:
            raise SealedElfError("CORE_ELF_EXECUTABLE_STACK_DENIED")
        if stack_headers != 1:
            raise SealedElfError("CORE_ELF_STACK_HEADER_REQUIRED")
        return SealedElfObservation(
            binary_class="ELF64_LE", architecture="x86_64",
            elf_type="ET_EXEC" if etype == 2 else "ET_DYN",
            load_segment_count=load,
            has_interpreter=bool(interp), has_dynamic_segment=bool(dynamic),
            executable_stack_requested=False,
        )
    except SealedElfError:
        raise
    except (OSError, ValueError, struct.error, OverflowError):
        raise SealedElfError("CORE_ELF_READ_DENIED") from None
