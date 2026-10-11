# CORE-EXEC-082 step 3a — static ELF loader profile from signed NOEXEC bytes

Building on PR #83's genuine WAM v0.1.11 release signature -> exact signed `wamd` hash -> Linux `MFD_NOEXEC_SEAL` memory image, this stage reads the **ELF64 x86-64 header and program table directly from the already-sealed file descriptor**, using bounded `os.pread`. It never hands out the `PT_INTERP` path, loads shared libraries, invokes a dynamic loader, calls `execve`, `fexecve`, `Popen` or starts WAM Core.

`inspect_sealed_linux_elf(fd)` checks:
- actual Linux kernel `F_GET_SEALS` includes WRITE/GROW/SHRINK/SEAL and `F_SEAL_EXEC`; descriptor mode has **no execute bits**;
- 64-bit little-endian ELF, `EM_X86_64` machine, ET_EXEC or ET_DYN type, bounded on-disk program headers and each segment's size;
- at least one `PT_LOAD` segment, no W+X LOAD, no executable GNU_STACK;
- at most one `PT_INTERP`, with canonical nonembedded-NUL absolute printable path, but does **not** return or trust the interpreter name;
- no callback, mock source, remote service, filename or executable path for operational ELF input.

The opt-in `tools.verify_core_release_sealed` now includes a scalar-only ELF layout summary on every successful official signed NOEXEC review: ELF class, architecture, ET_EXEC/ET_DYN, PT_LOAD count, interpreter/dynamic-section presence. It explicitly sets `runtime_loader_authenticated=false`. Neither a plausible ELF header nor a signed archive proves source/build reproducibility, the dynamic loader's runtime bytes, kernel process-image identity or a safe WAM Core execution environment.

The official release workflow tests **actual signed WAM Linux ELF bytes**, not a synthetic ELF, using the pre-existing HTTPS+GPG official verification and memfd pipeline. New negative tests are deliberately synthetic and use real Linux kernel NOEXEC/seals, while unsupported Windows/macOS remain denied.

**Still blocked:** `CORE_EXECUTION_REVIEW_REQUIRED` is unchanged; no binary launcher API or WAM Core subprocess is added. DEV WAM must independently review publisher/source mapping, loader/runtime dependency trust, OS-specific binary-to-process binding and isolated regtest-only node lifecycle. Real two-node Core execution, key/wallet persistence, WSP scanner integration and mainnet are not authorized by ELF preflight.
