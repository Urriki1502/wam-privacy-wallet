"""Linux-only CI proof: deny socket, process creation and ptrace BEFORE WSP CLI.

Actual kernel seccomp-BPF via libseccomp2, with PR_SET_NO_NEW_PRIVS.
Cannot certify OS filesystem sandboxing, process-image provenance or WAM Core.
This is a disposable *test harness*, never a wallet runtime signer launcher.
"""
from __future__ import annotations

import ctypes
import errno
import os
import runpy
import socket
import sys

SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO_EPERM = 0x00050000 | errno.EPERM
PR_SET_NO_NEW_PRIVS = 38
# Block network socket access AND escape by spawning an unfiltered process.
DENY = (
    "socket", "socketpair", "connect", "bind", "listen",
    "accept", "accept4", "sendto", "sendmsg", "sendmmsg",
    "recvfrom", "recvmsg", "recvmmsg", "shutdown",
    "getsockopt", "setsockopt", "execve", "execveat",
    "fork", "vfork", "clone", "clone3", "ptrace",
    "process_vm_readv", "process_vm_writev",
)


def install_network_and_exec_denial() -> None:
    if sys.platform != "linux" or os.name != "posix":
        raise RuntimeError("OFFLINE_SIGNER_SECCOMP_PLATFORM_DENIED")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                              ctypes.c_ulong, ctypes.c_ulong)
        libc.prctl.restype = ctypes.c_int
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise RuntimeError
        lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
        lib.seccomp_init.argtypes = (ctypes.c_uint32,)
        lib.seccomp_init.restype = ctypes.c_void_p
        lib.seccomp_syscall_resolve_name.argtypes = (ctypes.c_char_p,)
        lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
        lib.seccomp_rule_add.argtypes = (ctypes.c_void_p, ctypes.c_uint32,
                                         ctypes.c_int, ctypes.c_uint)
        lib.seccomp_rule_add.restype = ctypes.c_int
        lib.seccomp_load.argtypes = (ctypes.c_void_p,)
        lib.seccomp_load.restype = ctypes.c_int
        lib.seccomp_release.argtypes = (ctypes.c_void_p,)
        lib.seccomp_release.restype = None
        ctx = lib.seccomp_init(SCMP_ACT_ALLOW)
        if not ctx:
            raise RuntimeError
        try:
            for name in DENY:
                syscall = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
                # Some syscalls are deliberately absent on specific Linux
                # architectures. No unknown syscall may silently be skipped.
                if syscall < 0:
                    raise RuntimeError
                if lib.seccomp_rule_add(ctx, SCMP_ACT_ERRNO_EPERM,
                                        syscall, 0) != 0:
                    raise RuntimeError
            if lib.seccomp_load(ctx) != 0:
                raise RuntimeError
        finally:
            lib.seccomp_release(ctx)
        # Make network policy observable, not just a successfully returned
        # seccomp_load(). No child can fake PASS without an actual denied call.
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except OSError as error:
            if error.errno != errno.EPERM:
                raise RuntimeError from None
        else:
            raise RuntimeError
    except Exception:
        raise RuntimeError("OFFLINE_SIGNER_SECCOMP_DENIED") from None


def main() -> int:
    argv = sys.argv[1:]
    if argv == ["--network-probe"]:
        install_network_and_exec_denial()
        print("WSP_OFFLINE_SIGNER_KERNEL_NETWORK_DENIED")
        return 0
    if (len(argv) != 7 or argv[0] != "--signer"
            or argv[1] != "--keys" or argv[3] != "--request"
            or argv[5] != "--output"):
        raise SystemExit("OFFLINE_SIGNER_SECCOMP_ARGS_DENIED")
    # No upstream WSP import, Keyring or password until the syscall
    # restrictions are loaded in this same PID.
    install_network_and_exec_denial()
    sys.argv = ["wam_sp.offline_signer", *argv[1:]]
    runpy.run_module("wam_sp.offline_signer", run_name="__main__", alter_sys=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
