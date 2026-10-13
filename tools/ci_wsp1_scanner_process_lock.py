"""Native actual WSP Scanner lease across disposable Python processes.

Public synthetic REGTEST peer only; no Core, signer, retained application
custody or backup/anti-rollback qualification. Every child qualifies source
and dependencies before importing WSP. Pipes coordinate actual lease ownership.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import os
from pathlib import Path
import queue
import stat
import struct
import subprocess
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer

from tools.ci_wsp1_scanner_native_only import _no_signer
from tools.ci_wsp1_scanner_loopback import LocalSyntheticCoreShape, FORK
from wam_privacy_wallet.integrations.wsp1_source_closure import (
    verify_wsp1_full_source_closure,
)

PIN = "ac55f13423620252bdbf848c7e8a280c3b84721e"
ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 20


def _platform() -> None:
    if not __debug__:
        raise RuntimeError("WSP_PROCESS_LOCK_OPTIMIZED_TESTS_DENIED")
    if struct.calcsize("P") != 8 or sys.platform not in ("linux", "darwin", "win32"):
        raise RuntimeError("WSP_PROCESS_LOCK_PLATFORM_UNQUALIFIED")


def _qualify(root: Path) -> None:
    _platform()
    if (not root.is_absolute() or root.is_symlink()
            or any(n == "wam_sp" or n.startswith("wam_sp.") for n in sys.modules)):
        raise RuntimeError("WSP_PROCESS_LOCK_SOURCE_DENIED")
    proof = verify_wsp1_full_source_closure(root)
    if proof["pinned_commit"] != PIN or proof["scanner_enabled"] is not False:
        raise RuntimeError("WSP_PROCESS_LOCK_SOURCE_DENIED")
    for package, version in (("coincurve", "21.0.0"), ("cryptography", "50.0.0"),
                             ("pycryptodome", "3.23.0")):
        if importlib.metadata.version(package) != version:
            raise RuntimeError("WSP_PROCESS_LOCK_DEPENDENCY_DENIED")
    spec = importlib.util.find_spec("wam_sp")
    if (spec is None or spec.origin is None
            or Path(spec.origin).resolve() != root / "src/wam_sp/__init__.py"):
        raise RuntimeError("WSP_PROCESS_LOCK_INSTALLED_SOURCE_DENIED")


def _database(path: Path) -> None:
    """Accept only the disposable parent-created test layout, never a wallet."""
    if (not path.is_absolute() or path.name != "public-fixture.sqlite"
            or path.parent.name not in ("normal", "terminated")
            or not path.parent.parent.name.startswith("wsp-process-lock-")
            or path.is_symlink() or path.parent.is_symlink()):
        raise RuntimeError("WSP_PROCESS_LOCK_DATABASE_DENIED")
    info = path.parent.stat()
    if (not stat.S_ISDIR(info.st_mode) or (os.name == "posix" and
            (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700))):
        raise RuntimeError("WSP_PROCESS_LOCK_DATABASE_DENIED")


class _NoRpc:
    """Failure sentinel; lock contention must precede every RPC operation."""
    def __init__(self) -> None:
        self.attempts = 0

    def attest(self):
        self.attempts += 1
        raise RuntimeError("WSP_PROCESS_LOCK_RPC_BEFORE_LEASE_DENIED")

    def call(self, *_args):
        return self.attest()


def _child(root: Path, database: Path, role: str, port: int | None) -> None:
    _qualify(root)
    _database(database)
    sys.setprofile(_no_signer)
    # No native WSP import occurs before full source, dependency and origin proof.
    from wam_sp.core import pub
    from wam_sp.keystore import ScanAccount
    from wam_sp.scanner import Scanner
    scanner = Scanner(database, (ScanAccount(0, 1, pub(2), birthday=1),))
    try:
        if role == "holder":
            with scanner._lease():
                print("LEASE_READY", flush=True)
                if sys.stdin.readline(32) != "RELEASE\n":
                    raise RuntimeError("WSP_PROCESS_LOCK_PROTOCOL_DENIED")
            print("LEASE_RELEASED", flush=True)
        elif role == "contender":
            rpc = _NoRpc()
            before = scanner.store.tip()
            try:
                scanner.sync(rpc, max_blocks=1)
            except ValueError as error:
                if str(error) != "SCANNER_BUSY":
                    raise RuntimeError("WSP_PROCESS_LOCK_WRONG_DENIAL") from None
            else:
                raise RuntimeError("WSP_PROCESS_LOCK_EXCLUSION_FAILED")
            assert rpc.attempts == 0 and scanner.store.tip() == before
            assert not scanner.ready and not scanner.mempool_ready
            print("BUSY_NO_RPC", flush=True)
        elif role == "scan":
            from wam_privacy_wallet.application.wsp_scan_coordinator import run_consented_wsp_scan
            from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import Wsp1ScannerOnlyRpc
            from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
            from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
            if type(port) is not int or not 1 <= port <= 65535:
                raise RuntimeError("WSP_PROCESS_LOCK_ENDPOINT_DENIED")
            def rpc():
                return Wsp1ScannerOnlyRpc(LocalRegtestEndpoint("127.0.0.1", port),
                                         ExplicitRpcAuth("synthetic", "NO_REAL_CREDENTIAL"))
            first = rpc()
            assert not scanner.ready and first._baseline is None
            receipt = run_consented_wsp_scan(scanner, first, user_consented=True, max_blocks=1)
            assert receipt.blocks_processed == 1 and receipt.transactions_processed == 1
            assert scanner.ready and first._baseline is not None and not scanner.coins()
            assert not (receipt.wallet_operational or receipt.core_authenticated
                        or receipt.signer_enabled or receipt.broadcast_allowed or receipt.mainnet_allowed)
            print("ACTUAL_SYNC", flush=True)
            scanner.close()
            scanner = Scanner(database, (ScanAccount(0, 1, pub(2), birthday=1),))
            fresh = rpc()
            assert not scanner.ready and not scanner.mempool_ready and fresh._baseline is None
            repeat = run_consented_wsp_scan(scanner, fresh, user_consented=True, max_blocks=1)
            assert repeat.blocks_processed == 0 and scanner.ready and fresh._baseline is not None
            assert not scanner.coins()
            print("ACTUAL_REOPEN_REATTEST", flush=True)
        else:
            raise RuntimeError("WSP_PROCESS_LOCK_ROLE_DENIED")
    finally:
        scanner.close()
        sys.setprofile(None)


class _Process:
    """Bounded pipe protocol, with no sleeps, readiness polling or inherited auth."""
    def __init__(self, root: Path, database: Path, role: str, port: int | None = None):
        env = {key: os.environ[key] for key in
               ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR")
               if key in os.environ}
        env.update(PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1",
                   PYTHONUNBUFFERED="1")
        args = [sys.executable, "-B", "-m", "tools.ci_wsp1_scanner_process_lock",
                "--source-root", str(root), "--child-role", role, "--database", str(database)]
        if port is not None:
            args += ["--port", str(port)]
        self.process = subprocess.Popen(args, cwd=ROOT, env=env, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        text=True, bufsize=1)
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        try:
            while line := self.process.stdout.readline(128):
                if len(line) > 80 or not line.endswith("\n"):
                    self.lines.put("INVALID_PROTOCOL")
                    return
                self.lines.put(line.rstrip("\n"))
        finally:
            self.lines.put(None)

    def expect(self, expected: str | None):
        try:
            if self.lines.get(timeout=TIMEOUT) != expected:
                raise RuntimeError("WSP_PROCESS_LOCK_PROTOCOL_DENIED")
        except queue.Empty:
            raise RuntimeError("WSP_PROCESS_LOCK_PROTOCOL_TIMEOUT") from None

    def finish(self):
        if self.process.wait(timeout=TIMEOUT) != 0:
            raise RuntimeError("WSP_PROCESS_LOCK_CHILD_DENIED")
        self.expect(None)

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=TIMEOUT)
        for pipe in (self.process.stdin, self.process.stdout):
            pipe.close()
        self.reader.join(timeout=TIMEOUT)
        if self.reader.is_alive():
            raise RuntimeError("WSP_PROCESS_LOCK_READER_CLEANUP_DENIED")


def run(root: Path) -> list[str]:
    _qualify(root)
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalSyntheticCoreShape)
    server.tip = FORK
    server.height = 1
    server.discard_payment = False
    server.silent_payment = None
    server.observed_methods = []
    server.violations = []
    server.mempool_reads = 0
    server.flip_mempool_second = False
    server.bad_prevout = False
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    passed = []
    try:
        with tempfile.TemporaryDirectory(prefix="wsp-process-lock-") as temporary:
            for mode in ("normal", "terminated"):
                directory = Path(temporary).resolve() / mode
                directory.mkdir(mode=0o700)
                database = directory / "public-fixture.sqlite"
                holder = _Process(root, database, "holder")
                try:
                    holder.expect("LEASE_READY")
                    before = len(server.observed_methods)
                    contender = _Process(root, database, "contender")
                    try:
                        contender.expect("BUSY_NO_RPC")
                        contender.finish()
                    finally:
                        contender.close()
                    assert len(server.observed_methods) == before
                    passed.append(mode.upper() + "_BUSY_NO_RPC")
                    if mode == "normal":
                        holder.process.stdin.write("RELEASE\n")
                        holder.process.stdin.flush()
                        holder.expect("LEASE_RELEASED")
                        holder.finish()
                    else:
                        holder.process.terminate()
                        assert holder.process.wait(timeout=TIMEOUT) != 0
                        holder.expect(None)
                finally:
                    holder.close()
                assert database.with_name(database.name + ".scan.lock").is_file()
                resumed = _Process(root, database, "scan", server.server_port)
                try:
                    resumed.expect("ACTUAL_SYNC")
                    passed.append(mode.upper() + "_ACTUAL_SYNC_AFTER_EXIT")
                    resumed.expect("ACTUAL_REOPEN_REATTEST")
                    passed.append(mode.upper() + "_ACTUAL_REOPEN_REATTEST")
                    resumed.finish()
                finally:
                    resumed.close()
                assert len(server.observed_methods) > before and not server.violations
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=TIMEOUT)
        if thread.is_alive():
            raise RuntimeError("WSP_PROCESS_LOCK_SERVER_CLEANUP_DENIED")
    return passed


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--child-role", choices=("holder", "contender", "scan"), help=argparse.SUPPRESS)
    parser.add_argument("--database", help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        root = Path(args.source_root)
        if args.child_role:
            if not args.database:
                raise RuntimeError("WSP_PROCESS_LOCK_DATABASE_DENIED")
            _child(root, Path(args.database), args.child_role, args.port)
        else:
            passed = run(root)
            expected = [mode + suffix for mode in ("NORMAL", "TERMINATED")
                        for suffix in ("_BUSY_NO_RPC", "_ACTUAL_SYNC_AFTER_EXIT", "_ACTUAL_REOPEN_REATTEST")]
            if passed != expected:
                raise RuntimeError("WSP_PROCESS_LOCK_CASE_COUNT_DENIED")
            for name in passed:
                print("ACTUAL_NATIVE_WSP_PROCESS_LOCK_" + name + "_PASS")
            print(f"ACTUAL_NATIVE_WSP_PROCESS_LOCK_OK {sys.platform}; 6/6; public synthetic peer only; NO Core/signing/retained custody authority")
    except Exception:
        print("WSP_NATIVE_PROCESS_LOCK_DENIED", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
