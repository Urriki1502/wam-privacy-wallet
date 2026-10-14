"""Actual pinned WSP-1 scan-only envelope -> retained SQLite -> restart/reorg on macOS.

Only public fixture accounts and a SYNTHETIC localhost RPC server are used.
No Core process, production custody, real seed, signer, broadcast or GUI activation.
This is a native dependency-proof prerequisite for future real-Core REGTEST E2E.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer

from tools.ci_wsp1_scanner_loopback import (
    LocalSyntheticCoreShape, FORK, PAYTIP, PAYTIP_FORK, PAYTX, PREV,
)
from tools.ci_wsp1_scanner_process_lock import _qualify
from tools.ci_wsp1_scanner_native_only import _no_signer
from wam_privacy_wallet.application.macos_encrypted_scan_backup import (
    load_macos_encrypted_scan_backup, provision_macos_encrypted_scan_backup,
)
from wam_privacy_wallet.application.macos_private_directory import (
    open_macos_private_directory, validate_macos_private_directory,
)
from wam_privacy_wallet.application.wsp_scan_coordinator import run_consented_wsp_scan
from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import Wsp1ScannerOnlyRpc
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth


def _platform() -> None:
    if not __debug__ or sys.platform != "darwin" or struct.calcsize("P") != 8:
        raise RuntimeError("MACOS_RETAINED_WSP_PLATFORM_DENIED")


def _disposable_database(folder: Path) -> Path:
    """Seed a strictly private SQLite pathname; NOT a race-free FD handoff.

    The upstream Scanner still opens a PATH, so the application must not treat
    this fixture as a production storage/provenance boundary.
    """
    parent = open_macos_private_directory(folder)
    file_fd = None
    failed = False
    path = folder / "public-retained-fixture.sqlite"
    try:
        validate_macos_private_directory(parent)
        file_fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                          os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        info = os.fstat(file_fd)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.geteuid() or info.st_nlink != 1
                or info.st_size != 0 or os.get_inheritable(file_fd)
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
            raise RuntimeError("MACOS_RETAINED_WSP_DB_DENIED")
        validate_macos_private_directory(parent)
    except Exception:
        failed = True
    finally:
        for fd in (file_fd, parent):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    failed = True
    if failed:
        raise RuntimeError("MACOS_RETAINED_WSP_DB_DENIED") from None
    return path


def run(root: Path) -> tuple[str, ...]:
    _platform()
    _qualify(root)  # exact pinned source, native dependencies, import origin.
    previous = sys.getprofile()
    sys.setprofile(_no_signer)
    server = None
    thread = None
    scanner = None
    cases = []
    try:
        # WSP imports occur only AFTER full source/dependency/origin check.
        from wam_sp.core import Input, pub, send
        from wam_sp.keystore import ScanAccount, export_scan, import_scan
        from wam_sp.scanner import Scanner

        account = ScanAccount(0, 1, pub(2), birthday=1)
        password = b"PUBLIC_DISPOSABLE_REGTEST_SCAN_ONLY_PASSPHRASE"
        sender = b"\x51\x20" + pub(7)[1:]
        output = send(
            (Input(PREV, 0, sender, witness=(b"\x01",), secret=7),),
            (account.payment_code(),),
        )[0]
        server = ThreadingHTTPServer(("127.0.0.1", 0), LocalSyntheticCoreShape)
        server.tip = FORK
        server.height = 1
        server.discard_payment = False
        server.observed_methods = []
        server.violations = []
        server.mempool_reads = 0
        server.flip_mempool_second = False
        server.bad_prevout = False
        server.silent_payment = {
            "txid": PAYTX,
            "vin": [{"txid": PREV, "vout": 0,
                     "prevout": {"value": 0.003, "scriptPubKey": {"hex": sender.hex()}},
                     "scriptSig": {"hex": ""}, "txinwitness": ["01"]}],
            "vout": [{"n": 0, "value": 0.002,
                      "scriptPubKey": {"hex": "5120" + output.hex()}}],
        }
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def rpc():
            return Wsp1ScannerOnlyRpc(
                LocalRegtestEndpoint("127.0.0.1", server.server_port),
                ExplicitRpcAuth("synthetic", "NO_REAL_RPC_CREDENTIAL"),
            )

        with tempfile.TemporaryDirectory(prefix="macos-retained-public-",
                                         dir="/private/tmp") as directory:
            folder = Path(directory)
            envelope = export_scan((account,), password)
            provision_macos_encrypted_scan_backup(folder, envelope)
            restored = import_scan(load_macos_encrypted_scan_backup(folder), password)
            if restored != (account,):
                raise RuntimeError("MACOS_RETAINED_WSP_IMPORT_DENIED")
            cases.append("ACTUAL_NATIVE_ENCRYPTED_SCAN_ONLY_IMPORT")
            db = _disposable_database(folder)
            scanner = Scanner(db, restored)
            first = run_consented_wsp_scan(scanner, rpc(), user_consented=True, max_blocks=1)
            if first.blocks_processed != 1 or scanner.coins():
                raise RuntimeError("MACOS_RETAINED_WSP_FIRST_SYNC_DENIED")
            cases.append("ACTUAL_NATIVE_SCANNER_SQLITE_SYNC")
            server.height, server.tip = 2, PAYTIP
            paid = run_consented_wsp_scan(scanner, rpc(), user_consented=True, max_blocks=1)
            coins = scanner.coins()
            if (paid.blocks_processed != 1 or len(coins) != 1
                    or coins[0]["txid"] != PAYTX or coins[0]["atoms"] != 200000
                    or any(getattr(paid, field) is not False for field in (
                        "wallet_operational", "signer_enabled", "broadcast_allowed",
                        "mainnet_allowed"))):
                raise RuntimeError("MACOS_RETAINED_WSP_PAYMENT_DENIED")
            cases.append("ACTUAL_NATIVE_BIP352_RECEIVE_MATCH")
            scanner.close()
            scanner = None
            if stat.S_IMODE(db.stat().st_mode) != 0o600:
                raise RuntimeError("MACOS_RETAINED_WSP_DB_PERMISSION_DENIED")
            renewed = import_scan(load_macos_encrypted_scan_backup(folder), password)
            scanner = Scanner(db, renewed)
            if scanner.ready or scanner.mempool_ready:
                raise RuntimeError("MACOS_RETAINED_WSP_STALE_STATE_DENIED")
            replay = run_consented_wsp_scan(scanner, rpc(), user_consented=True, max_blocks=1)
            if replay.blocks_processed != 0 or len(scanner.coins()) != 1:
                raise RuntimeError("MACOS_RETAINED_WSP_REOPEN_DENIED")
            cases.append("ACTUAL_NATIVE_RESTART_REATTEST_NO_REPLAY")
            server.tip, server.discard_payment = PAYTIP_FORK, True
            fork = run_consented_wsp_scan(scanner, rpc(), user_consented=True, max_blocks=1)
            if fork.rollback_blocks != 1 or fork.blocks_processed != 1 or scanner.coins():
                raise RuntimeError("MACOS_RETAINED_WSP_REORG_DENIED")
            cases.append("ACTUAL_NATIVE_REORG_ROLLBACK")
            if server.violations:
                raise RuntimeError("MACOS_RETAINED_WSP_RPC_VIOLATION")
        if len(cases) != 5:
            raise RuntimeError("MACOS_RETAINED_WSP_CASE_COUNT_DENIED")
        return tuple(cases)
    finally:
        if scanner is not None:
            scanner.close()
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=10)
            if thread.is_alive():
                raise RuntimeError("MACOS_RETAINED_WSP_THREAD_LEAK")
        sys.setprofile(previous)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True)
    options = parser.parse_args(argv)
    try:
        result = run(Path(options.source_root))
        for item in result:
            print("MACOS_RETAINED_WSP_" + item + "_PASS")
        print("MACOS_RETAINED_WSP_SYNTHETIC_ONLY_5_OF_5_PASS_NO_CORE")
        return 0
    except Exception:
        print("MACOS_RETAINED_WSP_NATIVE_DENIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
