"""Source-verified APP WSP scanner -> macOS inode-held SQLite, genuine WSP engine.

Native macOS ARM64; PUBLIC BIP352 fixture and synthetic localhost RPC ONLY.
No WAM Core execution, funds, real accounts, signer, broadcast or mainnet.
Unlike the lower-layer native fixture, exercises the actual app's
SourceQualifiedScanRuntime/QualifiedScanSession entrypoint and projections.
"""
from __future__ import annotations

import argparse
from http.server import ThreadingHTTPServer
from pathlib import Path
import os
import platform
import stat
import struct
import sys
import tempfile
from threading import Thread

from tools.ci_wsp1_scanner_loopback import (
    LocalSyntheticCoreShape, FORK, PAYTIP, PAYTIP_FORK, PAYTX, PREV,
)
from wam_privacy_wallet.application.qualified_scan_session import (
    SourceQualifiedScanRuntime, QualifiedScanError,
)
from wam_privacy_wallet.application.macos_encrypted_scan_backup import (
    provision_macos_encrypted_scan_backup,
)
from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import Wsp1ScannerOnlyRpc
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth


def run(source_root: Path) -> tuple[str, ...]:
    if (not __debug__ or sys.platform != "darwin"
            or platform.machine().lower() != "arm64"
            or struct.calcsize("P") != 8):
        raise RuntimeError("MACOS_APP_NATIVE_PLATFORM_DENIED")
    # Do not import ANY wam_sp source before the application's exact pin check.
    runtime = SourceQualifiedScanRuntime(
        source_root, user_consented=True, macos_disposable=True,
    )
    from wam_sp.core import Input, pub, send
    from wam_sp.keystore import ScanAccount, export_scan

    account = ScanAccount(0, 1, pub(2), birthday=1)
    password = b"PUBLIC_DISPOSABLE_MACOS_REGTEST_ONLY_PASSWORD"
    sender = b"\x51\x20" + pub(7)[1:]
    output = send(
        (Input(PREV, 0, sender, witness=(b"\x01",), secret=7),),
        (account.payment_code(),),
    )[0]
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalSyntheticCoreShape)
    thread = None
    session = None
    stages = []
    try:
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
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def rpc():
            return Wsp1ScannerOnlyRpc(
                LocalRegtestEndpoint("127.0.0.1", server.server_port),
                ExplicitRpcAuth("synthetic", "NOT_A_REAL_REGTEST_RPC_PASSWORD"),
            )

        with tempfile.TemporaryDirectory(
            prefix="macos-qualified-app-public-", dir="/private/tmp",
        ) as name:
            folder = Path(name)
            try:
                provision_macos_encrypted_scan_backup(
                    folder, export_scan((account,), password),
                )
                session = runtime.open(folder, password, user_consented=True)
                first = session.scan(rpc(), user_consented=True, max_blocks=1)
                if (first.blocks_processed != 1 or first.confirmed_utxo_count != 0
                        or first.wallet_operational or first.signer_enabled):
                    raise RuntimeError("MACOS_APP_FIRST_REAL_SCANNER_DENIED")
                stages.append("SOURCE_QUALIFIED_REAL_SCANNER_FIRST_BLOCK")

                server.height, server.tip = 2, PAYTIP
                paid = session.scan(rpc(), user_consented=True, max_blocks=1)
                if (paid.blocks_processed != 1 or paid.confirmed_utxo_count != 1
                        or paid.unqualified_confirmed_atoms != 200000
                        or paid.wallet_operational or paid.broadcast_allowed):
                    raise RuntimeError("MACOS_APP_ACTUAL_WSP_PAYMENT_DENIED")
                stages.append("SOURCE_QUALIFIED_RECEIVE_BALANCE_PROJECTION")

                code = session.receive_code(user_consented=True).code
                if not code.startswith("wamrtsp1"):
                    raise RuntimeError("MACOS_APP_RECEIVE_CODE_DENIED")
                page = session.history(user_consented=True, limit=20)
                if not any(row.txid == PAYTX for row in page.records):
                    raise RuntimeError("MACOS_APP_HISTORY_PROJECTION_DENIED")
                stages.append("SOURCE_QUALIFIED_HISTORY_AND_RECEIVE_CODE")

                session.close()
                session = None
                if stat.S_IMODE((folder / "scan-only-state.sqlite").stat().st_mode) != 0o600:
                    raise RuntimeError("MACOS_APP_SQLITE_PERMISSION_DENIED")
                session = runtime.open(folder, password, user_consented=True)
                try:
                    session.snapshot(user_consented=True)
                    raise RuntimeError("MACOS_APP_STALE_SNAPSHOT_ACCEPTED")
                except QualifiedScanError as exc:
                    if str(exc) != "APP_QUALIFIED_SCAN_NOT_CURRENT":
                        raise
                # A fail-closed snapshot request poisons/ends that session.
                session = None
                session = runtime.open(folder, password, user_consented=True)
                again = session.scan(rpc(), user_consented=True, max_blocks=1)
                if again.blocks_processed != 0 or again.confirmed_utxo_count != 1:
                    raise RuntimeError("MACOS_APP_RESTART_REATTEST_DENIED")
                stages.append("SOURCE_QUALIFIED_RESTART_WITHOUT_REPLAY")

                server.tip, server.discard_payment = PAYTIP_FORK, True
                undone = session.scan(rpc(), user_consented=True, max_blocks=1)
                if (undone.rollback_blocks != 1 or undone.blocks_processed != 1
                        or undone.confirmed_utxo_count != 0):
                    raise RuntimeError("MACOS_APP_REORG_ROLLBACK_DENIED")
                stages.append("SOURCE_QUALIFIED_REORG_REMOVES_UTXO")
                if server.violations:
                    raise RuntimeError("MACOS_APP_RPC_ALLOWLIST_VIOLATION")
            finally:
                if session is not None:
                    session.close()
                    session = None
        if len(stages) != 5:
            raise RuntimeError("MACOS_APP_CASE_COUNT_DENIED")
        return tuple(stages)
    finally:
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=10)
            if thread.is_alive():
                raise RuntimeError("MACOS_APP_SYNTHETIC_THREAD_LEAK")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True)
    args = parser.parse_args(argv)
    try:
        stages = run(Path(args.source_root))
        for stage in stages:
            print("MACOS_APP_" + stage + "_PASS")
        print("MACOS_SOURCE_QUALIFIED_APP_SCAN_ONLY_5_OF_5_PASS_SYNTHETIC_RPC_NO_CORE")
        return 0
    except Exception as exc:
        code = str(exc)
        if (type(exc) in (RuntimeError, QualifiedScanError)
                and 5 <= len(code) <= 110 and code.replace("_", "").isalnum()
                and code.upper() == code):
            print("MACOS_SOURCE_QUALIFIED_APP_DENIED:" + code, file=sys.stderr)
        else:
            print("MACOS_SOURCE_QUALIFIED_APP_DENIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
