"""Actual pinned retained application adapter against a synthetic loopback peer.

Linux x64 persistence qualification only; not a WAM Core operational backend.
Known public scan scalar 1 / spend public key 2 are created ONLY in this test.
"""
from __future__ import annotations

import argparse
from dataclasses import fields
from http.server import ThreadingHTTPServer
from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory
import threading

from tools.ci_wsp1_scanner_loopback import (
    LocalSyntheticCoreShape, FORK, PREV, PAYTIP, PAYTIP_FORK, PAYTX,
)
from tools.ci_wsp1_scanner_native_only import _no_signer
from wam_privacy_wallet.application.qualified_scan_session import (
    SourceQualifiedScanRuntime, QualifiedScanError,
)
from wam_privacy_wallet.application.encrypted_scan_backup import provision_encrypted_scan_backup
from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import Wsp1ScannerOnlyRpc
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth


def _denied(action, code: str) -> None:
    try:
        action()
    except QualifiedScanError as error:
        if str(error) != code:
            raise AssertionError("ACTUAL_SESSION_WRONG_DENIAL") from None
    else:
        raise AssertionError("ACTUAL_SESSION_DENIAL_MISSING")


class _CaseProgress(list):
    """Fixed test identities only; make partial CI failures diagnosable."""

    def append(self, case):
        super().append(case)
        print("PINNED_RETAINED_APP_SESSION_" + case + "_PASS", flush=True)


def run(root: Path) -> None:
    if not __debug__:
        raise RuntimeError("ACTUAL_SESSION_OPTIMIZED_TESTS_DENIED")
    # Runtime enforces platform, exact commit/full blobs, dependency versions,
    # installed origin, no bytecode and no preloaded upstream before imports.
    sys.setprofile(_no_signer)
    runtime = SourceQualifiedScanRuntime(root, user_consented=True)
    from wam_sp.core import Input, pub, send
    from wam_sp.keystore import ScanAccount, export_scan
    account = ScanAccount(0, 1, pub(2), birthday=1)
    password = b"PUBLIC_DISPOSABLE_REGTEST_TEST_PASSWORD"
    envelope = export_scan((account,), password)
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalSyntheticCoreShape)
    server.tip = FORK
    server.height = 1
    server.discard_payment = False
    server.observed_methods = []
    server.violations = []
    server.mempool_reads = 0
    server.flip_mempool_second = False
    server.bad_prevout = False
    sender_script = b"\x51\x20" + pub(7)[1:]
    # Pure known-public output derivation; witness 01 is not a valid signature.
    xonly = send((Input(PREV, 0, sender_script, witness=(b"\x01",), secret=7),),
                 (account.payment_code(),))[0]
    server.silent_payment = {
        "txid": PAYTX,
        "vin": [{"txid": PREV, "vout": 0,
                 "prevout": {"scriptPubKey": {"hex": sender_script.hex()}},
                 "scriptSig": {"hex": ""}, "txinwitness": ["01"]}],
        "vout": [{"n": 0, "value": 0.002,
                  "scriptPubKey": {"hex": "5120" + xonly.hex()}}],
    }
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    passed = _CaseProgress()
    session = None
    try:
        with TemporaryDirectory(prefix="actual-adapter-public-regtest-") as name:
            directory = Path(name)
            provision_encrypted_scan_backup(directory, envelope)
            def open_session():
                return runtime.open(directory, password, user_consented=True)
            def rpc(mempool=False):
                return Wsp1ScannerOnlyRpc(
                    LocalRegtestEndpoint("127.0.0.1", server.server_port),
                    ExplicitRpcAuth("synthetic", "NO_REAL_CREDENTIAL"),
                    include_mempool=mempool,
                )

            before = len(server.observed_methods)
            _denied(lambda: runtime.open(directory, password, user_consented=False),
                    "APP_QUALIFIED_SCAN_SCOPE_DENIED")
            _denied(lambda: runtime.open(directory, b"wrong-public-password", user_consented=True),
                    "APP_QUALIFIED_SCAN_OPEN_DENIED")
            assert len(server.observed_methods) == before
            passed.append("ACTUAL_AUTHENTICATED_BACKUP_DENIAL_NO_RPC")

            session = open_session()
            address = session.receive_code(user_consented=True)
            assert address.code == account.payment_code()
            assert address.namespace == "wamrtsp-draft-regtest"
            assert not (address.wallet_operational or address.signer_enabled
                        or address.broadcast_allowed or address.mainnet_allowed)
            assert len(server.observed_methods) == before
            passed.append("ACTUAL_SCAN_ONLY_OPEN_RECEIVE_NO_KEYRING")

            _denied(lambda: session.snapshot(user_consented=True),
                    "APP_QUALIFIED_SCAN_NOT_CURRENT")
            assert session.closed
            session = open_session()
            receipt = session.scan(rpc(), user_consented=True)
            assert receipt.tip_height == 1 and receipt.blocks_processed == 1
            assert receipt.confirmed_utxo_count == 0 and receipt.unqualified_confirmed_atoms == 0
            passed.append("ACTUAL_INITIAL_SCAN_STORE_PROJECTION")

            server.height = 2
            server.tip = PAYTIP
            partial_dir = directory / "partial-batch"
            partial_dir.mkdir(mode=0o700)
            provision_encrypted_scan_backup(partial_dir, envelope)
            partial_session = runtime.open(partial_dir, password, user_consented=True)
            try:
                partial = partial_session.scan(rpc(), user_consented=True, max_blocks=1)
                assert partial.tip_height == 1 and partial.blocks_processed == 1
                assert not partial.chain_current and partial.confirmed_utxo_count is None
                assert partial.unqualified_confirmed_atoms is None and partial.history_count is None
                assert not partial_session.closed
                progress = partial_session.snapshot(user_consented=True)
                assert not progress.chain_current and progress.unqualified_confirmed_atoms is None
                current = partial_session.scan(rpc(), user_consented=True, max_blocks=1)
                assert current.chain_current and current.tip_height == 2
                assert current.confirmed_utxo_count == 1 and current.unqualified_confirmed_atoms == 200_000
            finally:
                partial_session.close()
            passed.append("ACTUAL_PARTIAL_BATCH_PROGRESS_WITHOUT_STALE_BALANCE")
            receipt = session.scan(rpc(), user_consented=True)
            assert receipt.blocks_processed == 1 and receipt.transactions_processed == 2
            assert receipt.confirmed_utxo_count == 1 and receipt.unqualified_confirmed_atoms == 200_000
            assert receipt.history_count == 1 and receipt.tip_height == 2
            passed.append("ACTUAL_INCREMENTAL_PUBLIC_PAYMENT_DETECTED")

            # Real upstream WSP SQLite projection reaches the actual REGTEST Qt
            # workspace through an explicit non-authorizing review interface.
            from PySide6.QtCore import QCoreApplication, QEvent
            from PySide6.QtWidgets import QApplication
            from wam_privacy_wallet.gui.regtest_window import RegtestWindow
            qt_app = QApplication.instance() or QApplication([])
            window = RegtestWindow()
            try:
                window.controller.select_regtest()
                window.present_untrusted_scan_receipt(receipt, user_consented=True)
                label = window.scan_review_status.text()
                assert ("REVIEW_ONLY_UNTRUSTED" in label and "reported tip 2" in label
                        and "observed UTXOs 1 UNQUALIFIED" in label
                        and "200000" not in label and "NO VERIFIED CORE" in label)
                assert "NO WALLET LOADED" in window.authority_status.text()
                assert not window.controller.lifecycle.state.wallet_operational
                window.controller.cancel()
                assert window.scan_review_status.text() == "NO WSP-1 SCAN REVIEW"
            finally:
                window.close()
                window.deleteLater()
                QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
                QCoreApplication.processEvents()
            passed.append("ACTUAL_WSP_STORE_TO_REGTEST_QT_READONLY")

            repeat = session.scan(rpc(), user_consented=True)
            assert repeat.blocks_processed == 0 and repeat.confirmed_utxo_count == 1
            assert session.snapshot(user_consented=True).unqualified_confirmed_atoms == 200_000
            passed.append("ACTUAL_REPLAY_NOT_DUPLICATED")

            receipt = session.scan(rpc(True), user_consented=True, include_mempool=True)
            assert receipt.mempool_observed and receipt.mempool_transactions_processed == 1
            assert receipt.mempool_utxo_count == 0 and receipt.mempool_spend_count == 1
            assert receipt.unqualified_mempool_atoms == 0 and server.mempool_reads == 2
            passed.append("ACTUAL_MEMPOOL_STORE_PROJECTION")

            names = {item.name for item in fields(receipt)}
            assert not ({"password", "scan_secret", "accounts", "txid", "tweak", "scanner"} & names)
            for name in ("core_authenticated", "wallet_operational", "balance_qualified",
                         "signer_enabled", "broadcast_allowed", "mainnet_allowed"):
                assert getattr(receipt, name) is False
            passed.append("ACTUAL_RECEIPT_NO_SECRET_OR_AUTHORITY")

            session.close()
            session.close()
            session = open_session()
            _denied(lambda: session.snapshot(user_consented=True),
                    "APP_QUALIFIED_SCAN_NOT_CURRENT")
            assert session.closed
            session = open_session()
            receipt = session.scan(rpc(), user_consented=True)
            assert receipt.blocks_processed == 0 and receipt.confirmed_utxo_count == 1
            assert not receipt.mempool_observed and receipt.mempool_utxo_count is None
            assert receipt.unqualified_mempool_atoms is None and receipt.mempool_spend_count is None
            passed.append("ACTUAL_REOPEN_REATTEST_NO_CACHED_MEMPOOL")

            before_cancel = len(server.observed_methods)
            _denied(lambda: session.scan(rpc(), user_consented=True, cancelled=lambda: True),
                    "APP_QUALIFIED_SCAN_CANCELLED")
            assert session.closed and len(server.observed_methods) == before_cancel
            session = open_session()
            passed.append("ACTUAL_CANCEL_CLOSE_REOPEN_NO_RPC")

            tampered_dir = directory / "tampered-backup"
            tampered_dir.mkdir(mode=0o700)
            tampered = envelope[:-1] + bytes((envelope[-1] ^ 1,))
            provision_encrypted_scan_backup(tampered_dir, tampered)
            _denied(lambda: runtime.open(tampered_dir, password, user_consented=True),
                    "APP_QUALIFIED_SCAN_OPEN_DENIED")
            passed.append("ACTUAL_AES_GCM_TAMPER_DENIED")

            foreign_dir = directory / "foreign-account"
            foreign_dir.mkdir(mode=0o700)
            foreign_account = ScanAccount(0, 3, pub(4), birthday=1)
            provision_encrypted_scan_backup(foreign_dir, export_scan((foreign_account,), password))
            shutil.copyfile(directory / "scan-only-state.sqlite", foreign_dir / "scan-only-state.sqlite")
            (foreign_dir / "scan-only-state.sqlite").chmod(0o600)
            _denied(lambda: runtime.open(foreign_dir, password, user_consented=True),
                    "APP_QUALIFIED_SCAN_OPEN_DENIED")
            passed.append("ACTUAL_STORE_ACCOUNT_IDENTITY_MISMATCH_DENIED")

            server.tip = PAYTIP_FORK
            server.discard_payment = True
            receipt = session.scan(rpc(), user_consented=True)
            assert receipt.rollback_blocks == 1 and receipt.blocks_processed == 1
            assert receipt.confirmed_utxo_count == 0 and receipt.unqualified_confirmed_atoms == 0
            assert receipt.history_count == 0 and receipt.tip_height == 2
            passed.append("ACTUAL_REORG_STORE_AND_HISTORY_RECONCILED")

            before = len(server.observed_methods)
            _denied(lambda: SourceQualifiedScanRuntime(root, user_consented=True),
                    "APP_QUALIFIED_SCAN_PRELOADED_SOURCE_DENIED")
            assert len(server.observed_methods) == before and not server.violations
            passed.append("PRELOADED_RUNTIME_REJECTED_NO_RPC")
            session.close()
    finally:
        if session is not None:
            session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        sys.setprofile(None)
    expected = [
        "ACTUAL_AUTHENTICATED_BACKUP_DENIAL_NO_RPC",
        "ACTUAL_SCAN_ONLY_OPEN_RECEIVE_NO_KEYRING",
        "ACTUAL_INITIAL_SCAN_STORE_PROJECTION",
        "ACTUAL_PARTIAL_BATCH_PROGRESS_WITHOUT_STALE_BALANCE",
        "ACTUAL_INCREMENTAL_PUBLIC_PAYMENT_DETECTED",
        "ACTUAL_WSP_STORE_TO_REGTEST_QT_READONLY",
        "ACTUAL_REPLAY_NOT_DUPLICATED",
        "ACTUAL_MEMPOOL_STORE_PROJECTION",
        "ACTUAL_RECEIPT_NO_SECRET_OR_AUTHORITY",
        "ACTUAL_REOPEN_REATTEST_NO_CACHED_MEMPOOL",
        "ACTUAL_CANCEL_CLOSE_REOPEN_NO_RPC",
        "ACTUAL_AES_GCM_TAMPER_DENIED",
        "ACTUAL_STORE_ACCOUNT_IDENTITY_MISMATCH_DENIED",
        "ACTUAL_REORG_STORE_AND_HISTORY_RECONCILED",
        "PRELOADED_RUNTIME_REJECTED_NO_RPC",
    ]
    if passed != expected:
        raise RuntimeError("ACTUAL_SESSION_CASE_COUNT_DENIED")
    print("PINNED_RETAINED_APP_SESSION_OK 15/15; synthetic peer only; operational Core/WSP gates held")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True)
    args = parser.parse_args()
    try:
        run(Path(args.source_root))
    except Exception as error:
        # Only already-redacted adapter codes or a fixed class category; never
        # repr/tracebacks, password, path or arbitrary upstream exception text.
        category = "UNEXPECTED_TEST_FAILURE"
        if type(error) is QualifiedScanError:
            code = str(error)
            if code.startswith("APP_QUALIFIED_SCAN_") and all(
                    char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ_" for char in code):
                category = code
        elif type(error) is AssertionError:
            category = "TEST_ASSERTION_FAILURE"
        print("PINNED_RETAINED_APP_SESSION_FAILURE_CATEGORY=" + category, file=sys.stderr)
        print("PINNED_RETAINED_APP_SESSION_DENIED", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
