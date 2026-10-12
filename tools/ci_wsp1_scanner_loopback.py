"""CI-only actual pinned WSP-1 Scanner.sync against a disposable local RPC peer.

The local peer is SYNTHETIC, never WAM Core. Only this test runner imports
external WSP-1 after the pinned source/commit has been separately checked.
Generated test account secrets and sqlite DB stay in an ephemeral private dir.
No transaction send, mainnet, real funds, Core process or production wallet.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tools.wsp1_pinned_surface import PINNED_COMMIT, verify_pinned_wsp1_sources
from tools.wsp1_full_source_closure import verify_wsp1_full_source_closure
from wam_privacy_wallet.application.wsp_scan_coordinator import (
    ApplicationScanError, run_consented_wsp_scan,
)
from wam_privacy_wallet.application.scan_only_account_session import (
    ScanOnlySessionError, run_disposable_scan_only_backup,
)
from wam_privacy_wallet.application.scan_preview_workflow import (
    ScanPreviewError, run_disposable_scan_preview,
)
from wam_privacy_wallet.application.encrypted_scan_backup import (
    EncryptedScanBackupError, provision_encrypted_scan_backup,
    load_encrypted_scan_backup,
)
from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import (
    Wsp1ScannerOnlyRpc, WspScannerRpcError,
)
from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth

TIP = "a" * 64
FORK = "b" * 64
COINBASE = "c" * 64
MEMTX = "e" * 64
PREV = "f" * 64
PAYTIP = "9" * 64
PAYTIP_FORK = "6" * 64
PAYTX = "8" * 64
COINBASE2 = "7" * 64


class LocalSyntheticCoreShape(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        query = json.loads(body)
        method, params = query["method"], query["params"]
        state = self.server
        state.observed_methods.append(method)
        if method == "getblockhash":
            reply = (WAM_REGTEST_GENESIS if params == [0]
                     else state.tip if params == [state.height]
                     else FORK if state.height == 2 and params == [1]
                     else "invalid-hash")
        elif method == "getblockcount":
            reply = state.height
        elif method == "getbestblockhash":
            reply = state.tip
        elif method == "getblockchaininfo":
            reply = {"chain": "regtest", "pruned": False,
                     "blocks": state.height, "headers": state.height,
                     "bestblockhash": state.tip}
        elif method == "getblock" and params == [state.tip, 3]:
            if state.height == 2:
                txs = [{
                    "txid": COINBASE2, "vin": [{"coinbase": "0202"}],
                    "vout": [{"n": 0, "value": 0.01,
                              "scriptPubKey": {"hex": "51"}}],
                }]
                if not state.discard_payment:
                    txs.append(state.silent_payment)
                reply = {"hash": state.tip, "height": 2,
                         "previousblockhash": FORK, "tx": txs}
            else:
                reply = {
                    "hash": state.tip, "height": 1,
                    "previousblockhash": WAM_REGTEST_GENESIS,
                    "tx": [{
                        "txid": COINBASE, "vin": [{"coinbase": "0101"}],
                        "vout": [{"n": 0, "value": 0.01,
                                  "scriptPubKey": {"hex": "51"}}],
                    }],
                }
        elif method == "getrawmempool" and params == []:
            state.mempool_reads += 1
            reply = ([] if state.flip_mempool_second
                     and state.mempool_reads == 2 else [MEMTX])
        elif method == "getrawtransaction" and params == [MEMTX, 2]:
            reply = {
                "txid": MEMTX, "vin": [{"txid": PREV, "vout": 0}],
                "vout": [{"n": 0, "value": 0.001,
                          "scriptPubKey": {"hex": "51"}}],
            }
        elif method == "getrawtransaction" and params == [PREV, 1]:
            reply = {
                "txid": MEMTX if state.bad_prevout else PREV,
                "vin": [{"coinbase": "0101"}],
                "vout": [{"n": 0, "value": 0.01,
                          "scriptPubKey": {"hex": "51"}}],
            }
        else:
            state.violations.append(method)
            self.send_error(403)
            return
        payload = json.dumps({"id": 1, "error": None, "result": reply},
                             separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass


def _run(source_root: Path) -> None:
    if sys.platform != "linux":
        raise RuntimeError("WSP1_SYNTHETIC_LINUX_ONLY")
    # Check 4 immutable pinned WSP source blobs *before* importing any WSP.
    result = verify_pinned_wsp1_sources(source_root)
    if (result["upstream_commit_sha"] != PINNED_COMMIT
            or result["scanner_enabled"] is not False
            or result["wallet_read_rpc_missing"] !=
               ["getblock", "getrawmempool", "getrawtransaction"]):
        raise RuntimeError("WSP1_SOURCE_POLICY_DENIED")
    closure = verify_wsp1_full_source_closure(source_root)
    if (closure["pinned_commit"] != PINNED_COMMIT
            or closure["status"] != "WSP1_FULL_SOURCE_CLOSURE_VERIFIED_NO_AUTHORITY"
            or closure["scanner_enabled"] is not False
            or closure["python_modules_verified"] < 8):
        raise RuntimeError("WSP1_IMPORT_CLOSURE_UNQUALIFIED")
    print("WSP1_FULL_IMPORT_SOURCE_CLOSURE_PASS")

    spec = importlib.util.find_spec("wam_sp")
    if (spec is None or not spec.submodule_search_locations
            or not Path(next(iter(spec.submodule_search_locations))).resolve()
                   .is_relative_to((source_root / "src").resolve())):
        raise RuntimeError("WSP1_IMPORTED_SOURCE_UNPINNED")

    # This is the actual pinned scanner and its real OS lock/SQLite store.
    from wam_sp.core import Input, pub, send
    from wam_sp.keystore import ScanAccount, export_scan, import_scan
    from wam_sp.scanner import Scanner
    from wam_sp.watcher import GENESIS
    if GENESIS != WAM_REGTEST_GENESIS:
        raise RuntimeError("WSP1_GENESIS_MISMATCH")

    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalSyntheticCoreShape)
    server.tip = TIP
    server.height = 1
    server.discard_payment = False
    server.silent_payment = None
    server.observed_methods = []
    server.violations = []
    server.mempool_reads = 0
    server.flip_mempool_second = False
    server.bad_prevout = False
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        endpoint = LocalRegtestEndpoint("127.0.0.1", server.server_port)
        auth = ExplicitRpcAuth("synthetic", "NO_REAL_CREDENTIAL")
        account = ScanAccount(0, 1, pub(2), birthday=1)

        # A deterministic BIP352 SEND and RECEIVE pair generated by the real
        # pinned WSP core. These are disposable integer TEST scalars, not a
        # wallet seed, spending key service or valid consensus transaction.
        sender_secret = 7
        sender_script = b"\x51\x20" + pub(sender_secret)[1:]
        sender_input = Input(
            PREV, 0, sender_script,
            witness=(b"\x01",), secret=sender_secret,
        )
        xonly = send((sender_input,), (account.payment_code(),))[0]
        if len(xonly) != 32:
            raise RuntimeError("WSP1_SYNTHETIC_SEND_FAILED")
        server.silent_payment = {
            "txid": PAYTX,
            "vin": [{
                "txid": PREV, "vout": 0,
                "prevout": {"scriptPubKey": {"hex": sender_script.hex()}},
                "scriptSig": {"hex": ""},
                "txinwitness": ["01"],
            }],
            "vout": [{
                "n": 0, "value": 0.002,
                "scriptPubKey": {"hex": "5120" + xonly.hex()},
            }],
        }
        with tempfile.TemporaryDirectory(prefix="wsp1-scan-regtest-fixture-") as d:
            path = Path(d)
            if os.name == "posix":
                assert path.stat().st_mode & 0o077 == 0
            scanner = Scanner(path / "synthetic-scan-only.sqlite", (account,))
            try:
                first_rpc = Wsp1ScannerOnlyRpc(endpoint, auth)
                # The production APP coordinator (not a CI-only mock)
                # must refuse to access even a real WSP scanner without
                # explicit consent; no RPC should hit the synthetic peer.
                seen_before = len(server.observed_methods)
                try:
                    run_consented_wsp_scan(
                        scanner, first_rpc, user_consented=False, max_blocks=1,
                    )
                except ApplicationScanError as error:
                    if str(error) != "APP_WSP_SCAN_INPUT_DENIED":
                        raise
                else:
                    raise RuntimeError("WSP1_APP_SCAN_CONSENT_BYPASS")
                if len(server.observed_methods) != seen_before:
                    raise RuntimeError("WSP1_APP_SCAN_DENIED_SENT_RPC")

                stats = run_consented_wsp_scan(
                    scanner, first_rpc, user_consented=True, max_blocks=1,
                )
                if (stats.blocks_processed != 1
                        or stats.transactions_processed != 1
                        or stats.rollback_blocks != 0
                        or stats.status != "WSP1_SCAN_EXECUTED_UNTRUSTED_CORE"
                        or stats.wallet_operational is not False
                        or stats.signer_enabled is not False
                        or stats.broadcast_allowed is not False
                        or not scanner.ready or scanner.store.tip() != (1, TIP)):
                    raise RuntimeError("WSP1_ACTUAL_APP_SCANNER_SYNC_FAILED")
                print("WSP1_ACTUAL_APP_COORDINATOR_CONSENT_SYNC_PASS")
                print("WSP1_ACTUAL_SCANNER_LOCAL_SYNTHETIC_SYNC_PASS")

                # Actual pinned AES-GCM scan-only export/import + new genuine
                # WSP Scanner/SQLite session, in a freshly discarded temp
                # workspace. Never import Keyring or a spend-key backup.
                test_password = b"native-disposable-regtest-only"
                envelope = export_scan((account,), test_password)
                pre_denial = len(server.observed_methods)
                try:
                    run_disposable_scan_only_backup(
                        envelope, b"wrong-native-test-password",
                        import_scan=import_scan, scanner_factory=Scanner,
                        rpc=Wsp1ScannerOnlyRpc(endpoint, auth),
                        user_consented=True,
                    )
                except ScanOnlySessionError as exc:
                    if str(exc) != "APP_SCAN_ONLY_RUNTIME_DENIED":
                        raise
                else:
                    raise RuntimeError("WSP1_INVALID_SCAN_ENVELOPE_ACCEPTED")
                if len(server.observed_methods) != pre_denial:
                    raise RuntimeError("WSP1_BAD_SCAN_BACKUP_SENT_WIRE")

                intake = run_disposable_scan_only_backup(
                    envelope, test_password,
                    import_scan=import_scan, scanner_factory=Scanner,
                    rpc=Wsp1ScannerOnlyRpc(endpoint, auth),
                    user_consented=True, max_blocks=1,
                )
                if (intake.blocks_processed != 1
                        or intake.transactions_processed != 1
                        or intake.status != "WSP1_SCAN_EXECUTED_UNTRUSTED_CORE"
                        or intake.wallet_operational is not False
                        or intake.signer_enabled is not False
                        or intake.mainnet_allowed is not False):
                    raise RuntimeError("WSP1_REAL_SCAN_ONLY_INTAKE_FAILED")
                print("WSP1_REAL_ENCRYPTED_SCAN_ONLY_DISPOSABLE_INTAKE_PASS")

                # Persistent ciphertext (NOT SQLite/account plaintext) must
                # survive a simulated process restart. Real pinned WSP-1
                # export/import performs AES-GCM authentication after reload.
                private_backup = path / "scan-only-encrypted-vault"
                private_backup.mkdir(mode=0o700)
                provision_encrypted_scan_backup(private_backup, envelope)
                saved = load_encrypted_scan_backup(private_backup)
                if saved != envelope:
                    raise RuntimeError("WSP1_BACKUP_VAULT_ROUNDTRIP_DENIED")
                # Simulate restart by reloading only opaque ciphertext and
                # creating a distinct real scanner/SQLite in a new temp dir.
                recovered = run_disposable_scan_only_backup(
                    saved, test_password,
                    import_scan=import_scan, scanner_factory=Scanner,
                    rpc=Wsp1ScannerOnlyRpc(endpoint, auth),
                    user_consented=True, max_blocks=1,
                )
                if (recovered.blocks_processed != 1
                        or recovered.wallet_operational is not False
                        or recovered.signer_enabled is not False):
                    raise RuntimeError("WSP1_BACKUP_RESTART_SCAN_DENIED")
                before_tamper = len(server.observed_methods)
                backup_file = private_backup / "scan-only.wsp.enc"
                corrupted = bytearray(backup_file.read_bytes())
                corrupted[-1] ^= 0x01
                backup_file.write_bytes(corrupted)
                try:
                    run_disposable_scan_only_backup(
                        load_encrypted_scan_backup(private_backup), test_password,
                        import_scan=import_scan, scanner_factory=Scanner,
                        rpc=Wsp1ScannerOnlyRpc(endpoint, auth),
                        user_consented=True, max_blocks=1,
                    )
                except ScanOnlySessionError:
                    pass
                else:
                    raise RuntimeError("WSP1_BACKUP_TAMPER_ACCEPTED")
                if len(server.observed_methods) != before_tamper:
                    raise RuntimeError("WSP1_TAMPER_SENT_RPC")
                print("WSP1_ENCRYPTED_SCAN_BACKUP_RESTART_AESGCM_PASS")
                print("WSP1_ENCRYPTED_SCAN_BACKUP_TAMPER_NO_RPC_PASS")

                # Actual pinned encrypted account import + WSP-1 Scanner.sync
                # + native SQLite + offscreen Qt MainWindow. No GUI scan keys.
                os.environ["QT_QPA_PLATFORM"] = "offscreen"
                from PySide6.QtCore import QCoreApplication, QEvent
                from PySide6.QtWidgets import QApplication, QPushButton
                from wam_privacy_wallet.gui import MainWindow
                app = QApplication.instance() or QApplication([])
                window = MainWindow()
                print("WSP1_QT_OFFSCREEN_WINDOW_INIT_PASS")
                try:
                    try:
                        result_gui = run_disposable_scan_preview(
                        envelope, test_password,
                        import_scan=import_scan, scanner_factory=Scanner,
                        rpc=Wsp1ScannerOnlyRpc(endpoint, auth),
                        user_consented=True, max_blocks=1,
                        clear_preview=window.clear_offline_presentation,
                        present_preview=window.present_wsp_scan_session_summary,
                        )
                    except ScanPreviewError as preview_error:
                        # Only fixed, locally defined denial vocabulary.
                        print("WSP1_QT_PREVIEW_" + str(preview_error),
                              file=sys.stderr)
                        raise
                    print("WSP1_QT_APP_WORKFLOW_EXECUTED_PASS")
                    if (result_gui.blocks_processed != 1
                            or result_gui.transactions_processed != 1
                            or result_gui.wallet_operational is not False
                            or "WSP-1 SCAN EXECUTED" not in
                            window.wsp_session_status.text()
                            or "NO VALIDATED CORE" not in
                            window.wsp_session_notice.text()
                            or window.session_status.text() != "NO WALLET LOADED"
                            or window.findChildren(QPushButton)):
                        raise RuntimeError("WSP1_REAL_SCAN_TO_QT_GUI_DENIED")
                    print("WSP1_REAL_SCANNER_SQLITE_TO_QT_GUI_PASS")
                    before_bad = len(server.observed_methods)
                    try:
                        run_disposable_scan_preview(
                            envelope, b"incorrect-test-password",
                            import_scan=import_scan, scanner_factory=Scanner,
                            rpc=Wsp1ScannerOnlyRpc(endpoint, auth),
                            user_consented=True,
                            clear_preview=window.clear_offline_presentation,
                            present_preview=window.present_wsp_scan_session_summary,
                        )
                    except ScanPreviewError as exc:
                        if str(exc) != "APP_SCAN_PREVIEW_SCAN_DENIED":
                            raise
                    else:
                        raise RuntimeError("WSP1_GUI_WRONG_PASSWORD_ACCEPTED")
                    if (len(server.observed_methods) != before_bad
                            or window.wsp_session_status.text() !=
                            "NO WSP-1 APPLICATION SCAN RECEIPT"):
                        raise RuntimeError("WSP1_GUI_FAILURE_STALE_RECEIPT")
                    print("WSP1_REAL_SCAN_GUI_FAILURE_CLEAR_PASS")
                finally:
                    window.close()
                    window.deleteLater()
                    QCoreApplication.sendPostedEvents(
                        None, QEvent.Type.DeferredDelete
                    )
                    QCoreApplication.processEvents()

                # A retained old RPC session cannot silently follow a fork.
                server.tip = FORK
                try:
                    first_rpc.call("getblockcount")
                except WspScannerRpcError as exc:
                    if str(exc) != "WSP_SCAN_CHAIN_DRIFT":
                        raise
                else:
                    raise RuntimeError("WSP1_STALE_RPC_ACCEPTED")

                # A NEW explicit local read session can make the upstream
                # Scanner.sync perform real SQLite rollback/reorg bookkeeping.
                second_rpc = Wsp1ScannerOnlyRpc(endpoint, auth)
                fork_stats = scanner.sync(second_rpc, max_blocks=1)
                if (fork_stats.rollback != 1 or fork_stats.blocks != 1
                        or scanner.store.tip() != (1, FORK)
                        or not scanner.ready):
                    raise RuntimeError("WSP1_NATIVE_REORG_FAILED")
                print("WSP1_ACTUAL_SCANNER_LOCAL_SYNTHETIC_REORG_PASS")

                # Genuine pinned WSP scanner parses mempool tx/prevout via
                # our real localhost scanner-only RPC and real SQLite store.
                mempool_rpc = Wsp1ScannerOnlyRpc(
                    endpoint, auth, include_mempool=True,
                )
                count = scanner.sync_mempool(mempool_rpc)
                rows = [
                    tuple(r) for r in scanner.store.db.execute(
                        "SELECT txid,vout,spending FROM mempool_spends"
                    )
                ]
                if (count != 1 or rows != [(PREV, 0, MEMTX)]
                        or scanner.mempool_ready is not True
                        or server.mempool_reads != 2):
                    raise RuntimeError("WSP1_NATIVE_MEMPOOL_SYNC_FAILED")
                print("WSP1_ACTUAL_SCANNER_LOCAL_SYNTHETIC_MEMPOOL_PASS")

                # Default session's mempool lookup must fail before socket.
                before = len(server.observed_methods)
                try:
                    second_rpc.call("getrawtransaction", [MEMTX, 2])
                except WspScannerRpcError as exc:
                    if str(exc) != "WSP_SCAN_MEMPOOL_DENIED":
                        raise
                else:
                    raise RuntimeError("WSP1_DEFAULT_MEMPOOL_SCOPE_WIDENED")
                if len(server.observed_methods) != before:
                    raise RuntimeError("WSP1_MEMPOOL_SCOPE_SENT_WIRE")

                # The real upstream SQLite transaction must roll back if a
                # peer changes mempool membership before the second read.
                server.mempool_reads = 0
                server.flip_mempool_second = True
                try:
                    scanner.sync_mempool(Wsp1ScannerOnlyRpc(
                        endpoint, auth, include_mempool=True,
                    ))
                except ValueError as exc:
                    if str(exc) != "MEMPOOL_CHANGED_RETRY":
                        raise
                else:
                    raise RuntimeError("WSP1_MEMPOOL_CHANGE_ACCEPTED")
                if ([tuple(r) for r in scanner.store.db.execute(
                        "SELECT txid,vout,spending FROM mempool_spends"
                    )] != rows or scanner.mempool_ready):
                    raise RuntimeError("WSP1_MEMPOOL_ROLLBACK_NOT_ATOMIC")
                print("WSP1_ACTUAL_SCANNER_LOCAL_SYNTHETIC_MEMPOOL_ROLLBACK_PASS")

                # A wrong prevout identity must also preserve the previously
                # committed scanner snapshot, with no partial writes.
                server.flip_mempool_second = False
                server.bad_prevout = True
                try:
                    scanner.sync_mempool(Wsp1ScannerOnlyRpc(
                        endpoint, auth, include_mempool=True,
                    ))
                except WspScannerRpcError as exc:
                    if str(exc) != "WSP_SCAN_REPLY_DENIED":
                        raise
                else:
                    raise RuntimeError("WSP1_FORGED_PREVOUT_ACCEPTED")
                if ([tuple(r) for r in scanner.store.db.execute(
                        "SELECT txid,vout,spending FROM mempool_spends"
                    )] != rows or scanner.mempool_ready):
                    raise RuntimeError("WSP1_FORGED_PREVOUT_ROLLBACK_FAILED")
                print("WSP1_ACTUAL_SCANNER_LOCAL_SYNTHETIC_PREVOUT_DENIED_PASS")

                # Simulate a real application restart. A stored chain tip and
                # previous mempool snapshot MUST NOT bootstrap fresh scan
                # authority: WSP Scanner.ready always starts false.
                db_path = path / "synthetic-scan-only.sqlite"
                scanner.close()
                scanner = Scanner(db_path, (account,))
                if scanner.ready or scanner.mempool_ready:
                    raise RuntimeError("WSP1_RESTART_STALE_AUTHORITY")
                try:
                    scanner.assert_current()
                except ValueError as exc:
                    if str(exc) != "SCAN_NOT_CURRENT":
                        raise
                else:
                    raise RuntimeError("WSP1_RESTART_MISSING_REATTEST_GATE")
                if (scanner.store.tip() != (1, FORK)
                        or [tuple(row) for row in scanner.store.db.execute(
                            "SELECT txid,vout,spending FROM mempool_spends"
                        )] != rows):
                    raise RuntimeError("WSP1_RESTART_SNAPSHOT_CHANGED")
                print("WSP1_ACTUAL_SCANNER_PERSISTED_BUT_NOT_TRUSTED_PASS")

                # Revalidation on a NEW RPC session must not replay block #1
                # or duplicate the mempool's persisted spent outpoint.
                server.flip_mempool_second = False
                server.bad_prevout = False
                server.mempool_reads = 0
                fresh_session = Wsp1ScannerOnlyRpc(endpoint, auth)
                replay = scanner.sync(fresh_session, max_blocks=1)
                if (replay.blocks != 0 or replay.transactions != 0
                        or scanner.store.tip() != (1, FORK)
                        or scanner.ready is not True):
                    raise RuntimeError("WSP1_RESTART_IDEMPOTENT_RESCAN_FAILED")
                resumable_mempool = Wsp1ScannerOnlyRpc(
                    endpoint, auth, include_mempool=True,
                )
                if (scanner.sync_mempool(resumable_mempool) != 1
                        or [tuple(row) for row in scanner.store.db.execute(
                            "SELECT txid,vout,spending FROM mempool_spends"
                        )] != rows or scanner.mempool_ready is not True):
                    raise RuntimeError("WSP1_RESTART_MEMPOOL_REPLAY_FAILED")
                print("WSP1_ACTUAL_SCANNER_RESTART_REATTEST_IDEMPOTENT_PASS")

                # A different account cannot reuse the original scan-state
                # database, even if its chain tip is identical.
                from wam_sp.errors import StorageError
                different = ScanAccount(0, 2, pub(3), birthday=1)
                try:
                    forbidden_store = Scanner(db_path, (different,))
                except StorageError as exc:
                    if str(exc) != "STATE_WALLET_MISMATCH_RESCAN_REQUIRED":
                        raise
                else:
                    forbidden_store.close()
                    raise RuntimeError("WSP1_FOREIGN_ACCOUNT_DATABASE_ACCEPTED")
                if (scanner.store.tip() != (1, FORK)
                        or not scanner.ready
                        or not scanner.mempool_ready):
                    raise RuntimeError("WSP1_ACCOUNT_MISMATCH_CHANGED_VALID_SESSION")
                print("WSP1_ACTUAL_SCANNER_FOREIGN_ACCOUNT_DB_DENIED_PASS")

                # Real pinned BIP352 derivation: a synthetic sender pays the
                # synthetic scan account on fake regtest height 2. The actual
                # upstream scanner must discover the matching P2TR output,
                # record one coin in SQLite, and never duplicate on re-scan.
                server.height = 2
                server.tip = PAYTIP
                payment_stats = run_consented_wsp_scan(
                    scanner, Wsp1ScannerOnlyRpc(endpoint, auth),
                    user_consented=True, max_blocks=1,
                )
                coins = scanner.coins()
                if (payment_stats.blocks_processed != 1
                        or payment_stats.transactions_processed != 2
                        or scanner.metrics.candidates != 1
                        or scanner.metrics.ecdh < 1
                        or len(coins) != 1
                        or coins[0]["txid"] != PAYTX
                        or coins[0]["atoms"] != 200_000
                        or coins[0]["account"] != account.account_id
                        or coins[0]["received"] != 2
                        or scanner.store.tip() != (2, PAYTIP)):
                    raise RuntimeError("WSP1_SYNTHETIC_SILENT_PAYMENT_NOT_DETECTED")
                print("WSP1_ACTUAL_SCANNER_SYNTHETIC_BIP352_RECEIVE_PASS")

                # Render actual BIP352 match statistics through the real App
                # DTO into the real Qt GUI. No address/txid/balance display.
                payment_window = MainWindow()
                payment_window.present_wsp_scan_session_summary(payment_stats)
                if ("tx 2" not in payment_window.wsp_session_status.text()
                        or "UNTRUSTED CORE" not in
                        payment_window.wsp_session_status.text()
                        or payment_window.session_status.text()
                        != "NO WALLET LOADED"):
                    raise RuntimeError("WSP1_BIP352_RECEIVE_QT_DISPLAY_DENIED")
                print("WSP1_REAL_BIP352_RECEIVE_TO_GUI_PASS")

                again = run_consented_wsp_scan(
                    scanner, Wsp1ScannerOnlyRpc(endpoint, auth),
                    user_consented=True, max_blocks=1,
                )
                if (again.blocks_processed != 0 or len(scanner.coins()) != 1
                        or scanner.store.tip() != (2, PAYTIP)):
                    raise RuntimeError("WSP1_SYNTHETIC_PAYMENT_DUPLICATED")
                print("WSP1_ACTUAL_SCANNER_SYNTHETIC_PAYMENT_REPLAY_PASS")
                payment_window.present_wsp_scan_session_summary(again)
                if "blocks 0" not in payment_window.wsp_session_status.text():
                    raise RuntimeError("WSP1_REPLAY_QT_RECEIPT_STALE")

                # Chain fork at the same height drops the payment. Upstream
                # Scanner.sync must genuinely UNDO the prior wallet coin and
                # commit only the new, payment-free synthetic block.
                server.tip = PAYTIP_FORK
                server.discard_payment = True
                undone = run_consented_wsp_scan(
                    scanner, Wsp1ScannerOnlyRpc(endpoint, auth),
                    user_consented=True, max_blocks=1,
                )
                if (undone.rollback_blocks != 1 or undone.blocks_processed != 1
                        or scanner.store.tip() != (2, PAYTIP_FORK)
                        or scanner.coins()):
                    raise RuntimeError("WSP1_SYNTHETIC_PAYMENT_REORG_NOT_UNDONE")
                print("WSP1_ACTUAL_SCANNER_SYNTHETIC_PAYMENT_REORG_UNDO_PASS")
                payment_window.present_wsp_scan_session_summary(undone)
                if ("reorg 1" not in payment_window.wsp_session_status.text()
                        or "NO VALIDATED CORE" not in
                        payment_window.wsp_session_notice.text()
                        or payment_window.session_status.text()
                        != "NO WALLET LOADED"
                        or payment_window.findChildren(QPushButton)):
                    raise RuntimeError("WSP1_REAL_REORG_QT_UI_CLAIM_DENIED")
                print("WSP1_REAL_BIP352_REORG_TO_GUI_PASS")
                payment_window.close()
                payment_window.deleteLater()
                QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
                QCoreApplication.processEvents()

                before = len(server.observed_methods)
                for forbidden in ("sendrawtransaction", "getwalletinfo", "stop"):
                    try:
                        second_rpc.call(forbidden, [])
                    except WspScannerRpcError as exc:
                        if str(exc) != "WSP_SCAN_METHOD_DENIED":
                            raise
                    else:
                        raise RuntimeError("WSP1_RPC_MUTATION_ADMITTED")
                if len(server.observed_methods) != before or server.violations:
                    raise RuntimeError("WSP1_FORBIDDEN_METHOD_SENT")
                print("WSP1_ACTUAL_SCANNER_WRITE_RPC_INTERLOCK_PASS")
            finally:
                scanner.close()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Actual pinned WSP scanner with synthetic LOCAL RPC, NEVER WAM Core")
    parser.add_argument("--source-root", required=True)
    args = parser.parse_args(argv)
    # CI logs must never print source paths, credentials, stack traces with
    # untrusted peer replies, or synthetic scan secret material.
    try:
        root = Path(args.source_root)
        if not root.is_absolute() or root.is_symlink():
            raise ValueError
        _run(root)
    except Exception:
        print("WSP1_ACTUAL_SCANNER_SYNTHETIC_INTEGRATION_DENIED", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
