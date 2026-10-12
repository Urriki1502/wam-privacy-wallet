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


class LocalSyntheticCoreShape(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        query = json.loads(body)
        method, params = query["method"], query["params"]
        state = self.server
        state.observed_methods.append(method)
        if method == "getblockhash":
            reply = WAM_REGTEST_GENESIS if params == [0] else state.tip
        elif method == "getblockcount":
            reply = 1
        elif method == "getbestblockhash":
            reply = state.tip
        elif method == "getblockchaininfo":
            reply = {"chain": "regtest", "pruned": False, "blocks": 1, "headers": 1,
                     "bestblockhash": state.tip}
        elif method == "getblock" and params == [state.tip, 3]:
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
    spec = importlib.util.find_spec("wam_sp")
    if (spec is None or not spec.submodule_search_locations
            or not Path(next(iter(spec.submodule_search_locations))).resolve()
                   .is_relative_to((source_root / "src").resolve())):
        raise RuntimeError("WSP1_IMPORTED_SOURCE_UNPINNED")

    # This is the actual pinned scanner and its real OS lock/SQLite store.
    from wam_sp.core import pub
    from wam_sp.keystore import ScanAccount
    from wam_sp.scanner import Scanner
    from wam_sp.watcher import GENESIS
    if GENESIS != WAM_REGTEST_GENESIS:
        raise RuntimeError("WSP1_GENESIS_MISMATCH")

    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalSyntheticCoreShape)
    server.tip = TIP
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
        with tempfile.TemporaryDirectory(prefix="wsp1-scan-regtest-fixture-") as d:
            path = Path(d)
            if os.name == "posix":
                assert path.stat().st_mode & 0o077 == 0
            scanner = Scanner(path / "synthetic-scan-only.sqlite", (account,))
            try:
                first_rpc = Wsp1ScannerOnlyRpc(endpoint, auth)
                stats = scanner.sync(first_rpc, max_blocks=1)
                if (stats.blocks != 1 or stats.transactions != 1
                        or not scanner.ready or scanner.store.tip() != (1, TIP)):
                    raise RuntimeError("WSP1_ACTUAL_SCANNER_SYNC_FAILED")
                print("WSP1_ACTUAL_SCANNER_LOCAL_SYNTHETIC_SYNC_PASS")

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
