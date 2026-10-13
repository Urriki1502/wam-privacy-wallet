"""Genuine pinned WSP Wallet.propose+AES-GCM encode/decode using public test keys.

The HTTP peer is synthetic ONLY within this CI test process. The operational
manual-intent module never injects or selects this test server as a backend.
"""
from __future__ import annotations
import argparse
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading

from tools.ci_wsp1_scanner_loopback import (
    LocalSyntheticCoreShape, FORK, PREV, PAYTIP, PAYTX,
)
from wam_privacy_wallet.application.encrypted_scan_backup import provision_encrypted_scan_backup
from wam_privacy_wallet.application.regtest_manual_intent import create_manual_regtest_intent
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth

_SCAN = b"ONLY_PUBLIC_DISPOSABLE_SCAN_ACCOUNT_PASSPHRASE"
_INTENT = b"ONLY_PUBLIC_DISPOSABLE_INTENT_PASSPHRASE"


def worker() -> int:
    # The child process contains no imported upstream wam_sp modules.
    # SourceQualifiedScanRuntime verifies and imports them AFTER origin checks.
    data = json.load(sys.stdin)
    try:
        result = create_manual_regtest_intent(
            Path(data["source_root"]), Path(data["scan_dir"]),
            Path(data["output_dir"]), _SCAN, _INTENT,
            endpoint=LocalRegtestEndpoint("127.0.0.1", data["port"]),
            rpc_auth=ExplicitRpcAuth("disposable_fixture", "NO_REAL_CREDENTIAL"),
            recipient_code=data["recipient_code"], recipient_atoms=100_000,
            fee_atoms=1000, user_consented=True,
            acknowledge_unverified_binary=True,
        )
        assert result["status"] == "ENCRYPTED_WSP_INTENT_READY_FOR_SEPARATE_OFFLINE_SIGNER"
        assert not result["signer_executed"] and not result["broadcast_allowed"]
        assert result["input_count"] == 1 and result["fee_atoms"] == 1000
    except Exception:
        print("PINNED_WSP_ENCRYPTED_INTENT_CHILD_DENIED", file=sys.stderr)
        return 2
    print("PINNED_WSP_ENCRYPTED_INTENT_CHILD_OK")
    return 0


def parent(source_root: Path) -> int:
    if sys.platform != "linux" or not __debug__:
        raise RuntimeError("PINNED_WSP_INTENT_NATIVE_PLATFORM_DENIED")
    from wam_privacy_wallet.integrations.wsp1_source_closure import verify_wsp1_full_source_closure
    proof = verify_wsp1_full_source_closure(source_root)
    assert proof["pinned_commit"] == "ac55f13423620252bdbf848c7e8a280c3b84721e"
    from wam_sp.core import Input, pub, send
    from wam_sp.keystore import ScanAccount, export_scan
    from wam_sp.wallet import decode_request

    account = ScanAccount(0, 1, pub(2), birthday=1)
    encrypted_scan = export_scan((account,), _SCAN)
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalSyntheticCoreShape)
    server.tip = PAYTIP
    server.height = 2
    server.discard_payment = False
    server.observed_methods = []
    server.violations = []
    server.mempool_reads = 0
    server.flip_mempool_second = False
    server.bad_prevout = False
    sender_script = b"\x51\x20" + pub(7)[1:]
    derived = send((Input(PREV, 0, sender_script, witness=(b"\x01",), secret=7),),
                   (account.payment_code(),))[0]
    server.silent_payment = {
        "txid": PAYTX,
        "vin": [{"txid": PREV, "vout": 0,
                 "prevout": {"scriptPubKey": {"hex": sender_script.hex()}},
                 "scriptSig": {"hex": ""}, "txinwitness": ["01"]}],
        "vout": [{"n": 0, "value": 0.002,
                  "scriptPubKey": {"hex": "5120" + derived.hex()}}],
    }
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        with TemporaryDirectory(prefix="wsp-actual-manual-intent-") as tmp:
            root = Path(tmp)
            scan_dir = root / "scan"
            out = root / "offline"
            scan_dir.mkdir(mode=0o700)
            out.mkdir(mode=0o700)
            provision_encrypted_scan_backup(scan_dir, encrypted_scan)
            args = {
                "source_root": str(source_root),
                "scan_dir": str(scan_dir), "output_dir": str(out),
                "port": server.server_port,
                "recipient_code": account.payment_code(),
            }
            env = dict(os.environ)
            env["PYTHONPATH"] = "src"
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            child = subprocess.run(
                [sys.executable, "-B", "-m", "tools.ci_regtest_manual_intent_native",
                 "--worker"], input=json.dumps(args), text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=env, timeout=30,
            )
            assert child.returncode == 0, "PINNED_WSP_INTENT_CHILD_FAILED"
            assert child.stdout.strip() == "PINNED_WSP_ENCRYPTED_INTENT_CHILD_OK"
            data = (out / "wsp-intent-v1.enc").read_bytes()
            assert data.startswith(b"WAMSP02\x00")
            request = decode_request(data, _INTENT)
            assert len(request.intents) == 1 and request.intents[0].code == account.payment_code()
            assert request.intents[0].atoms == 100_000
            assert request.fee == 1000
            assert len(request.coins) == 1
            assert request.coins[0]["txid"] == PAYTX
            db = sqlite3.connect(scan_dir / "scan-only-state.sqlite")
            try:
                states = db.execute("SELECT state FROM reservations").fetchall()
                assert states == [("signed",)]
            finally:
                db.close()
            # No valid cryptographic data may be forged just by matching MAGIC.
            corrupted = data[:-1] + bytes((data[-1] ^ 1,))
            try:
                decode_request(corrupted, _INTENT)
            except Exception:
                pass
            else:
                raise AssertionError("PINNED_WSP_INTENT_TAMPER_ACCEPTED")
            assert not server.violations, "SYNTHETIC_PEER_RPC_SCOPE_VIOLATION"
            print("PINNED_WSP_REAL_WALLET_PROPOSE_AND_AESGCM_REQUEST_OK")
            print("PINNED_WSP_INTENT_CI_SYNTHETIC_PEER_ONLY_NO_CORE_E2E")
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--source-root", type=Path)
    p.add_argument("--worker", action="store_true")
    args = p.parse_args()
    if args.worker:
        return worker()
    if args.source_root is None:
        return 2
    try:
        return parent(args.source_root.resolve(strict=True))
    except Exception:
        print("PINNED_WSP_INTENT_NATIVE_DENIED", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
