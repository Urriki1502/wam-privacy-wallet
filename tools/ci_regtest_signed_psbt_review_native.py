"""Actual WSP Schnorr-signed PSBT cryptographic reviewer regression.

Disposable WSP Keyring/Signer in CI ONLY, funded by SYNTHETIC LOCAL RPC.
Not the approved isolated offline signer process; no Core execution, real
funds, broadcast, mainnet or executable provenance claims.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from http.server import ThreadingHTTPServer
from hashlib import sha256
import threading
from dataclasses import replace

from tools.ci_wsp1_scanner_loopback import (
    LocalSyntheticCoreShape, PREV, PAYTIP, PAYTX,
)
from wam_privacy_wallet.application.encrypted_scan_backup import (
    provision_encrypted_scan_backup,
)
from wam_privacy_wallet.application.offline_signed_psbt_review import (
    review_signed_regtest_psbt, SignedPsbtReviewError,
)

_SCAN = b"ONLY_PUBLIC_DISPOSABLE_SCAN_ACCOUNT_PASSPHRASE"
_INTENT = b"ONLY_PUBLIC_DISPOSABLE_INTENT_PASSPHRASE"


def run(source_root: Path) -> None:
    if sys.platform != "linux" or not __debug__:
        raise RuntimeError("WSP_PSBTV2_REVIEW_PLATFORM_DENIED")
    from wam_privacy_wallet.integrations.wsp1_source_closure import (
        verify_wsp1_full_source_closure,
    )
    proof = verify_wsp1_full_source_closure(source_root)
    assert proof["status"] == "WSP1_FULL_SOURCE_CLOSURE_VERIFIED_NO_AUTHORITY"
    from wam_sp.core import Input, pub, send
    from wam_sp.keystore import Keyring, export_scan
    from wam_sp.wallet import decode_request, Signer
    from wam_sp.psbt import PSBT

    keyring = Keyring(bytes(range(32)))  # disposable deterministic regtest only
    account = keyring.accounts()[0]
    scanner_backup = export_scan((account,), _SCAN)
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalSyntheticCoreShape)
    server.tip = PAYTIP
    server.height = 2
    server.discard_payment = False
    server.observed_methods = []
    server.violations = []
    server.mempool_reads = 0
    server.flip_mempool_second = False
    server.bad_prevout = False
    input_script = b"\x51\x20" + pub(7)[1:]
    derived = send((Input(PREV, 0, input_script, witness=(b"\x01",), secret=7),),
                   (account.payment_code(),))[0]
    server.silent_payment = {
        "txid": PAYTX,
        "vin": [{"txid": PREV, "vout": 0,
                 "prevout": {"scriptPubKey": {"hex": input_script.hex()}},
                 "scriptSig": {"hex": ""}, "txinwitness": ["01"]}],
        "vout": [{"n": 0, "value": 0.002,
                  "scriptPubKey": {"hex": "5120" + derived.hex()}}],
    }
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with TemporaryDirectory(prefix="wsp-real-signer-psbt-") as tmp:
            root = Path(tmp)
            scan = root / "scan"
            transfer = root / "transfer"
            scan.mkdir(mode=0o700)
            transfer.mkdir(mode=0o700)
            provision_encrypted_scan_backup(scan, scanner_backup)
            # This is the exact existing manual REGTEST app coordinator in a
            # fresh subprocess. No signer/Keyring can enter its memory.
            args = {
                "source_root": str(source_root),
                "scan_dir": str(scan),
                "output_dir": str(transfer),
                "port": server.server_port,
                "recipient_code": account.payment_code(),
            }
            env = dict(os.environ, PYTHONPATH="src", PYTHONDONTWRITEBYTECODE="1")
            proc = subprocess.run(
                [sys.executable, "-B", "-m",
                 "tools.ci_regtest_manual_intent_native", "--worker"],
                input=json.dumps(args), text=True, capture_output=True,
                env=env, timeout=35, check=False,
            )
            assert proc.returncode == 0, "SOURCE_QUALIFIED_INTENT_WORKER_DENIED"
            assert proc.stdout.strip() == "PINNED_WSP_ENCRYPTED_INTENT_CHILD_OK"
            request_file = transfer / "wsp-intent-v1.enc"
            encrypted = request_file.read_bytes()
            proposal = decode_request(encrypted, _INTENT)
            # This is an ephemeral signing REGRESSION ONLY, independent of
            # the wallet app and NOT a qualified offline signer deployment.
            signer = Signer(keyring)
            signed = signer.sign(signer.prepare(proposal),
                                 proposal.intents, proposal.fee)
            signed_psbt = PSBT.decode(signed)
            assert signed_psbt.finalize()  # real Schnorr/BIP352 verification
            file = transfer / "signed-psbt.b64"
            file.write_bytes(signed_psbt.base64().encode("ascii"))
            file.chmod(0o600)
            digest = sha256(encrypted).hexdigest()
            receipt = review_signed_regtest_psbt(
                source_root, request_file, file, _INTENT,
                expected_request_sha256=digest, user_consented=True,
            )
            assert receipt["status"] == "SEPARATE_SIGNER_PSBT_CRYPTO_VERIFIED_REVIEW_ONLY"
            assert receipt["signature_verified_by_upstream_parser"]
            assert receipt["input_count"] == 1 and receipt["recipient_count"] == 1
            assert receipt["fee_atoms"] == 1000
            assert receipt["change_output_present_unqualified"] is True
            assert not (receipt["wallet_operational"]
                        or receipt["broadcast_allowed"]
                        or receipt["core_binary_authenticated"]
                        or receipt["mainnet_allowed"])
            # Genuine upstream crypto rejects a deliberately corrupted
            # signature with unchanged transaction and encrypted intent.
            sig = signed_psbt.signatures[0]
            assert sig is not None
            bad = replace(signed_psbt,
                          signatures=(bytes([sig[0] ^ 1]) + sig[1:],))
            file.write_bytes(bad.base64().encode("ascii"))
            try:
                review_signed_regtest_psbt(
                    source_root, request_file, file, _INTENT,
                    expected_request_sha256=digest, user_consented=True,
                )
            except SignedPsbtReviewError as exc:
                assert str(exc) == "SIGNED_PSBT_REVIEW_DENIED"
            else:
                raise AssertionError("INVALID_SIGNATURE_ACCEPTED")
            assert not server.violations, "SYNTHETIC_RPC_SCOPE_VIOLATION"
            print("PINNED_WSP_SIGNED_PSBT_SIGNATURE_AND_INTENT_REVIEW_OK")
            print("WSP_SIGNED_REVIEW_SYNTHETIC_CHAIN_ONLY_NO_CORE_E2E_OR_SIGNER_ISOLATION")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source-root", type=Path, required=True)
    opts = p.parse_args()
    try:
        run(opts.source_root.resolve(strict=True))
    except Exception:
        print("PINNED_WSP_SIGNED_PSBT_REVIEW_DENIED", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
