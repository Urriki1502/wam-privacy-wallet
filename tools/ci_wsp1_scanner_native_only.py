"""Actual cross-platform WSP scanner ONLY on public loopback fixtures.

No Linux-only backup/checkpoint/anti-rollback component is qualified here.
The existing full Linux integration remains required and unchanged.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import importlib.metadata
import importlib.util
import struct
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer

from tools.ci_wsp1_scanner_loopback import (
    LocalSyntheticCoreShape, FORK, PREV, PAYTIP, PAYTIP_FORK, PAYTX,
)
from wam_privacy_wallet.integrations.wsp1_source_closure import verify_wsp1_full_source_closure
from wam_privacy_wallet.application.wsp_scan_coordinator import run_consented_wsp_scan, ApplicationScanError
from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import Wsp1ScannerOnlyRpc, WspScannerRpcError
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth


def _no_signer(frame,event,arg):
    if event!='call':return
    module=frame.f_globals.get('__name__','');name=frame.f_code.co_name
    if module.startswith(('wam_sp','coincurve')) and (name in (
        'sign','sign_schnorr','sign_spend','signed_single_input','finalize','finalized',
        'broadcast','export_signing_request','create_silent_wallet','spending_key')
        # core.prepare aggregates public transaction inputs for scanning; the
        # signer.prepare method is a distinct forbidden API.
        or (name=='prepare' and module!='wam_sp.core')
        or (name=='__init__' and frame.f_locals.get('self') is not None
            and type(frame.f_locals['self']).__name__ in ('Signer','Wallet','SilentWallet','Keyring','KeyRing'))):
        raise RuntimeError('WSP_NATIVE_SIGNER_DENIED')


def run(root):
    if not __debug__:raise RuntimeError('WSP_NATIVE_OPTIMIZED_TESTS_DENIED')
    if struct.calcsize('P')!=8 or sys.platform not in ('linux','darwin','win32'):
        raise RuntimeError('WSP_NATIVE_PLATFORM_UNQUALIFIED')
    proof=verify_wsp1_full_source_closure(root)
    if proof['pinned_commit']!='ac55f13423620252bdbf848c7e8a280c3b84721e':raise RuntimeError('WSP_NATIVE_SOURCE_DENIED')
    for package,version in (('coincurve','21.0.0'),('cryptography','50.0.0'),('pycryptodome','3.23.0')):
        if importlib.metadata.version(package)!=version:raise RuntimeError('WSP_NATIVE_DEPENDENCY_DENIED')
    spec=importlib.util.find_spec('wam_sp')
    if spec is None or Path(spec.origin).resolve()!=root/'src/wam_sp/__init__.py':raise RuntimeError('WSP_NATIVE_INSTALLED_SOURCE_DENIED')
    sys.setprofile(_no_signer)
    from wam_sp.core import Input,pub,send
    from wam_sp.keystore import ScanAccount
    from wam_sp.scanner import Scanner
    from PySide6.QtCore import QCoreApplication,QEvent
    from PySide6.QtWidgets import QApplication,QPushButton
    from wam_privacy_wallet.gui import MainWindow
    qt=QApplication.instance() or QApplication([])
    server=ThreadingHTTPServer(('127.0.0.1',0),LocalSyntheticCoreShape)
    server.tip=FORK;server.height=1;server.discard_payment=False
    server.observed_methods=[];server.violations=[];server.mempool_reads=0
    server.flip_mempool_second=False;server.bad_prevout=False
    account=ScanAccount(0,1,pub(2),birthday=1)
    # Upstream send() performs public-fixture BIP352 output derivation only.
    # It does not construct/sign a valid transaction or send any RPC.
    sender_script=b'\x51\x20'+pub(7)[1:]
    xonly=send((Input(PREV,0,sender_script,witness=(b'\x01',),secret=7),),(account.payment_code(),))[0]
    server.silent_payment={'txid':PAYTX,'vin':[{'txid':PREV,'vout':0,'prevout':{'scriptPubKey':{'hex':sender_script.hex()}},'scriptSig':{'hex':''},'txinwitness':['01']}], 'vout':[{'n':0,'value':0.002,'scriptPubKey':{'hex':'5120'+xonly.hex()}}]}
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    passed=[]
    try:
        rpc=lambda:Wsp1ScannerOnlyRpc(LocalRegtestEndpoint('127.0.0.1',server.server_port),ExplicitRpcAuth('synthetic','NO_REAL_CREDENTIAL'))
        with tempfile.TemporaryDirectory(prefix='public-native-scanner-') as temporary:
            path=Path(temporary)/'public-fixture.sqlite';scanner=Scanner(path,(account,))
            try:
                before=len(server.observed_methods)
                try:run_consented_wsp_scan(scanner,rpc(),user_consented=False,max_blocks=1)
                except ApplicationScanError:pass
                else:raise RuntimeError('WSP_NATIVE_CONSENT_BYPASS')
                assert len(server.observed_methods)==before
                passed.append('DENIED_CONSENT_NO_RPC')
                first=run_consented_wsp_scan(scanner,rpc(),user_consented=True,max_blocks=1)
                assert first.blocks_processed==1 and first.transactions_processed==1 and not scanner.coins()
                passed.append('ACTUAL_SCANNER_SQLITE_SYNC')
                server.height=2;server.tip=PAYTIP
                receipt=run_consented_wsp_scan(scanner,rpc(),user_consented=True,max_blocks=1)
                coins=scanner.coins()
                assert receipt.blocks_processed==1 and len(coins)==1 and coins[0]['txid']==PAYTX and coins[0]['atoms']==200000
                assert not (receipt.wallet_operational or receipt.signer_enabled or receipt.broadcast_allowed or receipt.mainnet_allowed)
                passed.append('ACTUAL_PUBLIC_BIP352_MATCH')
                replay=run_consented_wsp_scan(scanner,rpc(),user_consented=True,max_blocks=1)
                assert replay.blocks_processed==0 and len(scanner.coins())==1
                passed.append('ACTUAL_REPLAY_NOT_DUPLICATED')
                window=MainWindow()
                try:
                    window.present_wsp_scan_session_summary(receipt)
                    assert 'tx 2' in window.wsp_session_status.text() and 'UNTRUSTED CORE' in window.wsp_session_status.text()
                    assert window.session_status.text()=='NO WALLET LOADED' and window.findChildren(QPushButton)==[]
                finally:
                    window.close();window.deleteLater()
                    QCoreApplication.sendPostedEvents(None,QEvent.Type.DeferredDelete);QCoreApplication.processEvents()
                passed.append('ACTUAL_SCANNER_TO_QT_NO_AUTHORITY')
                read=rpc();before=len(server.observed_methods)
                for method in ('sendrawtransaction','getwalletinfo','stop'):
                    try:read.call(method,[])
                    except WspScannerRpcError:pass
                    else:raise RuntimeError('WSP_NATIVE_WRITE_RPC_ACCEPTED')
                assert len(server.observed_methods)==before and not server.violations
                passed.append('WRITE_RPC_DENIED_BEFORE_WIRE')
                scanner.close();scanner=Scanner(path,(account,))
                assert not scanner.ready and not scanner.mempool_ready
                repeat=run_consented_wsp_scan(scanner,rpc(),user_consented=True,max_blocks=1)
                assert repeat.blocks_processed==0 and len(scanner.coins())==1
                passed.append('ACTUAL_SQLITE_REOPEN_REATTEST')
                server.tip=PAYTIP_FORK;server.discard_payment=True
                undo=run_consented_wsp_scan(scanner,rpc(),user_consented=True,max_blocks=1)
                assert undo.rollback_blocks==1 and undo.blocks_processed==1 and not scanner.coins()
                assert scanner.store.tip()==(2,PAYTIP_FORK)
                passed.append('ACTUAL_SYNTHETIC_REORG_UNDO')
            finally:scanner.close()
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5);sys.setprofile(None)
    expected=['DENIED_CONSENT_NO_RPC','ACTUAL_SCANNER_SQLITE_SYNC','ACTUAL_PUBLIC_BIP352_MATCH','ACTUAL_REPLAY_NOT_DUPLICATED','ACTUAL_SCANNER_TO_QT_NO_AUTHORITY','WRITE_RPC_DENIED_BEFORE_WIRE','ACTUAL_SQLITE_REOPEN_REATTEST','ACTUAL_SYNTHETIC_REORG_UNDO']
    if passed!=expected:raise RuntimeError('WSP_NATIVE_CASE_COUNT_DENIED')
    for name in passed:print('ACTUAL_NATIVE_WSP_'+name+'_PASS')
    print(f'ACTUAL_NATIVE_WSP_X64_OK {sys.platform}; 8/8; synthetic-only; no Core/recovery/sign/send qualification')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source-root',required=True);args=parser.parse_args()
    try:
        root=Path(args.source_root)
        if not root.is_absolute() or root.is_symlink():raise ValueError
        run(root.resolve())
    except Exception:
        print('WSP_NATIVE_PUBLIC_SCANNER_DENIED',file=sys.stderr);return 2
    return 0


if __name__=='__main__':raise SystemExit(main())
