"""Native public-fixture tests of actual exact-source HPKE; never Core/signing."""
from hashlib import sha1
import argparse
import json
from pathlib import Path
import subprocess
import unittest
from wam_privacy_wallet.application import selective_disclosure_review as app

ROOT = Path(__file__).resolve().parents[1]


def verify(root):
    pin = json.loads((ROOT/'native/hpke_readonly/upstream-source-blobs.json').read_bytes())
    if pin['source_commit'] != app._PIN: raise SystemExit('HPKE_SOURCE_PIN_DENIED')
    head=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD']).decode().strip()
    if head!=app._PIN: raise SystemExit('HPKE_SOURCE_HEAD_DENIED')
    for name, oid in pin['files'].items():
        path=root/name
        if path.is_symlink() or path.stat().st_size>1_000_000: raise SystemExit('HPKE_SOURCE_PATH_DENIED')
        data=path.read_bytes()
        if sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()!=oid:
            raise SystemExit('HPKE_SOURCE_BYTES_DENIED')
    crate=root/'prototypes/zk_balance_halo2'
    expected={str(root/name) for name in pin['files']}
    for path in crate.rglob('*.rs'):
        if 'target' not in path.relative_to(crate).parts and str(path) not in expected:
            raise SystemExit('HPKE_UNTRACKED_RUST_SOURCE_DENIED')
    print(f'PINNED_HPKE_RAW_SOURCE_OK {app._PIN}; {len(pin["files"])} blobs; no release/review authority')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source-root',required=True);parser.add_argument('--verify-only',action='store_true');parser.add_argument('--gui',action='store_true')
    args=parser.parse_args();verify(Path(args.source_root).resolve())
    if args.verify_only: return
    name='wam-wallet-hpke-readonly.exe' if app.sys.platform=='win32' else 'wam-wallet-hpke-readonly'
    exe=app._NATIVE/name; manifest=app._NATIVE/'hpke-public-fixture-build.json'
    class ActualHpkeTests(unittest.TestCase):
        def review(self,**kwargs): return app.review_public_disclosure_fixture(**(dict(role='incoming',scope='synthetic-regtest',consent=True)|kwargs))
        def test_incoming_and_audit_actual_hpke_scalar_receipts(self):
            for role in ('incoming','audit'):
                r=self.review(role=role)
                self.assertEqual((r.role,r.negative_checks),(role,14))
                self.assertFalse(r.runtime_authenticated or r.external_review_complete or r.spend_authorized or r.sign_allowed or r.broadcast_allowed)
        def test_consent_denial_after_success_never_grants_authority(self):
            self.review()
            with self.assertRaises(app.SelectiveDisclosureReviewError):self.review(consent=False)
        def test_unknown_role_denied(self):
            with self.assertRaises(app.SelectiveDisclosureReviewError):self.review(role='spend')
        def test_native_protocol_unknown_request_is_rejected_without_stdout(self):
            result=subprocess.run([str(exe)],input=b'PRIVATE INPUT',capture_output=True,timeout=15)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(2,b'',b''))
        def test_native_extra_argument_cannot_open_file_or_key(self):
            result=subprocess.run([str(exe),'--key=PRIVATE'],input=b'',capture_output=True,timeout=15)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(2,b'',b''))
        def test_actual_native_binary_byte_tamper_denied_before_execution(self):
            raw=exe.read_bytes()
            try:
                exe.write_bytes(raw+b'PUBLIC_FAULT')
                with self.assertRaises(app.SelectiveDisclosureReviewError):self.review()
            finally:exe.write_bytes(raw)
        def test_build_manifest_cannot_claim_external_review_or_release(self):
            raw=manifest.read_bytes()
            try:
                data=json.loads(raw);data['release_allowed']=True;manifest.write_text(json.dumps(data))
                with self.assertRaises(app.SelectiveDisclosureReviewError):self.review()
            finally:manifest.write_bytes(raw)
        def test_repeated_native_fixture_does_not_expose_plaintext_or_keys(self):
            for role in ('incoming','audit'):
                r=self.review(role=role)
                self.assertNotIn('123456',repr(r));self.assertNotIn('PUBLIC WALLET HPKE FIXTURE',repr(r))
    if args.gui:
        import os
        os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
        from PySide6.QtCore import QCoreApplication, QEvent
        from PySide6.QtWidgets import QApplication, QPushButton
        from wam_privacy_wallet.gui import MainWindow
        class ActualSourceGuiTests(unittest.TestCase):
            @classmethod
            def setUpClass(cls):cls.qt=QApplication.instance() or QApplication([])
            def setUp(self):self.window=MainWindow()
            def tearDown(self):
                self.window.close();self.window.deleteLater()
                QCoreApplication.sendPostedEvents(None,QEvent.Type.DeferredDelete)
                QCoreApplication.processEvents()
            def test_actual_source_worker_to_qt_keeps_every_authority_blocked(self):
                self.window.review_public_disclosure_fixture(role='incoming',scope='synthetic-regtest',consent=True)
                self.assertEqual(self.window.offline_presentation_state.disclosure,'PUBLIC_HPKE_UNTRUSTED')
                self.assertEqual(self.window.offline_presentation_state.authority,'BLOCKED')
                self.assertEqual(self.window.session_status.text(),'NO WALLET LOADED')
                self.assertIn('UNTRUSTED',self.window.disclosure_review_status.text())
                self.assertEqual(self.window.findChildren(QPushButton),[])
            def test_withdrawn_consent_clears_actual_source_worker_receipt(self):
                self.window.review_public_disclosure_fixture(role='incoming',scope='synthetic-regtest',consent=True)
                with self.assertRaisesRegex(ValueError,'^APP_GUI_DISCLOSURE_DENIED$'):
                    self.window.review_public_disclosure_fixture(role='incoming',scope='synthetic-regtest',consent=False)
                self.assertEqual(self.window.offline_presentation_state.disclosure,'ABSENT')
                self.assertEqual(self.window.offline_presentation_state.authority,'BLOCKED')

    suite=unittest.defaultTestLoader.loadTestsFromTestCase(ActualHpkeTests)
    if args.gui:suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(ActualSourceGuiTests))
    expected=10 if args.gui else 8
    if suite.countTestCases()!=expected:raise SystemExit('HPKE_NATIVE_DISCOVERY_DENIED')
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.skipped or result.expectedFailures or result.unexpectedSuccesses:raise SystemExit('HPKE_NATIVE_TEST_DENIED')
    print(f'ACTUAL_PINNED_HPKE_PUBLIC_FIXTURE_OK {expected}/{expected}; GUI={args.gui}; untrusted experiment; review/spend/sign/send blocked')


if __name__=='__main__':main()
