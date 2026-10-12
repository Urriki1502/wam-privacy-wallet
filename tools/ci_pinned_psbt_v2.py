"""Actual pinned unsigned PSBTv2 native regressions, no signer or Core execution."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from pathlib import Path
import sys
import unittest

from wam_privacy_wallet.integrations.wsp1_source_closure import verify_wsp1_full_source_closure
from wam_privacy_wallet.application.psbt_v2_review import PsbtV2ReviewError, review_synthetic_psbt_v2

PUBLIC_X = bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source-root',required=True)
    parser.add_argument('--gui', action='store_true', help='Also exercise actual parser-to-Qt path')
    args=parser.parse_args()
    root=Path(args.source_root).resolve()
    sys.dont_write_bytecode=True
    proof=verify_wsp1_full_source_closure(root)
    if proof['pinned_commit']!='ac55f13423620252bdbf848c7e8a280c3b84721e':
        raise SystemExit('NATIVE_PSBT_SOURCE_DENIED')
    # Fixture encoder is the actual upstream implementation. Public curve point
    # only; no PrivateKey, Keyring, wallet, signer, signature or secret generation.
    from wam_sp.psbt import PSBT, Tx, _map
    from wam_sp.transaction import blob, compact
    script=b'\x51\x20'+PUBLIC_X
    fixture=PSBT(Tx((('01'*32,0),),((9000,b'\x6a'),)),((10000,script),))
    raw=fixture.encode()

    def wire(g,ins,outs):
        return b'psbt\xff'+_map(g)+b''.join(_map(m) for m in ins+outs)

    class ActualPinnedPsbtTests(unittest.TestCase):
        def review(self,data=raw,**kwargs):
            return review_synthetic_psbt_v2(data,
                **(dict(source_root=root,scope='synthetic-regtest',consent=True)|kwargs))
        def denied(self,data,**kwargs):
            with self.assertRaisesRegex(PsbtV2ReviewError,'^APP_PSBT_V2_REVIEW_DENIED$'):
                self.review(data,**kwargs)
        def test_actual_unsigned_decoder_receipt_no_authority(self):
            value=self.review()
            self.assertEqual((value.input_count,value.output_count),(1,1))
            self.assertFalse(value.ownership_verified or value.chain_verified or value.sign_allowed or value.broadcast_allowed)
            self.assertNotIn('psbt',asdict(value))
        def test_multi_input_decode_from_actual_encoder(self):
            p=PSBT(Tx((('01'*32,0),('02'*32,0)),((19000,b'\x6a'),)),((10000,script),(10000,script)))
            self.assertEqual(self.review(p.encode()).input_count,2)
        def test_v0_is_denied_despite_upstream_support(self): self.denied(fixture.to_v0().encode())
        def test_truncation_denied(self):
            for cut in (1,4,len(raw)-1,len(raw)-20): self.denied(raw[:cut])
        def test_trailing_bytes_denied(self): self.denied(raw+b'PRIVATE')
        def test_duplicate_global_map_key_denied_by_actual_reader(self):
            g,ins,outs=fixture.maps()
            duplicate=_map(g)[:-1]+blob(b'\xfb')+blob(b'\x02\x00\x00\x00')+b'\x00'
            self.denied(b'psbt\xff'+duplicate+b''.join(_map(m) for m in ins+outs))
        def test_noncanonical_compact_length_denied(self):
            self.denied(raw[:5]+b'\xfd\x01\x00'+raw[6:])
        def test_unknown_global_field_denied(self):
            g,ins,outs=fixture.maps();g[b'\xfcx']=b'PRIVATE';self.denied(wire(g,ins,outs))
        def test_partial_signature_field_denied(self):
            g,ins,outs=fixture.maps();ins[0][b'\x13']=bytes(64);self.denied(wire(g,ins,outs))
        def test_input_keypath_denied(self):
            g,ins,outs=fixture.maps();ins[0][b'\x06\x02'+PUBLIC_X]=b'PRIVATE';self.denied(wire(g,ins,outs))
        def test_finalized_witness_metadata_denied(self):
            g,ins,outs=fixture.maps();ins[0][b'\x08']=b'PRIVATE';self.denied(wire(g,ins,outs))
        def test_output_keypath_denied(self):
            g,ins,outs=fixture.maps();outs[0][b'\x06']=b'PRIVATE';self.denied(wire(g,ins,outs))
        def test_modifiable_flags_denied(self):
            g,ins,outs=fixture.maps();g[b'\x06']=b'\x01';self.denied(wire(g,ins,outs))
        def test_negative_fee_denied(self):
            p=PSBT(Tx((('01'*32,0),),((11000,b'\x6a'),)),((10000,script),));self.denied(p.encode())
        def test_duplicate_outpoints_denied_by_actual_decoder(self):
            g,ins,outs=fixture.maps();g[b'\x04']=compact(2);self.denied(wire(g,ins+ins,outs))
        def test_count_limit_denied(self):
            for key,value in ((b'\x04',129),(b'\x05',257)):
                g,ins,outs=fixture.maps();g[key]=compact(value);self.denied(wire(g,ins,outs))
        def test_oversized_raw_denied(self): self.denied(b'x'*1_000_001)
        def test_wrong_source_root_denied(self): self.denied(raw,source_root=root.parent)
        def test_genuine_transitive_source_tampering_denied_before_import(self):
            path=root/'src/wam_sp/core.py'; original=path.read_bytes()
            try:
                path.write_bytes(original+b'\n# synthetic fault injection\n')
                self.denied(raw)
            finally: path.write_bytes(original)
        def test_injected_cached_bytecode_denied(self):
            directory=root/'src/wam_sp/__pycache__'; created=not directory.exists()
            directory.mkdir(exist_ok=True); path=directory/'synthetic-invalid.pyc'
            try:
                path.write_bytes(b'UNTRUSTED CACHE')
                self.denied(raw)
            finally:
                path.unlink()
                if created: directory.rmdir()
        def test_repeated_fresh_worker_does_not_mutate_source(self):
            self.assertEqual(self.review(),self.review())
            self.assertFalse(any((root/'src/wam_sp').rglob('*.pyc')))
            verify_wsp1_full_source_closure(root)

    if args.gui:
        import os
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtCore import QCoreApplication, QEvent
        from PySide6.QtWidgets import QApplication, QPushButton
        from wam_privacy_wallet.gui import MainWindow

        class ActualParserGuiTests(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                cls.app = QApplication.instance() or QApplication([])
            def setUp(self): self.window = MainWindow()
            def tearDown(self):
                self.window.close(); self.window.deleteLater()
                QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
                QCoreApplication.processEvents()
            def test_actual_worker_to_qt_has_only_scalar_untrusted_receipt(self):
                self.window.review_unsigned_psbt_fixture(raw, source_root=root, scope='synthetic-regtest', consent=True)
                self.assertEqual(self.window.offline_presentation_state.psbt, 'UNSIGNED_PARSED_UNTRUSTED')
                self.assertIn('inputs 1', self.window.psbt_review_status.text())
                self.assertIn('UNTRUSTED', self.window.psbt_review_status.text())
                self.assertIn('ac55f134', self.window.psbt_review_notice.text())
                self.assertEqual(self.window.session_status.text(), 'NO WALLET LOADED')
                self.assertEqual(self.window.findChildren(QPushButton), [])
            def test_actual_worker_rejection_and_withdrawn_consent_clear_prior_parse(self):
                for data, consent in ((raw+b'PRIVATE', True), (raw, False)):
                    self.window.review_unsigned_psbt_fixture(raw, source_root=root, scope='synthetic-regtest', consent=True)
                    with self.assertRaisesRegex(ValueError, '^APP_GUI_PSBT_REVIEW_DENIED$'):
                        self.window.review_unsigned_psbt_fixture(data, source_root=root, scope='synthetic-regtest', consent=consent)
                    self.assertEqual(self.window.offline_presentation_state.psbt, 'ABSENT')
                    self.assertEqual(self.window.psbt_review_status.text(), 'NO UNSIGNED PSBT REVIEW')
                    self.assertEqual(self.window.offline_presentation_state.authority, 'BLOCKED')

    suite=unittest.defaultTestLoader.loadTestsFromTestCase(ActualPinnedPsbtTests)
    if args.gui:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(ActualParserGuiTests))
    expected = 23 if args.gui else 21
    if suite.countTestCases()!=expected: raise SystemExit('NATIVE_PSBT_DISCOVERY_DENIED')
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
        raise SystemExit('NATIVE_PSBT_TESTS_DENIED')
    print(f'NATIVE_PINNED_UNSIGNED_PSBT_V2_OK {expected}/{expected}; GUI={args.gui}; no ownership/chain/sign/broadcast authority')


if __name__=='__main__': main()
