"""Denial instrumentation only; real parser evidence comes from native CI."""
import contextlib
import io
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from wam_privacy_wallet.application import _psbt_v2_worker as worker


class PsbtWorkerBoundaryTests(unittest.TestCase):
    def test_bad_raw_rejected_before_source_check(self):
        with patch.object(worker,'verify_wsp1_full_source_closure') as verify:
            for value in (None,bytearray(b'psbt\xff'),b'',b'x'*1_000_001):
                with self.assertRaises(ValueError): worker.parse_pinned_unsigned_fixture(value,Path.cwd())
            verify.assert_not_called()

    def test_32bit_worker_also_denied_before_source_check(self):
        with patch('struct.calcsize',return_value=4),patch.object(worker,'verify_wsp1_full_source_closure') as verify:
            with self.assertRaises(ValueError): worker.parse_pinned_unsigned_fixture(b'psbt\xff',Path.cwd())
            verify.assert_not_called()

    def test_existing_wsp_module_denied_before_qualification(self):
        with patch('struct.calcsize',return_value=8),patch.dict('sys.modules',{'wam_sp':SimpleNamespace()}),patch.object(worker,'verify_wsp1_full_source_closure') as verify:
            with self.assertRaises(ValueError): worker.parse_pinned_unsigned_fixture(b'psbt\xff',Path.cwd())
            verify.assert_not_called()

    def test_source_failure_does_not_attempt_upstream_import(self):
        with patch('struct.calcsize',return_value=8),patch.object(worker,'verify_wsp1_full_source_closure',side_effect=ValueError('PRIVATE')),patch('importlib.util.find_spec') as find:
            with self.assertRaises(ValueError): worker.parse_pinned_unsigned_fixture(b'psbt\xff',Path.cwd())
            find.assert_not_called()

    def test_network_and_process_audit_events_denied(self):
        for event in ('socket.__new__','socket.connect','subprocess.Popen','os.system','os.exec','os.posix_spawn'):
            with self.assertRaises(ValueError): worker._audit_read_only(event,())

    def test_write_open_denied_but_read_event_permitted(self):
        for flags in (os.O_CREAT,os.O_TRUNC,os.O_WRONLY,os.O_RDWR,os.O_APPEND):
            with self.assertRaises(ValueError): worker._audit_read_only('open',('PRIVATE','w',flags))
        worker._audit_read_only('open',('unused','r',os.O_RDONLY))

    def test_sign_finalize_broadcast_and_direct_crypto_sign_denied(self):
        for module,name in (('wam_sp.psbt','sign'),('wam_sp.wallet','prepare'),('wam_sp.wallet','broadcast'),('wam_sp.psbt','finalize'),('coincurve.keys','sign_schnorr')):
            frame=SimpleNamespace(f_globals={'__name__':module},f_code=SimpleNamespace(co_name=name),f_locals={})
            with self.assertRaises(ValueError): worker._profile_no_sign(frame,'call',None)

    def test_signer_construction_denied(self):
        value=type('Signer',(),{})()
        frame=SimpleNamespace(f_globals={'__name__':'wam_sp.wallet'},f_code=SimpleNamespace(co_name='__init__'),f_locals={'self':value})
        with self.assertRaises(ValueError): worker._profile_no_sign(frame,'call',None)

    def test_worker_error_has_no_stdout_or_traceback(self):
        stream=io.StringIO()
        with patch('sys.argv',['worker','--source-root','/PRIVATE']),patch.object(worker,'parse_pinned_unsigned_fixture',side_effect=ValueError('PRIVATE')),patch('sys.stdin',SimpleNamespace(buffer=io.BytesIO(b'psbt\xff'))),contextlib.redirect_stdout(stream):
            self.assertEqual(worker.main(),2)
        self.assertEqual(stream.getvalue(),'')

    def test_unknown_worker_args_denied_without_reading_stdin(self):
        with patch('sys.argv',['worker','--sign','PRIVATE']),patch.object(worker,'parse_pinned_unsigned_fixture') as parse:
            self.assertEqual(worker.main(),2)
            parse.assert_not_called()


if __name__=='__main__': unittest.main()
