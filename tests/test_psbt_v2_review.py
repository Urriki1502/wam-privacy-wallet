"""Child protocol/denial tests only; native WSP tests prove actual decoding."""
from dataclasses import FrozenInstanceError, asdict
import json
from pathlib import Path
import struct
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from wam_privacy_wallet.application.psbt_v2_review import (
    PsbtV2Review, PsbtV2ReviewError, review_synthetic_psbt_v2,
)


class PsbtV2ReviewTests(unittest.TestCase):
    def review(self, raw=b'psbt\xfffixture', **changes):
        return review_synthetic_psbt_v2(raw,
            **(dict(source_root=Path.cwd(), scope='synthetic-regtest', consent=True) | changes))

    def child(self, **fields):
        data=asdict(PsbtV2Review(1,1)); data.update(fields)
        return SimpleNamespace(returncode=0,stdout=json.dumps(data).encode())

    def test_consent_required_before_process_or_source_io(self):
        with patch('subprocess.run') as run:
            for flag in (False,1,None,'yes'):
                with self.assertRaises(PsbtV2ReviewError): self.review(consent=flag)
            run.assert_not_called()

    def test_scope_required_before_child(self):
        with patch('subprocess.run') as run:
            for scope in ('mainnet','regtest',None,True):
                with self.assertRaises(PsbtV2ReviewError): self.review(scope=scope)
            run.assert_not_called()

    def test_raw_type_and_bounds_denied_before_child(self):
        with patch('subprocess.run') as run:
            for raw in (None,bytearray(b'psbt\xff'),b'',b'x'*1_000_001):
                with self.assertRaises(PsbtV2ReviewError): self.review(raw)
            run.assert_not_called()

    def test_32bit_is_explicitly_unqualified_without_child(self):
        with patch('struct.calcsize',return_value=4),patch('subprocess.run') as run:
            with self.assertRaisesRegex(PsbtV2ReviewError,'^APP_PSBT_V2_PLATFORM_UNQUALIFIED$'):
                self.review()
            run.assert_not_called()

    def test_unsupported_os_denied_without_child(self):
        with patch('struct.calcsize',return_value=8),patch('sys.platform','unknown'),patch('subprocess.run') as run:
            with self.assertRaisesRegex(PsbtV2ReviewError,'^APP_PSBT_V2_PLATFORM_UNQUALIFIED$'): self.review()
            run.assert_not_called()

    def test_invalid_source_root_types_denied(self):
        with patch('struct.calcsize',return_value=8),patch('sys.platform','linux'),patch('subprocess.run') as run:
            for root in (None,'/path',Path('relative'),object()):
                with self.assertRaises(PsbtV2ReviewError): self.review(source_root=root)
            run.assert_not_called()

    def test_source_stat_failure_is_redacted_without_child(self):
        with patch('struct.calcsize',return_value=8),patch('sys.platform','linux'),patch.object(Path,'is_symlink',side_effect=OSError('PRIVATE')),patch('subprocess.run') as run:
            with self.assertRaisesRegex(PsbtV2ReviewError,'^APP_PSBT_V2_REVIEW_DENIED$'): self.review()
            run.assert_not_called()

    def test_fixed_isolated_command_and_bounded_protocol_only(self):
        # Mock protocol PASS is not integration evidence; actual decoding is native-only.
        with patch('struct.calcsize',return_value=8),patch('sys.platform','linux'),patch('subprocess.run',return_value=self.child()) as run:
            result=self.review()
        args=run.call_args.args[0]
        self.assertEqual(args[1:5],['-I','-B','-m','wam_privacy_wallet.application._psbt_v2_worker'])
        self.assertEqual(run.call_args.kwargs['input'],b'psbt\xfffixture')
        self.assertEqual(run.call_args.kwargs['timeout'],30)
        self.assertEqual(run.call_args.kwargs['stderr'],subprocess.DEVNULL)
        self.assertFalse(result.ownership_verified or result.chain_verified or result.sign_allowed or result.broadcast_allowed)

    def test_child_failure_denies_and_redacts(self):
        with patch('struct.calcsize',return_value=8),patch('sys.platform','linux'),patch('subprocess.run',return_value=SimpleNamespace(returncode=2,stdout=b'PRIVATE')):
            with self.assertRaisesRegex(PsbtV2ReviewError,'^APP_PSBT_V2_REVIEW_DENIED$'): self.review()

    def test_timeout_or_spawn_failure_denies_and_redacts(self):
        for error in (OSError('PRIVATE'),subprocess.TimeoutExpired('PRIVATE',30)):
            with patch('struct.calcsize',return_value=8),patch('sys.platform','linux'),patch('subprocess.run',side_effect=error):
                with self.assertRaisesRegex(PsbtV2ReviewError,'^APP_PSBT_V2_REVIEW_DENIED$'): self.review()

    def test_empty_oversized_or_non_json_child_reply_denied(self):
        for data in (b'',b'x'*2049,b'PRIVATE',b'[]'):
            with patch('struct.calcsize',return_value=8),patch('sys.platform','linux'),patch('subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=data)):
                with self.assertRaises(PsbtV2ReviewError): self.review()

    def test_extra_child_fields_or_missing_field_denied(self):
        for mode in ('extra','missing'):
            data=asdict(PsbtV2Review(1,1))
            if mode=='extra': data['psbt']='PRIVATE'
            else: del data['source_commit']
            with patch('struct.calcsize',return_value=8),patch('sys.platform','linux'),patch('subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(data).encode())):
                with self.assertRaises(PsbtV2ReviewError): self.review()

    def test_forged_pin_or_evidence_denied(self):
        for data in ({'source_commit':'0'*40},{'evidence':'READY_TO_SIGN'}):
            with patch('struct.calcsize',return_value=8),patch('sys.platform','linux'),patch('subprocess.run',return_value=self.child(**data)):
                with self.assertRaises(PsbtV2ReviewError): self.review()

    def test_bool_or_out_of_range_counts_denied(self):
        for field,max_value in (('input_count',128),('output_count',256)):
            for count in (True,0,max_value+1,'1'):
                with patch('struct.calcsize',return_value=8),patch('sys.platform','linux'),patch('subprocess.run',return_value=self.child(**{field:count})):
                    with self.assertRaises(PsbtV2ReviewError): self.review()

    def test_forged_authority_denied(self):
        for field in ('ownership_verified','chain_verified','sign_allowed','broadcast_allowed'):
            for value in (True,0,None,'false'):
                with patch('struct.calcsize',return_value=8),patch('sys.platform','linux'),patch('subprocess.run',return_value=self.child(**{field:value})):
                    with self.assertRaises(PsbtV2ReviewError): self.review()

    def test_receipt_immutable_and_no_raw_data_fields(self):
        value=PsbtV2Review(1,1)
        with self.assertRaises(FrozenInstanceError): value.sign_allowed=True
        for name in ('psbt','transaction','utxos','script','amount','source_root','signer','key'):
            self.assertFalse(hasattr(value,name))


if __name__=='__main__': unittest.main()
