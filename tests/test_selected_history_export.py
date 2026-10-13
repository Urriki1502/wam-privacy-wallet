"""Local export policy tests; DTO fixtures do not prove actual Core history."""
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
import socket
import subprocess
import threading
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application.qualified_scan_session import PrivateHistoryPage, PrivateHistoryRow
from wam_privacy_wallet.application.selected_history_export import LocalHistoryExport, LocalHistoryExportError

A, B = 'a'*64, 'b'*64

def page():
    return PrivateHistoryPage((PrivateHistoryRow(A, 10, 2, 500, 0),
                               PrivateHistoryRow(B, 11, 1, 0, 50)), 11, 0)

class SelectedHistoryExportTests(unittest.TestCase):
    def pending(self, **changes):
        args=dict(page=page(), selected_txids=(A,), fields=('height',), user_consented=True)
        args.update(changes)
        return LocalHistoryExport(**args)
    def denied(self, **changes):
        with self.assertRaisesRegex(LocalHistoryExportError,'^APP_LOCAL_HISTORY_EXPORT_DENIED$'):
            self.pending(**changes)
    def test_selected_fields_only_and_exact_once(self):
        pending=self.pending();preview=pending.preview(user_consented=True)
        data=json.loads(preview.payload)
        self.assertEqual(data['rows'],[dict(txid=A,height=10)])
        self.assertNotIn(B,preview.payload.decode())
        self.assertNotIn('credit_atoms',preview.payload.decode())
        self.assertFalse(data['spend_authorized'] or data['proof_verified'])
        self.assertEqual(sha256(preview.payload).hexdigest(),preview.approval_sha256)
        self.assertEqual(pending.export(approved_sha256=preview.approval_sha256,user_consented=True),preview.payload)
        with self.assertRaises(LocalHistoryExportError):pending.export(approved_sha256=preview.approval_sha256,user_consented=True)
    def test_consent_before_page_access(self):
        class Evil:
            def __getattribute__(self,name):raise AssertionError('secret access')
        for value in (False,None,1,'yes'):self.denied(page=Evil(),user_consented=value)
    def test_seed_key_unknown_and_empty_fields_denied(self):
        for value in ((),('seed',),('scan_secret',),('spend_secret',),('height','height'),['height'],('txid',)):
            self.denied(fields=value)
    def test_selection_cannot_expand_drop_or_duplicate(self):
        for value in ((),(A,A),(A,'c'*64),tuple('c'*64 for _ in range(21)),[A]):self.denied(selected_txids=value)
    def test_hostile_primitive_subclasses_denied(self):
        class Evil(str):
            __hash__=str.__hash__
            def __eq__(self,other):raise AssertionError('callback')
        self.denied(selected_txids=(Evil(A),))
        self.denied(fields=(Evil('height'),))
    def test_mutated_or_authority_bearing_page_denied(self):
        for field,value in (('tip_height',True),('source_commit','x'*40),('signer_enabled',True),('wallet_operational',True),('broadcast_allowed',0)):
            data=page();object.__setattr__(data,field,value);self.denied(page=data)
    def test_stale_internal_confirmation_and_duplicates_denied(self):
        data=page();object.__setattr__(data,'tip_height',12);self.denied(page=data)
        self.denied(page=PrivateHistoryPage((page().records[0],page().records[0]),11,0))
    def test_source_row_mutation_after_prepare_cannot_change_approved_bytes(self):
        data=page();pending=self.pending(page=data);preview=pending.preview(user_consented=True)
        object.__setattr__(data.records[0],'height',1)
        self.assertEqual(pending.export(approved_sha256=preview.approval_sha256,user_consented=True),preview.payload)
    def test_wrong_digest_consumes_pending_approval(self):
        pending=self.pending();preview=pending.preview(user_consented=True)
        for digest in ('0'*64,preview.approval_sha256):
            with self.assertRaises(LocalHistoryExportError):pending.export(approved_sha256=digest,user_consented=True)
    def test_withdrawal_and_cancel_invalidate(self):
        for action in ('cancel','withdraw'):
            pending=self.pending();preview=pending.preview(user_consented=True)
            if action=='cancel':pending.cancel()
            else:
                with self.assertRaises(LocalHistoryExportError):pending.export(approved_sha256=preview.approval_sha256,user_consented=False)
            with self.assertRaises(LocalHistoryExportError):pending.preview(user_consented=True)
    def test_expiry_includes_exact_deadline(self):
        with patch('wam_privacy_wallet.application.selected_history_export.monotonic',return_value=100):pending=self.pending()
        with patch('wam_privacy_wallet.application.selected_history_export.monotonic',return_value=220):
            with self.assertRaises(LocalHistoryExportError):pending.preview(user_consented=True)
        with self.assertRaises(LocalHistoryExportError):pending.preview(user_consented=True)
    def test_concurrent_export_has_one_winner(self):
        pending=self.pending();preview=pending.preview(user_consented=True);results=[]
        def run():
            try:results.append(pending.export(approved_sha256=preview.approval_sha256,user_consented=True))
            except LocalHistoryExportError:results.append(None)
        threads=[threading.Thread(target=run) for _ in range(2)]
        for t in threads:t.start()
        for t in threads:t.join()
        self.assertEqual(results.count(preview.payload),1)
    def test_preview_is_private_and_immutable(self):
        pending=self.pending();preview=pending.preview(user_consented=True)
        self.assertNotIn(A,repr(pending));self.assertNotIn(A,repr(preview))
        with self.assertRaises(FrozenInstanceError):preview.payload=b'changed'
    def test_no_io_network_process_or_proof_dependency(self):
        with patch.object(socket,'socket',side_effect=AssertionError),patch.object(subprocess,'Popen',side_effect=AssertionError),patch('builtins.open',side_effect=AssertionError):
            pending=self.pending();preview=pending.preview(user_consented=True)
            pending.export(approved_sha256=preview.approval_sha256,user_consented=True)

if __name__=='__main__':unittest.main()
