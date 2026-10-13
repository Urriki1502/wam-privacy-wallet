"""Real HMAC and Linux persistence negatives; fixture WSP ciphertext, NO Core."""
import hashlib
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import checkpoint_metadata_auth as a
from wam_privacy_wallet.application import versioned_checkpoint_journal as j
from test_versioned_checkpoint_journal import linux_or_deny

KEY = b'M' * 32  # Public fixture key, never a production credential.
CIPHER = b'WAMSP02\x00' + b'C' * 56  # Shape fixture, NOT valid WSP AES-GCM.
SCOPE = 'a' * 64


class CheckpointMetadataAuthTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory(prefix='wsp-metadata-auth-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.expected = a.CheckpointExpectation(SCOPE, 1, 3, 1)
        self.manifest = j._generation_manifest(1, CIPHER, scope_digest=SCOPE,
            tip_height=2, tip_hash='b'*64, predecessor_digest='0'*64)
        self.raw = a.authenticate_checkpoint_metadata(self.manifest, CIPHER,
            key=KEY, expected=self.expected)

    def verify(self, raw=None, cipher=CIPHER, key=KEY, expected=None):
        return a.verify_checkpoint_metadata(self.raw if raw is None else raw,
            cipher, key=key, expected=self.expected if expected is None else expected)

    def write(self, **kw):
        opts = dict(scope_digest=SCOPE, tip_height=2, tip_hash='b'*64,
            predecessor_digest='0'*64, checkpoint_schema=3, key_epoch=1,
            metadata_key=KEY)
        opts.update(kw)
        return j.write_authenticated_regtest_generation(self.root, 1, CIPHER, **opts)

    def read(self, **kw):
        opts = dict(scope_digest=SCOPE, checkpoint_schema=3, key_epoch=1,
            metadata_key=KEY, allow_unanchored_synthetic=True)
        opts.update(kw)
        return j.read_authenticated_regtest_generation(self.root, 1, **opts)

    def test_real_hmac_roundtrip_preserves_exact_ciphertext_binding(self):
        self.assertEqual(self.verify(), self.manifest)
        self.assertEqual(json.loads(self.raw)['metadata_schema'], 2)
        self.assertNotIn(KEY, self.raw)

    def test_every_metadata_field_tamper_denied(self):
        for name in self.manifest:
            body=json.loads(self.raw)
            body['manifest'][name] = 999 if type(body['manifest'][name]) is int else 'c'*64
            with self.subTest(name=name), self.assertRaises(a.CheckpointMetadataError):
                self.verify(j._canonical(body))

    def test_same_size_ciphertext_substitution_denied(self):
        with self.assertRaises(a.CheckpointMetadataError):
            self.verify(cipher=CIPHER[:-1]+b'X')

    def test_wrong_key_denied(self):
        with self.assertRaisesRegex(a.CheckpointMetadataError, 'AUTHENTICATION_DENIED'):
            self.verify(key=b'N'*32)

    def test_invalid_key_type_length_denied(self):
        for key in (None, 'password', b'', b'K'*31, b'K'*33, bytearray(KEY)):
            with self.subTest(type=type(key).__name__), self.assertRaises(a.CheckpointMetadataError):
                self.verify(key=key)

    def test_account_identity_mismatch_denied(self):
        with self.assertRaises(a.CheckpointMetadataError):
            self.verify(expected=a.CheckpointExpectation('c'*64,1,3,1))

    def test_stale_generation_denied_under_selected_expectation(self):
        with self.assertRaises(a.CheckpointMetadataError):
            self.verify(expected=a.CheckpointExpectation(SCOPE,2,3,1))

    def test_schema_mismatch_and_rotation_epoch_denied(self):
        for expected in (a.CheckpointExpectation(SCOPE,1,2,1),
                         a.CheckpointExpectation(SCOPE,1,3,2)):
            with self.assertRaises(a.CheckpointMetadataError):
                self.verify(expected=expected)

    def test_explicit_key_rotation_no_old_key_fallback(self):
        next_expected=a.CheckpointExpectation(SCOPE,1,3,2)
        raw=a.authenticate_checkpoint_metadata(self.manifest,CIPHER,
            key=b'N'*32,expected=next_expected)
        self.assertEqual(self.verify(raw,key=b'N'*32,expected=next_expected),self.manifest)
        with self.assertRaises(a.CheckpointMetadataError):
            self.verify(raw,expected=next_expected)
        with self.assertRaises(a.CheckpointMetadataError):
            self.verify(expected=next_expected)

    def test_boolean_and_overflow_bindings_denied(self):
        for fields in ((True,3,1),(1,True,1),(1,3,True),(0,3,1),(2**63,3,1),(1,0,1),(1,3,0)):
            with self.subTest(fields=fields), self.assertRaises(a.CheckpointMetadataError):
                self.verify(expected=a.CheckpointExpectation(SCOPE,*fields))

    def test_authenticated_but_invalid_manifest_not_signable(self):
        for field,value in (('schema',True),('network','mainnet'),('source_pin','0'*40),
                            ('tip_height',True),('predecessor','c'*64)):
            manifest={**self.manifest,field:value}
            with self.subTest(field=field),self.assertRaises(a.CheckpointMetadataError):
                a.authenticate_checkpoint_metadata(manifest,CIPHER,key=KEY,expected=self.expected)

    def test_genesis_cross_chain_denied(self):
        body=json.loads(self.raw); body['genesis']='0'*64
        with self.assertRaises(a.CheckpointMetadataError): self.verify(j._canonical(body))

    def test_noncanonical_duplicate_extra_and_oversize_metadata_denied(self):
        cases=[b' '+self.raw, self.raw.replace(b'"key_epoch":1',b'"key_epoch":1,"key_epoch":1'),
               self.raw[:-1]+b',"authority":true}', b'X'*4097, b'\xff', b'{}',b'['*4000]
        for raw in cases:
            with self.subTest(size=len(raw)),self.assertRaises(a.CheckpointMetadataError): self.verify(raw)

    def test_mac_replay_authenticates_but_never_proves_freshness(self):
        self.assertEqual(self.verify(),self.verify())
        for provider in (None,lambda:True, {'generation':1,'trusted':True},self.raw):
            with self.assertRaisesRegex(a.CheckpointMetadataError,'INDEPENDENT_ANCHOR_UNQUALIFIED'):
                a.require_independent_anchor(provider)

    def test_protected_read_denies_before_any_file_or_key_access(self):
        with patch.object(j,'_open_dir',side_effect=AssertionError('must not read')):
            with self.assertRaisesRegex(j.VersionedCheckpointError,'TRUSTED_ANCHOR_REQUIRED'):
                self.read(allow_unanchored_synthetic=False)

    def test_pinned_source_accepts_only_current_checkpoint_schema_before_write(self):
        with patch.object(j,'_persist_generation',side_effect=AssertionError('must not write')):
            for schema in (1,2,4,999,True):
                with self.subTest(schema=schema),self.assertRaises(a.CheckpointMetadataError):
                    self.write(checkpoint_schema=schema)
        self.assertEqual(a._PINNED_CHECKPOINT_SCHEMA,3)

    def test_invalid_binding_or_key_denied_before_disk_read(self):
        with patch.object(j,'_load_generation',side_effect=AssertionError('must not read')):
            for opts in ({'checkpoint_schema':4},{'checkpoint_schema':1},
                         {'scope_digest':'not-a-scope'},{'key_epoch':0},
                         {'metadata_key':b'not-a-valid-key'}):
                with self.subTest(opts=opts),self.assertRaises(a.CheckpointMetadataError):
                    self.read(**opts)

    def test_expectation_repr_hides_scope(self):
        self.assertNotIn(SCOPE,repr(self.expected))

    @linux_or_deny
    def test_linux_disk_roundtrip_and_private_modes(self):
        self.write(); self.assertEqual(self.read(),(self.manifest,CIPHER))
        for file in (self.root/'versions'/'0000000000000001').iterdir():
            self.assertEqual(file.stat().st_mode & 0o777,0o600)
        self.assertEqual((self.root/'versions'/'0000000000000001'/'checkpoint.wsp.enc').read_bytes(),CIPHER)

    @linux_or_deny
    def test_torn_metadata_write_has_no_ready_marker(self):
        original=j._file
        def fault(fd,name,body):
            if name=='metadata.v2.json': raise OSError('injected torn write')
            return original(fd,name,body)
        with patch.object(j,'_file',side_effect=fault):
            with self.assertRaises(j.VersionedCheckpointError): self.write()
        self.assertFalse((self.root/'versions'/'0000000000000001'/'ready.sha256').exists())
        with self.assertRaises(j.VersionedCheckpointError): self.read()

    @linux_or_deny
    def test_corruption_even_with_recomputed_local_marker_denied(self):
        self.write(); base=self.root/'versions'/'0000000000000001'
        manifest=json.loads((base/'manifest.json').read_bytes());manifest['tip_height']=3
        raw=j._canonical(manifest)
        (base/'manifest.json').write_bytes(raw)
        (base/'ready.sha256').write_bytes((hashlib.sha256(raw).hexdigest()+'\n').encode())
        with self.assertRaises(j.VersionedCheckpointError): self.read()

    @linux_or_deny
    def test_missing_or_symlinked_mac_denied(self):
        self.write();base=self.root/'versions'/'0000000000000001'
        p=base/'metadata.v2.json';p.unlink()
        with self.assertRaises(j.VersionedCheckpointError): self.read()
        p.symlink_to(base/'manifest.json')
        with self.assertRaises(j.VersionedCheckpointError): self.read()

    @linux_or_deny
    def test_legacy_journal_cannot_implicitly_upgrade_to_authenticated(self):
        j.write_unanchored_regtest_generation(self.root,1,CIPHER,scope_digest=SCOPE,
            tip_height=2,tip_hash='b'*64,predecessor_digest='0'*64)
        with self.assertRaises(j.VersionedCheckpointError): self.read()

    @linux_or_deny
    def test_ancestor_symlink_and_dotdot_refused(self):
        alias=self.root/'alias';alias.symlink_to(self.root,target_is_directory=True)
        for path in (alias/'child',self.root/'child'/'..'):
            with self.assertRaises(j.VersionedCheckpointError): j._open_dir(path)

    @linux_or_deny
    def test_native_lock_conflict_read_and_write_refused(self):
        self.write(); fd=j._open_dir(self.root)
        try:
            j._lock(fd,exclusive=True)
            with self.assertRaisesRegex(j.VersionedCheckpointError,'CONCURRENT_UPDATE_DENIED'):self.read()
            with self.assertRaisesRegex(j.VersionedCheckpointError,'CONCURRENT_UPDATE_DENIED'):self.write()
        finally:os.close(fd)

    @linux_or_deny
    def test_native_interprocess_lock_denies_child_writer(self):
        fd=j._open_dir(self.root);j._lock(fd,exclusive=True)
        pid=os.fork()
        if pid==0:
            os.close(fd)
            try:self.write()
            except j.VersionedCheckpointError:os._exit(0)
            os._exit(1)
        try:
            _,status=os.waitpid(pid,0)
            self.assertEqual(os.waitstatus_to_exitcode(status),0)
        finally:os.close(fd)
        self.write()

    @linux_or_deny
    def test_fsync_faults_never_authorize_restore_or_overwrite_prior(self):
        self.write(); old=self.read();original=j.os.fsync
        for fail_at in range(1,8):
            with TemporaryDirectory() as root:
                folder=Path(root);calls=0
                def fault(fd):
                    nonlocal calls
                    calls+=1
                    if calls==fail_at:raise OSError('fsync injection')
                    return original(fd)
                with patch.object(j.os,'fsync',side_effect=fault):
                    with self.assertRaises(j.VersionedCheckpointError):
                        j.write_authenticated_regtest_generation(folder,1,CIPHER,
                            scope_digest=SCOPE,tip_height=2,tip_hash='b'*64,
                            predecessor_digest='0'*64,checkpoint_schema=3,key_epoch=1,metadata_key=KEY)
                with self.assertRaisesRegex(j.VersionedCheckpointError,'TRUSTED_ANCHOR_REQUIRED'):
                    j.read_authenticated_regtest_generation(folder,1,scope_digest=SCOPE,
                        checkpoint_schema=3,key_epoch=1,metadata_key=KEY)
        self.assertEqual(self.read(),old)
