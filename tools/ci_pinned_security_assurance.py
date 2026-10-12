"""Actual pinned stdlib WAM Security tests; no Core or signing harness."""
from hashlib import sha1
import json
from pathlib import Path
import subprocess
import sys
import unittest
from wam_privacy_wallet.application import security_assurance_review as app

EXPECTED_DIGEST="0700a9000944f1188eebafb4448823f11c6df8723feb6f0cedd6ff1243eb7424"
TEST_BLOB="b5a2052e6d60c1d2e4e3bdaf4fc7da6f25397fc8"


def verify(root):
    if subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD']).decode().strip()!=app._PIN:
        raise SystemExit('SECURITY_SOURCE_HEAD_DENIED')
    files={f'src/wam_security/{name}':oid for name,oid in app._BLOBS.items()}|{'tests/test_provenance.py':TEST_BLOB}
    for name,oid in files.items():
        path=root/name
        if path.is_symlink() or path.stat().st_size>100_000:raise SystemExit('SECURITY_SOURCE_PATH_DENIED')
        data=path.read_bytes()
        if sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()!=oid:raise SystemExit('SECURITY_SOURCE_BYTES_DENIED')
    print(f'PINNED_SECURITY_RAW_SOURCE_OK {app._PIN}; 5 blobs; no Core audit or release authority')


def main():
    if len(sys.argv) not in (2,3) or (len(sys.argv)==3 and sys.argv[2]!='--verify-only'):
        raise SystemExit('SECURITY_SOURCE_ARGUMENT_DENIED')
    root=Path(sys.argv[1]).resolve();verify(root)
    if len(sys.argv)==3:return
    if app._verify_source().resolve()!=root/'src/wam_security':raise SystemExit('SECURITY_INSTALLED_SOURCE_DENIED')
    original=unittest.TestLoader().discover(str(root/'tests'),pattern='test_provenance.py')
    if original.countTestCases()!=3:raise SystemExit('SECURITY_UPSTREAM_DISCOVERY_DENIED')
    class ActualAssuranceTests(unittest.TestCase):
        def review(self,**kwargs):return app.review_public_assurance_fixture(**(dict(scope='synthetic-regtest',consent=True)|kwargs))
        def test_actual_canonical_provenance_digest_matches_public_vector(self):
            self.assertEqual(self.review().provenance_digest,EXPECTED_DIGEST)
        def test_actual_helper_returns_no_core_runtime_release_or_spend_authority(self):
            r=self.review();self.assertEqual((r.subject_count,r.dependency_count),(1,3))
            self.assertFalse(r.publisher_authenticated or r.runtime_authenticated or r.release_allowed or r.sign_allowed or r.broadcast_allowed)
        def test_public_fixture_is_deterministic_across_fresh_temporary_artifacts(self):
            self.assertEqual(self.review(),self.review())
        def test_no_consent_or_wrong_scope_denies_without_a_success_fallback(self):
            for kwargs in ({'consent':False},{'scope':'mainnet'}):
                with self.assertRaises(app.SecurityAssuranceReviewError):self.review(**kwargs)
        def test_actual_identity_source_byte_tamper_is_redacted_and_denied(self):
            path=root/'src/wam_security/supplychain/identities.py';raw=path.read_bytes()
            try:
                path.write_bytes(raw+b'\n# PUBLIC FAULT\n')
                with self.assertRaisesRegex(app.SecurityAssuranceReviewError,'^APP_SECURITY_ASSURANCE_DENIED$'):self.review()
            finally:path.write_bytes(raw)
        def test_actual_worker_unknown_request_is_rejected_without_output(self):
            result=subprocess.run([sys.executable,'-I','-B','-m','wam_privacy_wallet.application._security_assurance_worker'],input=b'PRIVATE',capture_output=True,timeout=15)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(2,b'',b''))
        def test_actual_worker_extra_argument_cannot_select_an_artifact(self):
            result=subprocess.run([sys.executable,'-I','-B','-m','wam_privacy_wallet.application._security_assurance_worker','--artifact=PRIVATE'],input=b'',capture_output=True,timeout=15)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(2,b'',b''))
        def test_injected_bytecode_denied_without_importing_it(self):
            directory=root/'src/wam_security/__pycache__';created=not directory.exists();directory.mkdir(exist_ok=True)
            path=directory/'public-invalid.pyc'
            try:
                path.write_bytes(b'UNTRUSTED CACHE')
                with self.assertRaises(app.SecurityAssuranceReviewError):self.review()
            finally:
                path.unlink()
                if created:directory.rmdir()
    suite=unittest.TestSuite((original,unittest.defaultTestLoader.loadTestsFromTestCase(ActualAssuranceTests)))
    if suite.countTestCases()!=11:raise SystemExit('SECURITY_NATIVE_DISCOVERY_DENIED')
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
        raise SystemExit('SECURITY_NATIVE_TEST_DENIED')
    verify(root)
    print(f'ACTUAL_PINNED_SECURITY_PROVENANCE_OK 11/11; {EXPECTED_DIGEST}; unsigned untrusted public fixture only')


if __name__=='__main__':main()
