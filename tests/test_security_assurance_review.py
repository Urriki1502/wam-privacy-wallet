"""Negative/protocol evidence, not execution proof; native CI uses real helper."""
from dataclasses import FrozenInstanceError
import importlib.machinery
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from wam_privacy_wallet.application import security_assurance_review as app


class SecurityAssuranceReviewTests(unittest.TestCase):
    def review(self,**kwargs):return app.review_public_assurance_fixture(**(dict(scope="synthetic-regtest",consent=True)|kwargs))
    def test_denied_consent_before_source_lookup_or_io(self):
        with patch.object(app.subprocess,"run") as source:
            for value in (False,None,1,"yes"):
                with self.assertRaisesRegex(app.SecurityAssuranceReviewError,"^APP_SECURITY_ASSURANCE_DENIED$"):self.review(consent=value)
            source.assert_not_called()
    def test_mainnet_or_nonprimitive_scope_denied_before_import(self):
        class Hook(str): pass
        with patch.object(app.subprocess,"run") as source:
            for scope in ("mainnet","regtest",Hook("synthetic-regtest")):
                with self.assertRaises(app.SecurityAssuranceReviewError):self.review(scope=scope)
            source.assert_not_called()
    def test_missing_dependency_is_fail_closed_without_fallback(self):
        with patch.object(app.importlib.util,"find_spec",return_value=None):
            with self.assertRaisesRegex(app.SecurityAssuranceReviewError,"^APP_SECURITY_ASSURANCE_DENIED$"):app._execute_public_fixture()
    def test_wrong_source_bytes_denied_before_upstream_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/"__init__.py").write_bytes(b"PRIVATE")
            spec=importlib.machinery.ModuleSpec("wam_security",None,origin=str(root/"__init__.py"))
            with patch.object(app.importlib.util,"find_spec",return_value=spec):
                with self.assertRaisesRegex(app.SecurityAssuranceReviewError,"^APP_SECURITY_ASSURANCE_DENIED$"):app._execute_public_fixture()
    def test_source_io_or_private_errors_are_redacted(self):
        with patch.object(app,"_verify_source",side_effect=RuntimeError("PRIVATE PATH")):
            with self.assertRaisesRegex(app.SecurityAssuranceReviewError,"^APP_SECURITY_ASSURANCE_DENIED$"):app._execute_public_fixture()
    def test_fixed_child_command_and_public_request_protocol_only(self):
        import json, subprocess, sys
        from dataclasses import asdict
        reply=json.dumps(asdict(app.SecurityAssuranceReview("0"*64))).encode()
        with patch.object(app.subprocess,"run",return_value=subprocess.CompletedProcess([],0,reply)) as child:
            self.assertEqual(self.review().provenance_digest,"0"*64)
            args,kwargs=child.call_args
            self.assertEqual(args[0],[sys.executable,"-I","-B","-m","wam_privacy_wallet.application._security_assurance_worker"])
            self.assertEqual(kwargs["input"],b"PUBLIC_ASSURANCE_FIXTURE_V1\n")

    def test_forged_child_publisher_runtime_release_sign_or_send_flags_denied(self):
        import json, subprocess
        from dataclasses import asdict
        reply=asdict(app.SecurityAssuranceReview("0"*64))
        for field in ("publisher_authenticated","runtime_authenticated","release_allowed","sign_allowed","broadcast_allowed"):
            with patch.object(app.subprocess,"run",return_value=subprocess.CompletedProcess([],0,json.dumps(reply|{field:True}).encode())):
                with self.assertRaises(app.SecurityAssuranceReviewError):self.review()

    def test_forged_child_digest_shape_counts_or_pin_denied(self):
        import json, subprocess
        from dataclasses import asdict
        reply=asdict(app.SecurityAssuranceReview("0"*64))
        for field,value in (("provenance_digest","PRIVATE"),("subject_count",True),("dependency_count",4),("source_commit","forged"),("evidence","AUTHENTICATED")):
            with patch.object(app.subprocess,"run",return_value=subprocess.CompletedProcess([],0,json.dumps(reply|{field:value}).encode())):
                with self.assertRaises(app.SecurityAssuranceReviewError):self.review()
        for raw in (b"PRIVATE",b"x"*2049,b"[]"):
            with patch.object(app.subprocess,"run",return_value=subprocess.CompletedProcess([],0,raw)):
                with self.assertRaises(app.SecurityAssuranceReviewError):self.review()

    def test_child_timeout_failure_and_private_exception_are_redacted(self):
        import subprocess
        for failure in (subprocess.TimeoutExpired(["PRIVATE"],15),RuntimeError("PRIVATE")):
            with patch.object(app.subprocess,"run",side_effect=failure):
                with self.assertRaisesRegex(app.SecurityAssuranceReviewError,"^APP_SECURITY_ASSURANCE_DENIED$"):self.review()
        with patch.object(app.subprocess,"run",return_value=subprocess.CompletedProcess([],2,b"PRIVATE")):
            with self.assertRaisesRegex(app.SecurityAssuranceReviewError,"^APP_SECURITY_ASSURANCE_DENIED$"):self.review()

    def test_api_accepts_no_artifact_path_or_untrusted_statement(self):
        with self.assertRaises(TypeError):app.review_public_assurance_fixture(scope="synthetic-regtest",consent=True,artifact="PRIVATE")
        with self.assertRaises(TypeError):app.review_public_assurance_fixture(scope="synthetic-regtest",consent=True,statement={})
    def test_receipt_is_frozen_and_does_not_contain_file_or_key_material(self):
        r=app.SecurityAssuranceReview("0"*64)
        with self.assertRaises(FrozenInstanceError):r.release_allowed=True
        self.assertFalse(hasattr(r,"statement") or hasattr(r,"path") or hasattr(r,"key"))
    def test_receipt_has_no_publisher_runtime_release_or_signing_authority(self):
        r=app.SecurityAssuranceReview("0"*64)
        for name in ("publisher_authenticated","runtime_authenticated","release_allowed","sign_allowed","broadcast_allowed"):
            self.assertIs(getattr(r,name),False)


if __name__=="__main__":unittest.main()
