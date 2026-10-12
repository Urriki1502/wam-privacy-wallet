"""Protocol/negative checks ONLY; native CI executes actual pinned Rust HPKE."""
from dataclasses import FrozenInstanceError, asdict
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from wam_privacy_wallet.application import selective_disclosure_review as app


class DisclosureReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.executable = self.root / ("wam-wallet-hpke-readonly.exe" if sys.platform == "win32" else "wam-wallet-hpke-readonly")
        self.executable.write_bytes(b"NONEXECUTABLE_PROTOCOL_FIXTURE")
        self.manifest = self.root / "hpke-public-fixture-build.json"
        self.build = dict(source_commit=app._PIN, worker_sha256=sha256(self.executable.read_bytes()).hexdigest(), pointer_bits=struct.calcsize("P")*8, platform=sys.platform, release_allowed=False)
        self.manifest.write_text(json.dumps(self.build))
        self.reply = dict(source_commit=app._PIN, role="incoming", negative_checks=14, pointer_bits=struct.calcsize("P")*8, evidence="PUBLIC_HPKE_FIXTURE_EXECUTED_UNTRUSTED", external_review_complete=False, runtime_authenticated=False, spend_authorized=False, sign_allowed=False, broadcast_allowed=False)
        self.addCleanup(patch.stopall); patch.object(app, "_NATIVE", self.root).start()
        self.child = patch.object(app.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(self.reply).encode())).start()
    def review(self, **kwargs):
        return app.review_public_disclosure_fixture(**(dict(role="incoming", scope="synthetic-regtest", consent=True)|kwargs))
    def denied(self, **kwargs):
        with self.assertRaisesRegex(app.SelectiveDisclosureReviewError, "^APP_DISCLOSURE_FIXTURE_DENIED$"): self.review(**kwargs)
    def test_no_consent_or_wrong_scope_denied_before_files_or_child(self):
        with patch.object(Path, "stat", side_effect=AssertionError("NO_IO")):
            for kwargs in ({"consent": False}, {"consent": 1}, {"scope": "mainnet"}): self.denied(**kwargs)
        self.child.assert_not_called()
    def test_unknown_or_nonprimitive_role_cannot_select_arbitrary_worker(self):
        class Hook(str): pass
        for role in ("spend", "../signer", Hook("incoming"), None): self.denied(role=role)
        self.child.assert_not_called()
    def test_fixed_command_and_public_request_protocol(self):
        value=self.review(); args,kwargs=self.child.call_args
        self.assertEqual(args[0], [str(self.executable)])
        self.assertEqual(kwargs["input"], b"PUBLIC_SYNTHETIC_HPKE_V1:incoming\n")
        self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(value, app.SelectiveDisclosureReview("incoming", 14))
    def test_build_digest_tampering_denied_before_child(self):
        self.executable.write_bytes(b"CHANGED")
        self.denied(); self.child.assert_not_called()
    def test_unqualified_build_platform_width_pin_or_authority_denied(self):
        for key,value in (("platform","foreign"),("pointer_bits",0),("source_commit","forged"),("release_allowed",True)):
            self.manifest.write_text(json.dumps(self.build|{key:value}))
            self.denied()
        self.child.assert_not_called()
    def test_missing_or_extra_manifest_fields_denied(self):
        for value in ({}, self.build|{"signer":True}, []):
            self.manifest.write_text(json.dumps(value)); self.denied()
        self.child.assert_not_called()
    def test_oversize_manifest_or_binary_denied(self):
        self.manifest.write_bytes(b"x"*1025); self.denied(); self.child.assert_not_called()
    def test_native_failure_timeout_and_error_are_redacted(self):
        self.child.side_effect=RuntimeError("PRIVATE PATH"); self.denied()
        self.child.side_effect=subprocess.TimeoutExpired(["PRIVATE"],15); self.denied()
        self.child.side_effect=None; self.child.return_value=subprocess.CompletedProcess([],2,b"PRIVATE"); self.denied()
    def test_bad_or_oversize_worker_reply_denied(self):
        for raw in (b"PRIVATE", b"x"*2049, b"[]", json.dumps(self.reply|{"extra":1}).encode()):
            self.child.return_value=subprocess.CompletedProcess([],0,raw); self.denied()
    def test_forged_review_spend_sign_broadcast_or_authentication_denied(self):
        for key in ("external_review_complete","runtime_authenticated","spend_authorized","sign_allowed","broadcast_allowed"):
            self.child.return_value=subprocess.CompletedProcess([],0,json.dumps(self.reply|{key:True}).encode()); self.denied()
    def test_forged_role_pin_evidence_width_or_bool_count_denied(self):
        for key,value in (("role","audit"),("source_commit","forged"),("evidence","VERIFIED"),("pointer_bits",1),("negative_checks",True)):
            self.child.return_value=subprocess.CompletedProcess([],0,json.dumps(self.reply|{key:value}).encode()); self.denied()
    def test_receipt_is_frozen_and_contains_no_keys_notes_or_paths(self):
        value=self.review()
        with self.assertRaises(FrozenInstanceError): value.sign_allowed=True
        self.assertEqual(set(asdict(value)), app._FIELDS-{"pointer_bits"})


if __name__=="__main__": unittest.main()
