"""Pinned pure research validators — fixed synthetic input only, never Core."""
from __future__ import annotations

import dataclasses
from hashlib import sha1
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import synthetic_policy_demo as demo


class PinnedSyntheticPolicyDemoTests(unittest.TestCase):
    def test_actual_pure_validators_compose_to_untrusted_report(self):
        report = demo.run_fixed_synthetic_privacy_demo()
        self.assertEqual(report.provenance, "PIN_RECORDED_UNATTESTED")
        self.assertEqual(report.network, "MODEL_PASS_UNTRUSTED")
        self.assertEqual(report.payjoin, "MODEL_PASS_UNTRUSTED")
        self.assertEqual(report.authority, "MODEL_ONLY_NO_AUTHORITY")
        self.assertEqual((report.scan, report.sign, report.send), ("BLOCKED",) * 3)

    def test_vendor_code_is_byte_identical_to_pinned_upstream_blobs(self):
        self.assertEqual(len(demo._PINNED_FILES), 4)
        # Windows checkout must not silently CRLF-convert SHA-pinned blobs.
        attrs = (demo._SOURCE_ROOT.parents[1] / ".gitattributes").read_text(encoding="utf-8")
        for path in demo._PINNED_FILES:
            self.assertIn(f"src/wam_privacy_wallet/{path} text eol=lf", attrs)
        for path, expected in demo._PINNED_FILES.items():
            with self.subTest(source=path):
                data = (demo._SOURCE_ROOT / path).read_bytes()
                actual = sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
                self.assertEqual(actual, expected)
        demo._verify_source_bytes()

    def test_tampered_vendor_source_fails_closed_before_execution(self):
        with tempfile.TemporaryDirectory(prefix="wam-synthetic-pin-") as tmp:
            source = Path(tmp)
            (source / "research_models/network_privacy").mkdir(parents=True)
            (source / "research_models/network_privacy/model.py").write_text(
                "print('UNTRUSTED')\n", encoding="utf-8"
            )
            with patch.object(demo, "_SOURCE_ROOT", source):
                with self.assertRaisesRegex(
                    demo.SyntheticDemoError, "^APP_SYNTHETIC_MODEL_PIN_DENIED$"
                ):
                    demo.run_fixed_synthetic_privacy_demo()

    def test_absent_vendor_files_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="wam-synthetic-missing-") as tmp:
            with patch.object(demo, "_SOURCE_ROOT", Path(tmp)):
                with self.assertRaisesRegex(
                    demo.SyntheticDemoError, "^APP_SYNTHETIC_MODEL_PIN_DENIED$"
                ):
                    demo.run_fixed_synthetic_privacy_demo()

    def test_demo_never_attempts_network_socket_or_subprocess(self):
        import socket
        from urllib import request

        with (patch.object(socket, "socket", side_effect=AssertionError("socket used")),
              patch.object(socket, "create_connection", side_effect=AssertionError("network")),
              patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
              patch.object(request, "urlopen", side_effect=AssertionError("urlopen"))):
            self.assertEqual(
                demo.run_fixed_synthetic_privacy_demo().send, "BLOCKED"
            )

    def test_model_failure_or_exception_is_redacted(self):
        with patch.object(demo, "inspect_synthetic_policy_evidence",
                          side_effect=ValueError("PRIVATE_SECRET")):
            with self.assertRaisesRegex(
                demo.SyntheticDemoError, "^APP_SYNTHETIC_MODEL_EXECUTION_DENIED$"
            ) as outcome:
                demo.run_fixed_synthetic_privacy_demo()
            self.assertNotIn("PRIVATE_SECRET", str(outcome.exception))
            self.assertIsNone(outcome.exception.__cause__)

    def test_reports_are_fixed_immutable_and_no_authority(self):
        report = demo.run_fixed_synthetic_privacy_demo()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            report.send = "READY"
        for name in ("transaction", "txid", "psbt", "wallet", "signer",
                     "endpoint", "hostname", "rpc", "key", "broadcast", "scanner"):
            with self.subTest(field=name):
                self.assertFalse(hasattr(report, name))
        self.assertNotIn("synthetic-receiver", repr(report))
        self.assertNotIn("example.invalid", repr(report))
        self.assertNotIn("100000", repr(report))

    def test_repeatable_no_argument_demo_never_grants_capabilities(self):
        a = demo.run_fixed_synthetic_privacy_demo()
        b = demo.run_fixed_synthetic_privacy_demo()
        self.assertEqual(a, b)
        self.assertIsNot(a, b)
        with self.assertRaises(TypeError):
            demo.run_fixed_synthetic_privacy_demo({"spend": True})


if __name__ == "__main__":
    unittest.main()
