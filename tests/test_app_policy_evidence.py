"""Offline redacted privacy-policy model evidence tests; no Core or signer."""
from __future__ import annotations

import dataclasses
import unittest

from wam_privacy_wallet.application.policy_evidence import (
    NETWORK_POLICY_BLOB_SHA,
    NETWORK_POLICY_PATH,
    PAYJOIN_VALIDATOR_BLOB_SHA,
    PAYJOIN_VALIDATOR_PATH,
    PolicyEvidenceError,
    RESEARCH_COMMIT_SHA,
    RESEARCH_REPOSITORY,
    SyntheticPolicyReport,
    inspect_synthetic_policy_evidence,
)


def fixture():
    network = {
        "schema": 1,
        "scan_route": "local",
        "broadcast_route": "tor",
        "broadcast_encrypted": False,
        "async_payjoin": False,
        "payjoin_route": None,
        "direct_fallback_present": False,
        "result": "PASS",
    }
    payjoin = {
        "schema": 1,
        "receiver_inputs_added": 1,
        "output_substitution": False,
        "sender_fee_contribution_used": False,
        "absolute_fee_increased": True,
        "result": "PASS",
    }
    return network, payjoin


class SyntheticPolicyEvidenceTests(unittest.TestCase):
    def deny(self, network, payjoin):
        with self.assertRaisesRegex(
            PolicyEvidenceError, "^APP_SYNTHETIC_POLICY_EVIDENCE_DENIED$"
        ):
            inspect_synthetic_policy_evidence(network, payjoin)

    def test_valid_redacted_fixture_only_reports_untrusted_model(self):
        network, payjoin = fixture()
        report = inspect_synthetic_policy_evidence(network, payjoin)
        self.assertEqual(report, SyntheticPolicyReport(
            "PIN_RECORDED_UNATTESTED",
            "MODEL_PASS_UNTRUSTED", "MODEL_PASS_UNTRUSTED",
            "MODEL_ONLY_NO_AUTHORITY", "BLOCKED", "BLOCKED", "BLOCKED",
        ))

    def test_report_is_immutable_and_contains_no_execution_capability(self):
        network, payjoin = fixture()
        report = inspect_synthetic_policy_evidence(network, payjoin)
        self.assertFalse(hasattr(report, "__dict__"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            report.sign = "READY"
        self.assertEqual(
            tuple(f.name for f in dataclasses.fields(report)),
            ("provenance", "network", "payjoin", "authority", "scan", "sign", "send"),
        )
        for name in ("rpc", "wallet", "client", "signer", "scanner", "send_tx",
                     "broadcast", "approve", "endpoint", "key", "secret"):
            self.assertFalse(hasattr(report, name))

    def test_source_commit_and_blob_pins_are_exact(self):
        self.assertEqual(RESEARCH_REPOSITORY, "Urriki1502/wam-privacy")
        self.assertEqual(RESEARCH_COMMIT_SHA, "db3d2dcaa540f1129d540101813b761167d33174")
        self.assertEqual(NETWORK_POLICY_PATH, "prototypes/network_privacy/policy.py")
        self.assertEqual(NETWORK_POLICY_BLOB_SHA, "3d24c9a9a010220503e6c81251da7c42309a63a0")
        self.assertEqual(PAYJOIN_VALIDATOR_PATH, "prototypes/payjoin_safety/validator.py")
        self.assertEqual(PAYJOIN_VALIDATOR_BLOB_SHA, "598596a8bde118204b3baf69bb53a884c6dad21a")

    def test_non_dict_or_forged_container_denied(self):
        good_network, good_payjoin = fixture()
        for bad in (None, [], (), True, 1, "PASS", object()):
            with self.subTest(kind=type(bad).__name__):
                self.deny(bad, good_payjoin)
                self.deny(good_network, bad)

    def test_missing_or_extra_metadata_is_not_leaked(self):
        a, b = fixture()
        missing = dict(a)
        missing.pop("scan_route")
        self.deny(missing, b)
        extra = dict(a, password="TOP_SECRET")
        self.deny(extra, b)
        missing_b = dict(b)
        missing_b.pop("receiver_inputs_added")
        self.deny(a, missing_b)
        self.deny(a, dict(b, credential="TOP_SECRET"))

    def test_schema_and_result_cannot_be_promoted(self):
        a, b = fixture()
        for key, values in (
            ("schema", (True, "1", 2, None)),
            ("result", ("APPROVED", "READY", "REJECT", True)),
        ):
            for value in values:
                with self.subTest(key=key, val=value):
                    self.deny(dict(a, **{key: value}), b)
                    self.deny(a, dict(b, **{key: value}))

    def test_scan_route_must_be_local_and_broadcast_private(self):
        a, b = fixture()
        for route in ("direct", "remote", "http", "LOCAL", None, True):
            with self.subTest(scan=route):
                self.deny(dict(a, scan_route=route), b)
        for route in ("direct", "local", "clearnet", "TOR", None, True):
            with self.subTest(broadcast=route):
                self.deny(dict(a, broadcast_route=route), b)
        for route in ("tor", "i2p", "ohttp"):
            with self.subTest(private=route):
                self.assertEqual(
                    inspect_synthetic_policy_evidence(
                        dict(a, broadcast_route=route), b
                    ).authority, "MODEL_ONLY_NO_AUTHORITY",
                )

    def test_async_payjoin_requires_exact_ohttp_and_sync_requires_none(self):
        a, b = fixture()
        self.assertEqual(
            inspect_synthetic_policy_evidence(
                dict(a, async_payjoin=True, payjoin_route="ohttp"), b
            ).payjoin,
            "MODEL_PASS_UNTRUSTED",
        )
        for route in (None, "direct", "tor", "i2p", "OHTTP", True):
            self.deny(dict(a, async_payjoin=True, payjoin_route=route), b)
        for route in ("ohttp", "tor", "direct", True):
            self.deny(dict(a, payjoin_route=route), b)

    def test_direct_fallback_and_untyped_network_flags_denied(self):
        a, b = fixture()
        for key, values in (
            ("direct_fallback_present", (True, 0, 1, None, "false")),
            ("broadcast_encrypted", (0, "true", None)),
            ("async_payjoin", (0, "false", None)),
        ):
            for value in values:
                with self.subTest(flag=key, value=value):
                    self.deny(dict(a, **{key: value}), b)

    def test_payjoin_receiver_count_requires_positive_strict_int(self):
        a, b = fixture()
        for count in (0, -1, 129, True, False, 1.0, "1", None):
            with self.subTest(receiver_count=count):
                self.deny(a, dict(b, receiver_inputs_added=count))
        self.assertEqual(
            inspect_synthetic_policy_evidence(
                a, dict(b, receiver_inputs_added=128)
            ).sign, "BLOCKED",
        )

    def test_payjoin_substitution_and_untyped_flags_denied(self):
        a, b = fixture()
        for key, values in (
            ("output_substitution", (True, None, 0, "false")),
            ("sender_fee_contribution_used", (0, "true", None)),
            ("absolute_fee_increased", (1, "false", None)),
        ):
            for value in values:
                with self.subTest(key=key, value=value):
                    self.deny(a, dict(b, **{key: value}))

    def test_model_result_does_not_retain_sensitive_or_mutable_inputs(self):
        a, b = fixture()
        report = inspect_synthetic_policy_evidence(a, b)
        a["scan_route"] = "sensitive.host.example"
        b["result"] = "PRIVATE_SECRET"
        self.assertNotIn("sensitive", repr(report).lower())
        self.assertNotIn("private_secret", repr(report).lower())
        self.assertEqual(report.scan, "BLOCKED")
        self.assertEqual(report.sign, "BLOCKED")
        self.assertEqual(report.send, "BLOCKED")


if __name__ == "__main__":
    unittest.main()
