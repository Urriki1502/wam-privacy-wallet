"""Real pinned policy execution on synthetic plans; no transport claims."""
from dataclasses import FrozenInstanceError
import socket
import subprocess
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application.network_plan_review import (
    NetworkPlanReviewError, review_synthetic_network_plan,
)


def endpoint(role, host, route, **changes):
    row = dict(role=role, host=host, port=1, route=route,
               encrypted_transport=False, authenticated_transport=False,
               fallback=False)
    row.update(changes)
    return row


def plan():
    return (endpoint("chain_scan", "127.0.0.1", "local"),
            endpoint("tx_broadcast", "synthetic.invalid", "tor"))


class NetworkPlanReviewTests(unittest.TestCase):
    def review(self, rows=None, **kwargs):
        return review_synthetic_network_plan(plan() if rows is None else rows,
            **(dict(scope="synthetic-regtest", consent=True) | kwargs))

    def denied(self, rows=None, **kwargs):
        with self.assertRaisesRegex(NetworkPlanReviewError, '^APP_NETWORK_PLAN_REVIEW_DENIED$'):
            self.review(rows, **kwargs)

    def test_real_pinned_policy_runs_and_returns_no_transport_authority(self):
        value = self.review()
        self.assertEqual(value.evidence, "PINNED_MODEL_EXECUTED_UNTRUSTED_INPUT")
        self.assertFalse(value.transport_verified)
        self.assertFalse(value.scan_allowed or value.sign_allowed or value.broadcast_allowed)

    def test_each_private_route_supported_by_actual_policy(self):
        for route in ("tor", "i2p", "ohttp"):
            a, b = plan()
            b["route"] = route
            self.review((a, b))

    def test_consent_and_scope_required(self):
        for value in (False, None, 1, "yes"):
            self.denied(consent=value)
        for value in ("mainnet", "regtest", None, True):
            self.denied(scope=value)

    def test_bool_port_and_non_bool_flags_denied(self):
        for key in ("port", "fallback", "encrypted_transport", "authenticated_transport"):
            a, b = plan()
            b[key] = True if key == "port" else 1
            self.denied((a, b))

    def test_extra_credentials_or_policy_override_denied(self):
        for key in ("password", "allow_direct_fallback", "require_private_broadcast"):
            a, b = plan()
            b[key] = "PRIVATE"
            self.denied((a, b))

    def test_remote_scan_denied_by_upstream(self):
        a, b = plan()
        a.update(host="remote.invalid", route="tor")
        self.denied((a, b))

    def test_encrypted_direct_route_is_still_denied(self):
        a, b = plan()
        b.update(route="direct", encrypted_transport=True)
        self.denied((a, b))

    def test_direct_fallback_denied(self):
        self.denied(plan() + (endpoint("tx_broadcast", "fallback.invalid", "direct", fallback=True),))

    def test_public_role_reuse_denied(self):
        a, b = plan()
        self.denied((a, b, endpoint("payjoin_directory", b["host"], "ohttp")), async_payjoin=True)

    def test_async_requires_one_ohttp_directory(self):
        self.denied(async_payjoin=True)
        directory = endpoint("payjoin_directory", "directory.invalid", "ohttp")
        self.review(plan() + (directory,), async_payjoin=True)
        directory["route"] = "tor"
        self.denied(plan() + (directory,), async_payjoin=True)

    def test_duplicate_primary_and_missing_role_denied(self):
        self.denied(plan() + (dict(plan()[0]),))
        self.denied((plan()[0],))

    def test_bounds_and_subclasses_denied(self):
        self.denied(())
        self.denied(plan() * 17)
        self.denied(list(plan()))
        class Evil(dict):
            pass
        self.denied((Evil(plan()[0]), plan()[1]))
        a, b = plan()
        for host in ("x" * 256, "secret\n.invalid", "", object()):
            b["host"] = host
            self.denied((a, b))

    def test_pin_failure_and_runtime_exception_are_redacted(self):
        with patch("wam_privacy_wallet.application.network_plan_review._verify_source_bytes", side_effect=ValueError("PRIVATE")):
            self.denied()
        with patch("wam_privacy_wallet.research_models.network_privacy.policy.validate_network_plan", side_effect=RuntimeError("PRIVATE")):
            self.denied()

    def test_nonprimitive_keys_denied_without_caller_comparison(self):
        class CallbackKey(str):
            calls = 0
            __hash__ = str.__hash__
            def __eq__(self, other):
                type(self).calls += 1
                return str.__eq__(self, other)
        a, b = plan()
        a[CallbackKey("role")] = a.pop("role")
        CallbackKey.calls = 0
        with patch("wam_privacy_wallet.application.network_plan_review._verify_source_bytes") as verify:
            self.denied((a, b))
            verify.assert_not_called()
        self.assertEqual(CallbackKey.calls, 0)
        # Oversized schema denied before key comparison/source reads too.
        a, b = plan()
        a.update({f"extra-{n}": n for n in range(1000)})
        with patch("wam_privacy_wallet.application.network_plan_review._verify_source_bytes") as verify:
            self.denied((a, b))
            verify.assert_not_called()

    def test_no_network_or_subprocess_and_no_input_retention(self):
        with (patch.object(socket, "socket", side_effect=AssertionError),
              patch.object(socket, "create_connection", side_effect=AssertionError),
              patch.object(subprocess, "Popen", side_effect=AssertionError)):
            receipt = self.review()
        self.assertNotIn("synthetic.invalid", repr(receipt))
        with self.assertRaises(FrozenInstanceError):
            receipt.broadcast_allowed = True


if __name__ == '__main__':
    unittest.main()
