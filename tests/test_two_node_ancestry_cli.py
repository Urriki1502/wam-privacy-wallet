"""CLI boundary tests; operational ancestry RPC has separate real TCP tests."""
from __future__ import annotations

import contextlib
import io
import json
import subprocess
import unittest
from unittest.mock import patch

from tools import audit_two_node_ancestry as cli


ARGUMENTS = [
    "--node-a-host", "127.0.0.1",
    "--node-a-port", "39101",
    "--node-a-rpc-user", "regtest_a",
    "--node-b-host", "127.0.0.1",
    "--node-b-port", "39103",
    "--node-b-rpc-user", "regtest_b",
]
OUTPUT = {
    "status": "UNTRUSTED_TWO_NODE_BOUNDED_ANCESTRY_ONLY",
    "scanner_enabled": False,
    "signing_allowed": False,
    "mainnet_allowed": False,
    "genuine_core_processes_verified": False,
    "block_parent_links_verified": False,
    "real_two_node_regtest_qualified": False,
    "wallet_ready": False,
    "broadcast_allowed": False,
    "height": 3,
    "window_start": 1,
    "window_count": 3,
    "independent_rpc_endpoints": 2,
    "height_hash_read_passes": 2,
    "reported_histories_agree": True,
}


class BoundedAncestryCliTests(unittest.TestCase):
    def _invoke(self, arguments=None, *, tty=True, secrets=("ONE", "TWO"),
                audit_output=OUTPUT, audit_error=None, header_output=None,
                header_error=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        args = ARGUMENTS if arguments is None else arguments
        with patch("tools.audit_two_node_ancestry.sys.stdin") as stdin, \
             patch("tools.audit_two_node_ancestry.getpass.getpass",
                   side_effect=secrets) as prompt, \
             patch("tools.audit_two_node_ancestry.TwoNodeBoundedAncestry") as audit, \
             patch("tools.audit_two_node_ancestry.TwoNodeHeaderLinkAuditor") as header_audit, \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            stdin.isatty.return_value = tty
            if audit_error is not None:
                audit.return_value.audit.side_effect = audit_error
            else:
                audit.return_value.audit.return_value = audit_output
            header_audit.return_value.audit.return_value = (
                self._default_header() if header_output is None else header_output
            )
            if header_error is not None:
                header_audit.return_value.audit.side_effect = header_error
            self.header_audit_mock = header_audit
            code = cli.main(args)
        return code, stdout.getvalue(), stderr.getvalue(), prompt, audit

    @staticmethod
    def _default_header():
        return {
            "status": "UNTRUSTED_TWO_NODE_RPC_HEADER_LINKS_ONLY",
            "height": 3,
            "window_start": 1,
            "window_count": 3,
            "independent_rpc_endpoints": 2,
            "header_link_read_passes": 2,
            "rpc_reported_parent_links_match": True,
            "genuine_core_processes_verified": False,
            "cryptographic_headers_verified": False,
            "block_parent_links_verified": False,
            "real_two_node_regtest_qualified": False,
            "scanner_enabled": False,
            "wallet_ready": False,
            "signing_allowed": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
        }

    def test_optional_header_review_reuses_one_tty_prompt_pair(self):
        receipt = {**OUTPUT, "height": 3, "window_start": 1, "window_count": 3}
        code, out, err, prompt, _ = self._invoke(
            ARGUMENTS + ["--include-header-links"], audit_output=receipt,
        )
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(prompt.call_count, 2)
        self.assertEqual(self.header_audit_mock.call_count, 1)
        self.assertEqual(self.header_audit_mock.call_args.args[1].password, "ONE")
        self.assertEqual(self.header_audit_mock.call_args.args[3].password, "TWO")
        payload = json.loads(out)
        self.assertTrue(payload["rpc_reported_parent_links_match"])
        self.assertIs(payload["same_epoch_proven"], False)
        self.assertIs(payload["cryptographic_headers_verified"], False)
        self.assertIs(payload["signing_allowed"], False)

    def test_default_cli_does_not_send_header_rpc_requests(self):
        code, _, _, _, _ = self._invoke()
        self.assertEqual(code, 0)
        self.header_audit_mock.assert_not_called()

    def test_header_forged_authority_and_missing_flags_denied(self):
        receipt = {**OUTPUT, "height": 3, "window_start": 1, "window_count": 3}
        for header in (
            {**self._default_header(), "signing_allowed": True},
            {**self._default_header(), "cryptographic_headers_verified": True},
            {**self._default_header(), "rpc_reported_parent_links_match": False},
            {"status": "APPROVED"},
            {},
        ):
            with self.subTest(header=header.get("status")):
                code, out, err, _, _ = self._invoke(
                    ARGUMENTS + ["--include-header-links"], audit_output=receipt,
                    header_output=header,
                )
                self.assertEqual((code, out), (2, ""))
                self.assertEqual(err.strip(), "REGTEST_ANCESTRY_HEADER_AUTHORITY_DENIED")

    def test_header_height_window_epoch_mismatch_is_denied(self):
        receipt = {**OUTPUT, "height": 3, "window_start": 1, "window_count": 3}
        for changed in (
            {"height": 4}, {"window_start": 0}, {"window_count": 4},
            {"height": True},
        ):
            with self.subTest(changed=changed):
                code, out, err, _, _ = self._invoke(
                    ARGUMENTS + ["--include-header-links"], audit_output=receipt,
                    header_output={**self._default_header(), **changed},
                )
                self.assertEqual((code, out), (2, ""))
                self.assertEqual(err.strip(), "REGTEST_ANCESTRY_HEADER_EPOCH_DENIED")

    def test_header_transport_failure_redacted_and_no_output(self):
        receipt = {**OUTPUT, "height": 3, "window_start": 1, "window_count": 3}
        code, out, err, _, _ = self._invoke(
            ARGUMENTS + ["--include-header-links"], audit_output=receipt,
            header_error=cli.TwoNodeHeaderLinkError("REMOTE_SECRET_BODY"),
        )
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(err.strip(), "REGTEST_ANCESTRY_HEADER_RPC_DENIED")
        self.assertNotIn("REMOTE_SECRET_BODY", err)

    def test_valid_interactive_run_is_nonauthorizing_json(self):
        code, out, err, prompt, audit = self._invoke()
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out), OUTPUT)
        self.assertEqual(prompt.call_count, 2)
        self.assertEqual(audit.return_value.audit.call_args.kwargs["window_size"], 8)
        self.assertEqual(audit.call_args.args[1].password, "ONE")
        self.assertEqual(audit.call_args.args[3].password, "TWO")

    def test_explicit_window_sixteen_passes_through(self):
        code, _, _, _, audit = self._invoke(ARGUMENTS + ["--window-size", "16"])
        self.assertEqual(code, 0)
        self.assertEqual(audit.return_value.audit.call_args.kwargs["window_size"], 16)

    def test_invalid_window_values_fail_before_tty_prompt(self):
        for bad in ("0", "17", "-1", "1000000"):
            with self.subTest(bad=bad):
                code, out, err, prompt, audit = self._invoke(
                    ARGUMENTS + ["--window-size", bad],
                )
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("REGTEST_ANCESTRY_WINDOW_DENIED", err)
                prompt.assert_not_called()
                audit.assert_not_called()

    def test_duplicate_endpoint_fails_before_prompt(self):
        a = list(ARGUMENTS)
        a[a.index("--node-b-port") + 1] = "39101"
        code, _, err, prompt, audit = self._invoke(a)
        self.assertEqual(code, 2)
        self.assertIn("REGTEST_ANCESTRY_DUPLICATE_ENDPOINT", err)
        prompt.assert_not_called()
        audit.assert_not_called()

    def test_remote_dns_and_unspecified_hosts_fail_before_prompt(self):
        for invalid in ("example.org", "192.168.1.10", "0.0.0.0"):
            with self.subTest(host=invalid):
                a = list(ARGUMENTS)
                a[a.index("--node-b-host") + 1] = invalid
                code, out, err, prompt, audit = self._invoke(a)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("REGTEST_ANCESTRY_INPUT_DENIED", err)
                prompt.assert_not_called()
                audit.assert_not_called()

    def test_malformed_rpc_username_fails_before_prompt(self):
        a = list(ARGUMENTS)
        a[a.index("--node-a-rpc-user") + 1] = "bad:name"
        code, out, err, prompt, audit = self._invoke(a)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("REGTEST_ANCESTRY_INPUT_DENIED", err)
        prompt.assert_not_called()
        audit.assert_not_called()

    def test_noninteractive_stdio_is_denied_no_secret_prompts(self):
        code, out, err, prompt, audit = self._invoke(tty=False)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("REGTEST_ANCESTRY_TTY_REQUIRED", err)
        prompt.assert_not_called()
        audit.assert_not_called()

    def test_failed_password_prompt_is_redacted(self):
        code, out, err, _, audit = self._invoke(secrets=("SECRET_ONE", KeyboardInterrupt()))
        self.assertEqual((code, out), (2, ""))
        self.assertIn("REGTEST_ANCESTRY_INPUT_DENIED", err)
        self.assertNotIn("SECRET_ONE", err)
        audit.assert_not_called()

    def test_rpc_denial_does_not_leak_password_or_remote_error(self):
        code, out, err, _, audit = self._invoke(
            secrets=("SECRET_ONE", "SECRET_TWO"),
            audit_error=cli.TwoNodeAncestryError("REGTEST_ANCESTRY_RPC_DENIED"),
        )
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(err.strip(), "REGTEST_ANCESTRY_RPC_DENIED")
        self.assertNotIn("SECRET", err)
        self.assertEqual(audit.call_count, 1)

    def test_forged_true_authority_is_redacted_and_denied(self):
        for field in ("scanner_enabled", "wallet_ready", "signing_allowed",
                      "broadcast_allowed", "mainnet_allowed",
                      "genuine_core_processes_verified",
                      "block_parent_links_verified",
                      "real_two_node_regtest_qualified"):
            with self.subTest(field=field):
                code, out, err, _, _ = self._invoke(
                    audit_output={**OUTPUT, field: True},
                )
                self.assertEqual((code, out), (2, ""))
                self.assertEqual(err.strip(), "REGTEST_ANCESTRY_AUTHORITY_DENIED")

    def test_missing_or_malformed_review_receipt_is_refused(self):
        for report in (
            {}, [], None, {**OUTPUT, "status": "CORE_APPROVED"},
            {key: value for key, value in OUTPUT.items() if key != "wallet_ready"},
        ):
            with self.subTest(type=type(report).__name__):
                code, out, err, _, _ = self._invoke(audit_output=report)
                self.assertEqual((code, out), (2, ""))
                self.assertEqual(err.strip(), "REGTEST_ANCESTRY_AUTHORITY_DENIED")

    def test_secret_bearing_extra_ancestry_fields_are_refused(self):
        for fake in (
            {**OUTPUT, "rpc_password": "SUPER_SECRET"},
            {**OUTPUT, "height": True},
            {**OUTPUT, "reported_histories_agree": 1},
            {**OUTPUT, "window_count": 17},
        ):
            with self.subTest(keys=tuple(fake)):
                code, out, err, _, _ = self._invoke(audit_output=fake)
                self.assertEqual((code, out), (2, ""))
                self.assertEqual(err.strip(), "REGTEST_ANCESTRY_RECEIPT_DENIED")
                self.assertNotIn("SUPER_SECRET", err)

    def test_header_extra_fields_or_fake_pass_count_denied(self):
        for fake in (
            {**self._default_header(), "private_key": "SECRET"},
            {**self._default_header(), "header_link_read_passes": 1},
            {**self._default_header(), "independent_rpc_endpoints": True},
        ):
            with self.subTest(header=fake.get("header_link_read_passes")):
                code, out, err, _, _ = self._invoke(
                    ARGUMENTS + ["--include-header-links"],
                    header_output=fake,
                )
                self.assertEqual((code, out), (2, ""))
                self.assertEqual(err.strip(), "REGTEST_ANCESTRY_HEADER_AUTHORITY_DENIED")
                self.assertNotIn("SECRET", err)

    def test_live_cli_boundary_never_launches_core(self):
        with patch.object(subprocess, "Popen",
                          side_effect=AssertionError("NO_CORE_PROCESS")):
            code, output, _, _, _ = self._invoke()
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(output)["genuine_core_processes_verified"])


if __name__ == "__main__":
    unittest.main()
