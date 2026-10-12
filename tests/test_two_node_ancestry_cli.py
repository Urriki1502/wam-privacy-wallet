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
}


class BoundedAncestryCliTests(unittest.TestCase):
    def _invoke(self, arguments=None, *, tty=True, secrets=("ONE", "TWO"),
                audit_output=OUTPUT, audit_error=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        args = ARGUMENTS if arguments is None else arguments
        with patch("tools.audit_two_node_ancestry.sys.stdin") as stdin, \
             patch("tools.audit_two_node_ancestry.getpass.getpass",
                   side_effect=secrets) as prompt, \
             patch("tools.audit_two_node_ancestry.TwoNodeBoundedAncestry") as audit, \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            stdin.isatty.return_value = tty
            if audit_error is not None:
                audit.return_value.audit.side_effect = audit_error
            else:
                audit.return_value.audit.return_value = audit_output
            code = cli.main(args)
        return code, stdout.getvalue(), stderr.getvalue(), prompt, audit

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

    def test_live_cli_boundary_never_launches_core(self):
        with patch.object(subprocess, "Popen",
                          side_effect=AssertionError("NO_CORE_PROCESS")):
            code, output, _, _, _ = self._invoke()
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(output)["genuine_core_processes_verified"])


if __name__ == "__main__":
    unittest.main()
