"""DEV-core help/example parity parser: synthetic offline fixtures only.

Passing these tests never proves actual signed release or --help provenance.
"""
from __future__ import annotations

from dataclasses import fields
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node import core_help_example_parity as audit
from tools import verify_core_help_example_parity as cli

_HELP = b"Options:\n  -server=<0|1>  RPC server\n  -rpcbind=<addr> Bind\n  -regtest  Test\n  -rpcpassword=<pass> Secret\n"
_CONF = b"# WAM daemon sample\n#server=0\n#rpcbind=127.0.0.1\n#regtest=1\n#rpcpassword=<secret>\n"


class CoreHelpExampleParityTests(unittest.TestCase):
    def deny(self, code, help_text=_HELP, example=_CONF):
        with self.assertRaisesRegex(audit.CoreHelpExampleError, "^"+code+"$"):
            audit.inspect_help_example_text(help_text, example)

    def test_same_options_no_release_authority(self):
        r = audit.inspect_help_example_text(_HELP, _CONF)
        self.assertEqual(r.option_count, 4)
        self.assertTrue(r.text_option_inventory_matches)
        self.assertEqual(len(r.option_names_sha256), 64)
        for name in (
            "signed_provenance_verified", "same_executed_image_proven",
            "help_parity_verified", "safe_defaults_verified",
            "real_regtest_qualified", "core_execution_allowed",
            "signer_enabled", "broadcast_allowed", "mainnet_allowed",
        ):
            self.assertIs(getattr(r, name), False)

    def test_added_help_option_without_sample_is_denied(self):
        self.deny("CORE_CONFIG_OPTION_INVENTORY_MISMATCH",
                  _HELP+b"  -newflag=<n> new\n")

    def test_sample_unknown_option_is_denied(self):
        self.deny("CORE_CONFIG_OPTION_INVENTORY_MISMATCH",
                  example=_CONF+b"#undocumented=1\n")

    def test_help_duplicate_option_denied(self):
        self.deny("CORE_CONFIG_HELP_DUPLICATE_DENIED",
                  _HELP+b"  --RPCBIND=<addr> duplicate\n")

    def test_example_duplicate_option_denied(self):
        self.deny("CORE_CONFIG_EXAMPLE_DUPLICATE_DENIED",
                  example=_CONF+b"#RPCBIND=127.0.0.1\n")

    def test_active_option_denied_even_when_safe_loopback(self):
        self.deny("CORE_CONFIG_ACTIVE_DIRECTIVE_DENIED",
                  example=_CONF+b"rpcbind=127.0.0.1\n")

    def test_active_network_header_denied(self):
        self.deny("CORE_CONFIG_ACTIVE_DIRECTIVE_DENIED",
                  example=_CONF+b"[regtest]\n")

    def test_ipv4_wildcard_binding_comment_denied(self):
        self.deny("CORE_CONFIG_EXAMPLE_BIND_DENIED",
                  example=_CONF.replace(b"127.0.0.1", b"0.0.0.0"))

    def test_ipv6_wildcard_binding_denied(self):
        self.deny("CORE_CONFIG_EXAMPLE_BIND_DENIED",
                  example=_CONF.replace(b"127.0.0.1", b"::"))

    def test_uncommented_credential_denied(self):
        self.deny("CORE_CONFIG_ACTIVE_DIRECTIVE_DENIED",
                  example=_CONF+b"rpcpassword=examplepassword\n")

    def test_commented_literal_password_denied(self):
        self.deny("CORE_CONFIG_EXAMPLE_CREDENTIAL_DENIED",
                  example=_CONF.replace(b"<secret>", b"actual-value"))

    def test_bad_network_selector_value_denied(self):
        self.deny("CORE_CONFIG_EXAMPLE_NETWORK_DENIED",
                  example=_CONF.replace(b"#regtest=1", b"#regtest=mainnet"))

    def test_malformed_help_not_considered_proven(self):
        self.deny("CORE_CONFIG_HELP_OPTIONS_MISSING",
                  help_text=b"no options in this help capture\n")

    def test_malformed_example_no_option_inventory(self):
        self.deny("CORE_CONFIG_EXAMPLE_OPTIONS_MISSING",
                  example=b"# Example only\n")

    def test_embedded_nul_denied(self):
        self.deny("CORE_CONFIG_HELP_TEXT_DENIED", help_text=_HELP+b"\x00")

    def test_invalid_utf8_denied(self):
        self.deny("CORE_CONFIG_EXAMPLE_TEXT_DENIED", example=_CONF+b"\xff")

    def test_size_bound_enforced(self):
        self.deny("CORE_CONFIG_HELP_TEXT_DENIED", help_text=b"A"*(512*1024+1))

    def test_no_fixed_option_count_and_order_independent(self):
        help_text=b"  -foo=<x>\n  -bar\n"
        conf=b"#bar=0\n#foo=1\n"
        result=audit.inspect_help_example_text(help_text, conf)
        self.assertEqual(result.option_count, 2)

    def test_cli_reads_text_files_without_executing_any_binary(self):
        with TemporaryDirectory(prefix="wam-core-config-text-") as tmp:
            a=Path(tmp)/"help.txt"
            b=Path(tmp)/"wam.conf"
            a.write_bytes(_HELP)
            b.write_bytes(_CONF)
            import subprocess
            with patch.object(subprocess,"Popen",
                              side_effect=AssertionError("NO_WAM_LAUNCH")):
                with patch("sys.stdout",new_callable=io.StringIO) as out:
                    self.assertEqual(cli.main([
                        "--captured-help",str(a),"--example-conf",str(b)
                    ]),0)
            receipt=json.loads(out.getvalue())
            self.assertEqual(receipt["option_count"],4)
            self.assertIs(receipt["help_parity_verified"],False)

    def test_cli_refuses_relative_file_paths(self):
        with patch("sys.stderr",new_callable=io.StringIO) as err:
            self.assertEqual(cli.main([
                "--captured-help","help.txt",
                "--example-conf","./wam.conf"
            ]),2)
            self.assertIn("CORE_CONFIG_INPUT_FILE_DENIED",err.getvalue())

    def test_receipt_remains_small_and_nonauthorizing(self):
        f={x.name for x in fields(audit.CoreHelpExampleObservation)}
        self.assertFalse({"private_keys","password","wallet","seed"} & f)
        self.assertFalse(hasattr(audit,"launch_core"))
        self.assertFalse(hasattr(audit,"sign"))

if __name__ == "__main__":
    unittest.main()
