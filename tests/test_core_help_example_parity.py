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
    def _two_node_fixture(self):
        from wam_privacy_wallet.node.two_node_topology import plan_two_node_topology
        from wam_privacy_wallet.node.two_node_schema import build_structured_two_node_v1
        plan=plan_two_node_topology((31001,31002,32001,32002))
        names=sorted({o.key for n in build_structured_two_node_v1(plan).nodes for o in n.options})
        return plan, b"Fixture help ONLY:\n"+b"".join(
            b"  -"+name.encode()+b"=<value>\n" for name in names)

    def test_two_node_names_covered_without_core_authority(self):
        plan,help_text=self._two_node_fixture()
        r=audit.inspect_two_node_help_coverage(help_text,plan)
        self.assertEqual(r.schema_version,1)
        self.assertGreater(r.configured_option_count,10)
        for key in ('option_value_semantics_verified','same_executed_image_proven',
                    'signed_provenance_verified','help_parity_verified',
                    'core_execution_allowed','real_regtest_qualified',
                    'signer_enabled','broadcast_allowed','mainnet_allowed'):
            self.assertIs(getattr(r,key),False)

    def test_cli_two_node_option_coverage_is_explicit_and_non_authorizing(self):
        _,help_text=self._two_node_fixture()
        names=audit._help_options(help_text.decode())
        example=''.join('#'+name+'=\n' for name in sorted(names)).encode()
        with TemporaryDirectory() as root:
            help_file=Path(root)/'help.txt'; conf_file=Path(root)/'wam.conf'
            help_file.write_bytes(help_text);conf_file.write_bytes(example)
            with patch('sys.stdout',new_callable=io.StringIO) as output:
                code=cli.main(['--captured-help',str(help_file),'--example-conf',str(conf_file),
                               '--two-node-ports','31001','31002','32001','32002'])
            self.assertEqual(code,0)
            evidence=json.loads(output.getvalue())['two_node_help_coverage']
            self.assertFalse(evidence['same_executed_image_proven'])
            self.assertFalse(evidence['core_execution_allowed'])

    def test_missing_plan_option_is_refused_not_invented(self):
        plan,help_text=self._two_node_fixture()
        help_text=help_text.replace(b'  -natpmp=<value>\n',b'')
        with self.assertRaisesRegex(audit.CoreHelpExampleError,'TWO_NODE_UNSUPPORTED_OPTION'):
            audit.inspect_two_node_help_coverage(help_text,plan)

    def test_two_node_ambiguous_help_duplicate_denied(self):
        plan,help_text=self._two_node_fixture()
        with self.assertRaisesRegex(audit.CoreHelpExampleError,'HELP_DUPLICATE_DENIED'):
            audit.inspect_two_node_help_coverage(help_text+b'  -server=<value>\n',plan)

    def test_two_node_forged_loopback_policy_denied(self):
        from dataclasses import replace
        plan,help_text=self._two_node_fixture()
        forged=replace(plan,nodes=(replace(plan.nodes[0],rpc_host='0.0.0.0'),plan.nodes[1]))
        with self.assertRaisesRegex(audit.CoreHelpExampleError,'TWO_NODE_PLAN_DENIED'):
            audit.inspect_two_node_help_coverage(help_text,forged)

    def test_two_node_configuration_pair_digest_deterministic_and_port_bound(self):
        from wam_privacy_wallet.node.two_node_topology import plan_two_node_topology
        plan,help_text=self._two_node_fixture()
        a=audit.inspect_two_node_help_coverage(help_text,plan)
        self.assertEqual(a,audit.inspect_two_node_help_coverage(help_text,plan))
        b=audit.inspect_two_node_help_coverage(help_text,plan_two_node_topology((33001,33002,34001,34002)))
        self.assertNotEqual(a.configuration_pair_sha256,b.configuration_pair_sha256)

    def test_two_node_plan_cannot_forge_execution_or_scanner_enablement(self):
        from dataclasses import replace
        plan,help_text=self._two_node_fixture()
        for field in ('real_regtest_qualified','publisher_identity_verified',
                      'scanner_enabled','signing_enabled','release_allowed'):
            with self.subTest(field=field),self.assertRaises(audit.CoreHelpExampleError):
                audit.inspect_two_node_help_coverage(help_text,replace(plan,**{field:True}))

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
