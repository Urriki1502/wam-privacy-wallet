"""G1-03 schema-v1 parity and hostile-input regression; offline only."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import random
import socket
import subprocess
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node.two_node_schema import (
    SCHEMA_VERSION, ConfigOptionV1, StructuredNodeV1, StructuredTwoNodeV1,
    TwoNodeSchemaError, audit_parallel_two_node_v1,
    build_structured_two_node_v1, serialize_legacy_preview,
)
from wam_privacy_wallet.node.two_node_topology import plan_two_node_topology

PORTS = (31001, 31002, 32001, 32002)
DENIAL = "^G1_SCHEMA_INVALID$"


class ParallelTwoNodeSchemaTests(unittest.TestCase):
    def setUp(self):
        self.legacy = plan_two_node_topology(PORTS)
        self.schema = build_structured_two_node_v1(self.legacy)

    def assertDenied(self, candidate):
        with self.assertRaisesRegex(TwoNodeSchemaError, DENIAL):
            audit_parallel_two_node_v1(self.legacy, candidate)

    def test_schema_version_is_exact_one_and_no_execution_authority(self):
        self.assertIs(type(self.schema.schema_version), int)
        self.assertEqual(self.schema.schema_version, SCHEMA_VERSION)
        evidence = audit_parallel_two_node_v1(self.legacy, self.schema)
        self.assertEqual(evidence.status, "OFFLINE_PARITY_ONLY")
        self.assertTrue(evidence.legacy_config_unchanged)
        self.assertFalse(evidence.core_runtime_qualified)
        self.assertFalse(evidence.execution_allowed)
        self.assertFalse(evidence.release_allowed)

    def test_legacy_byte_for_byte_roundtrip_for_both_nodes(self):
        for schema_node, legacy_node in zip(self.schema.nodes, self.legacy.nodes):
            with self.subTest(label=schema_node.label):
                self.assertEqual(serialize_legacy_preview(schema_node),
                                 legacy_node.config_preview)
                self.assertTrue(legacy_node.config_preview.endswith("\n"))

    def test_section_boundaries_and_option_order_are_explicit(self):
        for node in self.schema.nodes:
            sections = tuple(item.section for item in node.options)
            self.assertIn("global", sections)
            self.assertIn("regtest", sections)
            first_regtest = sections.index("regtest")
            self.assertNotIn("global", sections[first_regtest:])
            self.assertEqual(node.options[0], ConfigOptionV1("global", "regtest", "1"))
            self.assertEqual(node.options[-1].key, "connect")

    def test_frozen_records_and_tuple_options(self):
        with self.assertRaises(FrozenInstanceError):
            self.schema.schema_version = 2
        with self.assertRaises(FrozenInstanceError):
            self.schema.nodes[0].rpc_port = 10000
        with self.assertRaises(FrozenInstanceError):
            self.schema.nodes[0].options[0].value = "0"
        self.assertIs(type(self.schema.nodes), tuple)
        self.assertIs(type(self.schema.nodes[0].options), tuple)

    def test_wrong_version_numeric_alias_and_string_subclass_denied(self):
        for wrong in (0, 2, True, 1.0, "1"):
            with self.subTest(wrong=repr(wrong)):
                self.assertDenied(replace(self.schema, schema_version=wrong))
        class TextAlias(str):
            pass
        self.assertDenied(replace(self.schema, status=TextAlias(self.schema.status)))

    def test_all_authority_flags_require_exact_builtin_boolean(self):
        for field in ("real_regtest_qualified", "publisher_identity_verified",
                      "scanner_enabled", "signing_enabled", "release_allowed"):
            for wrong in (0, 0.0, -0.0, True):
                with self.subTest(field=field, wrong=repr(wrong)):
                    self.assertDenied(replace(self.schema, **{field: wrong}))

    def test_node_port_alias_host_alias_and_peer_change_denied(self):
        class IntAlias(int):
            pass
        class TextAlias(str):
            pass
        for field in ("rpc_port", "p2p_port", "peer_p2p_port"):
            for wrong in (float(getattr(self.schema.nodes[0], field)),
                          IntAlias(getattr(self.schema.nodes[0], field)), 65536):
                self.assertDenied(replace(self.schema, nodes=(
                    replace(self.schema.nodes[0], **{field: wrong}), self.schema.nodes[1])))
        for field in ("label", "rpc_host", "p2p_host"):
            value = getattr(self.schema.nodes[0], field)
            self.assertDenied(replace(self.schema, nodes=(
                replace(self.schema.nodes[0], **{field: TextAlias(value)}),
                self.schema.nodes[1])))
        self.assertDenied(replace(self.schema, nodes=(
            replace(self.schema.nodes[0], peer_p2p_port=31002), self.schema.nodes[1])))

    def test_nested_option_subclasses_and_structural_impostors_denied(self):
        class TextAlias(str):
            pass
        node = self.schema.nodes[0]
        option = node.options[0]
        for key, value in (("key", TextAlias(option.key)),
                           ("value", TextAlias(option.value)),
                           ("section", TextAlias(option.section))):
            changed = replace(option, **{key: value})
            self.assertDenied(replace(self.schema, nodes=(
                replace(node, options=(changed,) + node.options[1:]),
                self.schema.nodes[1])))
        self.assertDenied(replace(self.schema, nodes=[*self.schema.nodes]))
        self.assertDenied(replace(self.schema, nodes=(object(), self.schema.nodes[1])))
        self.assertDenied(replace(self.schema, nodes=(
            replace(node, options=list(node.options)), self.schema.nodes[1])))

    def test_single_option_value_injection_and_section_change_denied(self):
        node = self.schema.nodes[0]
        for wrong in ("0", "1\naddnode=198.51.100.1", " 1", ""):
            changed = replace(node.options[0], value=wrong)
            self.assertDenied(replace(self.schema, nodes=(
                replace(node, options=(changed,) + node.options[1:]),
                self.schema.nodes[1])))
        wrong_section = replace(node.options[0], section="regtest")
        self.assertDenied(replace(self.schema, nodes=(
            replace(node, options=(wrong_section,) + node.options[1:]),
            self.schema.nodes[1])))

    def test_option_removed_reordered_or_duplicated_denied(self):
        node = self.schema.nodes[0]
        variants = (
            node.options[:-1],
            (node.options[1], node.options[0]) + node.options[2:],
            (node.options[0],) + node.options,
            tuple(reversed(node.options)),
        )
        for options in variants:
            with self.subTest(length=len(options)):
                self.assertDenied(replace(self.schema, nodes=(
                    replace(node, options=options), self.schema.nodes[1])))

    def test_serializer_rejects_duplicate_or_section_reentry(self):
        node = self.schema.nodes[0]
        for options in (
            (node.options[0], node.options[0]) + node.options[1:],
            node.options + (ConfigOptionV1("global", "dns", "0"),),
            node.options[:-1] + (ConfigOptionV1("regtest", "connect", "a\nb"),),
        ):
            with self.assertRaisesRegex(TwoNodeSchemaError, DENIAL):
                serialize_legacy_preview(replace(node, options=options))

    def test_noncanonical_legacy_plan_fails_even_with_valid_schema(self):
        legacy = replace(self.legacy, nodes=(
            replace(self.legacy.nodes[0], config_preview=
                    self.legacy.nodes[0].config_preview + "addnode=198.51.100.1\n"),
            self.legacy.nodes[1]))
        with self.assertRaisesRegex(TwoNodeSchemaError, DENIAL):
            build_structured_two_node_v1(legacy)
        with self.assertRaisesRegex(TwoNodeSchemaError, DENIAL):
            audit_parallel_two_node_v1(legacy, self.schema)

    def test_missing_slots_and_fake_objects_fail_closed(self):
        for forged in (object(), None, {}, object.__new__(StructuredTwoNodeV1)):
            with self.assertRaisesRegex(TwoNodeSchemaError, DENIAL):
                audit_parallel_two_node_v1(self.legacy, forged)
        missing_node = object.__new__(StructuredNodeV1)
        self.assertDenied(replace(self.schema, nodes=(missing_node, self.schema.nodes[1])))

    def test_seeded_random_valid_plans_roundtrip(self):
        rng = random.Random(0x6A103F)
        for i in range(100):
            ports = tuple(rng.sample(range(18000, 60000), 4))
            plan = plan_two_node_topology(ports)
            structured = build_structured_two_node_v1(plan)
            with self.subTest(index=i):
                self.assertEqual(audit_parallel_two_node_v1(plan, structured).status,
                                 "OFFLINE_PARITY_ONLY")
                self.assertEqual(tuple(serialize_legacy_preview(n) for n in structured.nodes),
                                 tuple(n.config_preview for n in plan.nodes))

    def test_seeded_random_mutations_rejected(self):
        rng = random.Random(0x6A1040)
        for i in range(160):
            which = rng.randrange(2)
            node = self.schema.nodes[which]
            idx = rng.randrange(len(node.options))
            option = node.options[idx]
            replacement = replace(option, value=option.value + rng.choice(("x", "0", " ")))
            options = node.options[:idx] + (replacement,) + node.options[idx + 1:]
            nodes = list(self.schema.nodes)
            nodes[which] = replace(node, options=options)
            with self.subTest(index=i):
                self.assertDenied(replace(self.schema, nodes=tuple(nodes)))

    def test_schema_parity_has_no_process_file_or_socket_io(self):
        with patch.object(socket, "socket", side_effect=AssertionError("SOCKET")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("PROCESS")), \
             patch("builtins.open", side_effect=AssertionError("FILE")):
            first = build_structured_two_node_v1(self.legacy)
            evidence = audit_parallel_two_node_v1(self.legacy, first)
        self.assertEqual(evidence.status, "OFFLINE_PARITY_ONLY")


    def test_schema_places_both_bind_options_under_regtest(self):
        for node in self.schema.nodes:
            with self.subTest(node=node.label):
                pairs = [(opt.section, opt.key) for opt in node.options]
                self.assertEqual(pairs.count(("regtest", "bind")), 1)
                self.assertEqual(pairs.count(("regtest", "rpcbind")), 1)
                self.assertNotIn(("global", "bind"), pairs)
                self.assertNotIn(("global", "rpcbind"), pairs)
                self.assertEqual(
                    tuple(opt.key for opt in node.options if opt.section == "regtest"),
                    ("bind", "rpcbind", "rpcport", "port", "connect"),
                )
                legacy = self.legacy.nodes[0 if node.label == "node-a" else 1]
                self.assertEqual(serialize_legacy_preview(node), legacy.config_preview)

    def test_global_network_only_option_relocation_fails_closed(self):
        from wam_privacy_wallet.node.two_node_schema import _parse_legacy
        for wrong_key in ("bind", "rpcbind", "rpcport", "port", "connect"):
            for index, node in enumerate(self.schema.nodes):
                changed = tuple(
                    replace(opt, section="global") if opt.key == wrong_key else opt
                    for opt in node.options
                )
                nodes = list(self.schema.nodes)
                nodes[index] = replace(node, options=changed)
                with self.subTest(node=index, key=wrong_key):
                    with self.assertRaisesRegex(TwoNodeSchemaError, DENIAL):
                        serialize_legacy_preview(nodes[index])
                    self.assertDenied(replace(self.schema, nodes=tuple(nodes)))
                    original = self.legacy.nodes[index].config_preview
                    raw = next(opt.value for opt in node.options if opt.key == wrong_key)
                    option_line = f"{wrong_key}={raw}\n"
                    # Construct the old incorrect global-option layout, not
                    # merely a malformed missing-line candidate.
                    moved = original.replace(option_line, "", 1).replace(
                        "[regtest]\n", option_line + "[regtest]\n", 1
                    )
                    self.assertNotEqual(moved, original)
                    with self.assertRaisesRegex(TwoNodeSchemaError, DENIAL):
                        _parse_legacy(moved)


if __name__ == "__main__":
    unittest.main()
