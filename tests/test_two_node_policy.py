"""G1-03: adversarial policy checks against the immutable topology candidate."""
from __future__ import annotations
from dataclasses import FrozenInstanceError, replace
import random
import socket
import subprocess
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node.two_node_policy import TwoNodePolicyError, audit_two_node_policy
from wam_privacy_wallet.node.two_node_topology import plan_two_node_topology

PORTS = (31001, 31002, 32001, 32002)


class TwoNodePolicyAuditTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_two_node_topology(PORTS)

    def test_canonical_candidate_returns_review_only_record(self):
        result = audit_two_node_policy(self.plan)
        self.assertEqual(result.status, "OFFLINE_CANDIDATE_SHAPE_ONLY")
        self.assertEqual(result.nodes, 2)
        self.assertTrue(result.loopback_only)
        self.assertFalse(result.real_regtest_qualified)

    def test_invalid_objects_and_impostors_rejected(self):
        for bad in (None, True, {}, [], (), "not a plan", PORTS):
            with self.subTest(bad=repr(bad)):
                with self.assertRaisesRegex(
                    TwoNodePolicyError, "^G1_POLICY_PLAN_REQUIRED$"
                ):
                    audit_two_node_policy(bad)

    def test_duplicate_and_out_of_range_ports_rejected_after_mutation(self):
        a, b = self.plan.nodes
        for value in (0, True, 65536, a.rpc_port, b.p2p_port):
            changed = replace(self.plan, nodes=(replace(b, rpc_port=value), a))
            with self.subTest(value=value), self.assertRaises(TwoNodePolicyError):
                audit_two_node_policy(changed)

    def test_remote_host_and_dns_host_are_denied(self):
        a, b = self.plan.nodes
        for host in ("0.0.0.0", "10.0.0.1", "example.org", "::1"):
            with self.subTest(host=host), self.assertRaises(TwoNodePolicyError):
                audit_two_node_policy(replace(self.plan, nodes=(replace(a, rpc_host=host), b)))

    def test_peer_rebinding_or_unexpected_connection_denied(self):
        a, b = self.plan.nodes
        for peer in (1, 10000, b.rpc_port, a.p2p_port):
            with self.subTest(peer=peer), self.assertRaises(TwoNodePolicyError):
                audit_two_node_policy(replace(self.plan, nodes=(replace(a, peer_p2p_port=peer), b)))

    def test_forged_config_line_or_disabled_sandbox_denied(self):
        a, b = self.plan.nodes
        for extra in ("rpcbind=0.0.0.0\n", "addnode=198.51.100.1\n",
                      "discover=1\n", "listen=0\n", "wallet=userdata\n",
                      "connect=0\n", "rpcpassword=secret\n"):
            with self.subTest(extra=extra), self.assertRaises(TwoNodePolicyError):
                audit_two_node_policy(replace(self.plan, nodes=(
                    replace(a, config_preview=a.config_preview + extra), b)))

    def test_reordered_missing_or_mutated_config_rejected(self):
        a, b = self.plan.nodes
        for config in ("", a.config_preview.replace("dns=0\n", ""),
                       a.config_preview.replace("regtest=1", "regtest=0")):
            with self.subTest(config=config[:20]), self.assertRaises(TwoNodePolicyError):
                audit_two_node_policy(replace(self.plan, nodes=(
                    replace(a, config_preview=config), b)))

    def test_release_scanner_signer_and_status_escalation_denied(self):
        for changes in ({"release_allowed": True}, {"scanner_enabled": True},
                        {"signing_enabled": True},
                        {"real_regtest_qualified": True},
                        {"publisher_identity_verified": True},
                        {"status": "READY_FOR_MAINNET"}):
            with self.subTest(changes=changes), self.assertRaises(TwoNodePolicyError):
                audit_two_node_policy(replace(self.plan, **changes))

    def test_numerically_equal_false_flags_cannot_impersonate_bool(self):
        # Python dataclass equality alone considers False == 0 == 0.0.
        # Exact type validation must reject every such forged field.
        fields = (
            "real_regtest_qualified", "publisher_identity_verified",
            "scanner_enabled", "signing_enabled", "release_allowed",
        )
        for field in fields:
            for wrong in (0, 0.0, -0.0):
                forged = replace(self.plan, **{field: wrong})
                with self.subTest(field=field, wrong=repr(wrong)):
                    self.assertEqual(forged, self.plan)
                    with self.assertRaisesRegex(
                        TwoNodePolicyError, "^G1_POLICY_PLAN_INVALID$"
                    ):
                        audit_two_node_policy(forged)

    def test_numeric_peer_port_coercion_and_subclassed_int_are_denied(self):
        # Other ports are already type-checked by the canonical planner;
        # peer_p2p_port was vulnerable to equality with float/int subclasses.
        a, b = self.plan.nodes
        class IntAlias(int):
            pass
        for wrong in (float(a.peer_p2p_port), IntAlias(a.peer_p2p_port)):
            forged = replace(self.plan, nodes=(replace(a, peer_p2p_port=wrong), b))
            with self.subTest(wrong=repr(wrong)):
                self.assertEqual(forged, self.plan)
                with self.assertRaisesRegex(
                    TwoNodePolicyError, "^G1_POLICY_PLAN_INVALID$"
                ):
                    audit_two_node_policy(forged)

    def test_equal_string_subclasses_and_missing_slots_fail_closed(self):
        class TextAlias(str):
            pass
        a, b = self.plan.nodes
        for attr in ("label", "rpc_host", "p2p_host", "config_preview"):
            forged_node = replace(a, **{attr: TextAlias(getattr(a, attr))})
            forged = replace(self.plan, nodes=(forged_node, b))
            with self.subTest(node_field=attr):
                self.assertEqual(forged, self.plan)
                with self.assertRaisesRegex(
                    TwoNodePolicyError, "^G1_POLICY_PLAN_INVALID$"
                ):
                    audit_two_node_policy(forged)
        forged_status = replace(self.plan, status=TextAlias(self.plan.status))
        with self.assertRaisesRegex(TwoNodePolicyError, "^G1_POLICY_PLAN_INVALID$"):
            audit_two_node_policy(forged_status)
        # A deliberately uninitialized instance must not leak AttributeError.
        from wam_privacy_wallet.node.two_node_topology import TwoNodePlan
        with self.assertRaisesRegex(TwoNodePolicyError, "^G1_POLICY_PLAN_INVALID$"):
            audit_two_node_policy(object.__new__(TwoNodePlan))

    def test_seeded_property_valid_plans_are_deterministic_and_review_only(self):
        """Fixed-seed generated valid port tuples preserve G1-01 policy."""
        rng = random.Random(0x6A103A)
        for index in range(96):
            ports = tuple(rng.sample(range(20000, 51000), 4))
            plan = plan_two_node_topology(ports)
            with self.subTest(index=index, ports=ports):
                self.assertEqual(plan, plan_two_node_topology(ports))
                evidence = audit_two_node_policy(plan)
                self.assertEqual(evidence.status, "OFFLINE_CANDIDATE_SHAPE_ONLY")
                self.assertFalse(evidence.release_allowed)
                self.assertFalse(evidence.real_regtest_qualified)

    def test_seeded_property_numeric_equivalence_forgery_is_denied(self):
        """Numeric aliases compare equal to the expected dataclass but fail policy."""
        rng = random.Random(0x6A103B)
        flags = ("release_allowed", "signing_enabled", "scanner_enabled",
                 "publisher_identity_verified", "real_regtest_qualified")
        for index in range(125):
            field = rng.choice(flags)
            fake = rng.choice((0, 0.0, -0.0))
            forged = replace(self.plan, **{field: fake})
            with self.subTest(index=index, field=field, fake=repr(fake)):
                self.assertEqual(forged, self.plan)
                with self.assertRaisesRegex(TwoNodePolicyError,
                                            "^G1_POLICY_PLAN_INVALID$"):
                    audit_two_node_policy(forged)

    def test_seeded_property_node_type_aliases_are_denied(self):
        """Type-coercible ports and string subclasses remain invalid."""
        rng = random.Random(0x6A103C)
        class IntAlias(int):
            pass
        class TextAlias(str):
            pass
        int_fields = ("rpc_port", "p2p_port", "peer_p2p_port")
        text_fields = ("label", "rpc_host", "p2p_host", "config_preview")
        for index in range(144):
            which = rng.randrange(2)
            original = self.plan.nodes[which]
            field = rng.choice(int_fields + text_fields)
            raw = getattr(original, field)
            replacement = rng.choice((float(raw), IntAlias(raw))) if field in int_fields else TextAlias(raw)
            mutant = replace(original, **{field: replacement})
            nodes = list(self.plan.nodes)
            nodes[which] = mutant
            forged = replace(self.plan, nodes=tuple(nodes))
            with self.subTest(index=index, field=field, node=which):
                self.assertEqual(forged, self.plan)
                with self.assertRaisesRegex(TwoNodePolicyError,
                                            "^G1_POLICY_PLAN_INVALID$"):
                    audit_two_node_policy(forged)

    def test_seeded_property_single_config_line_mutation_is_denied(self):
        """Remove/reorder/duplicate/change one line; never silently normalize."""
        rng = random.Random(0x6A103D)
        for index in range(112):
            which = rng.randrange(2)
            node = self.plan.nodes[which]
            lines = node.config_preview.splitlines()
            operation = rng.choice(("remove", "duplicate", "replace", "reverse"))
            if operation == "reverse":
                mutated = list(reversed(lines))
            else:
                mutated = lines[:]
                position = rng.randrange(len(mutated))
                if operation == "remove":
                    del mutated[position]
                elif operation == "duplicate":
                    mutated.insert(position, mutated[position])
                else:
                    mutated[position] = "rpcbind=0.0.0.0"
            preview = "\n".join(mutated) + "\n"
            nodes = list(self.plan.nodes)
            nodes[which] = replace(node, config_preview=preview)
            forged = replace(self.plan, nodes=tuple(nodes))
            with self.subTest(index=index, operation=operation):
                self.assertNotEqual(forged, self.plan)
                with self.assertRaisesRegex(TwoNodePolicyError,
                                            "^G1_POLICY_PLAN_INVALID$"):
                    audit_two_node_policy(forged)

    def test_seeded_property_peer_redirect_and_port_mutation_are_denied(self):
        """Reject changing a single peer/port without matching canonical plan."""
        rng = random.Random(0x6A103E)
        for index in range(120):
            which = rng.randrange(2)
            original = self.plan.nodes[which]
            field = rng.choice(("rpc_port", "p2p_port", "peer_p2p_port"))
            current = getattr(original, field)
            value = rng.choice((current + 1, current - 1, 0, 65536, None, True))
            changed = replace(original, **{field: value})
            nodes = list(self.plan.nodes)
            nodes[which] = changed
            forged = replace(self.plan, nodes=tuple(nodes))
            with self.subTest(index=index, field=field, mutated=repr(value)):
                with self.assertRaisesRegex(TwoNodePolicyError,
                                            "^G1_POLICY_PLAN_INVALID$"):
                    audit_two_node_policy(forged)

    def test_evidence_frozen_and_non_authorizing(self):
        value = audit_two_node_policy(self.plan)
        for field in ("external_network_allowed", "scanner_enabled", "signer_enabled",
                      "release_allowed", "real_regtest_qualified"):
            self.assertIs(getattr(value, field), False)
        with self.assertRaises(FrozenInstanceError):
            value.release_allowed = True

    def test_no_socket_file_process_access_during_audit(self):
        with patch.object(socket, "socket", side_effect=AssertionError("SOCKET")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("PROCESS")), \
             patch("builtins.open", side_effect=AssertionError("FILES")):
            first = audit_two_node_policy(self.plan)
            second = audit_two_node_policy(self.plan)
        self.assertEqual(first, second)


    def test_historical_global_bind_and_rpcbind_layout_is_rejected(self):
        """Reject the original preview placing network-only options globally."""
        a, b = self.plan.nodes
        current = "[regtest]\\nbind=127.0.0.1\\nrpcbind=127.0.0.1\\n"
        former = "bind=127.0.0.1\\nrpcbind=127.0.0.1\\n[regtest]\\n"
        for index, node in enumerate((a, b)):
            self.assertIn(current, node.config_preview)
            old_preview = node.config_preview.replace(current, former)
            self.assertNotEqual(old_preview, node.config_preview)
            nodes = list(self.plan.nodes)
            nodes[index] = replace(node, config_preview=old_preview)
            with self.subTest(node=node.label):
                with self.assertRaisesRegex(TwoNodePolicyError,
                                            "^G1_POLICY_PLAN_INVALID$"):
                    audit_two_node_policy(replace(self.plan, nodes=tuple(nodes)))


if __name__ == "__main__":
    unittest.main()
