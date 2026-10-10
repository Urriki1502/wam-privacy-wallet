"""G1-03: adversarial policy checks against the immutable topology candidate."""
from __future__ import annotations
from dataclasses import FrozenInstanceError, replace
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


if __name__ == "__main__":
    unittest.main()
