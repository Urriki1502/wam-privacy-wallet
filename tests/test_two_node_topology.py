"""Adversarial, offline-only tests for the G1-01 two-node topology plan."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import socket
import subprocess
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node.two_node_topology import (
    TwoNodeTopologyError, TwoNodePlan, plan_two_node_topology,
)

PORTS = (31001, 31002, 32001, 32002)


class TwoNodeTopologyTests(unittest.TestCase):
    def test_two_distinct_nodes_and_four_distinct_ports(self):
        plan = plan_two_node_topology(PORTS)
        self.assertIsInstance(plan, TwoNodePlan)
        self.assertEqual(tuple(node.label for node in plan.nodes), ("node-a", "node-b"))
        self.assertEqual(tuple(node.rpc_port for node in plan.nodes), (31001, 32001))
        self.assertEqual(tuple(node.p2p_port for node in plan.nodes), (31002, 32002))

    def test_explicit_loopback_peer_links_are_reciprocal(self):
        a, b = plan_two_node_topology(PORTS).nodes
        self.assertEqual((a.rpc_host, a.p2p_host, b.rpc_host, b.p2p_host),
                         ("127.0.0.1",) * 4)
        self.assertEqual(a.peer_p2p_port, b.p2p_port)
        self.assertEqual(b.peer_p2p_port, a.p2p_port)
        self.assertIn("connect=127.0.0.1:32002", a.config_preview)
        self.assertIn("connect=127.0.0.1:31002", b.config_preview)

    def test_templates_are_regtest_only_without_external_discovery(self):
        plan = plan_two_node_topology(PORTS)
        for node in plan.nodes:
            with self.subTest(node=node.label):
                lines = node.config_preview.splitlines()
                for line in ("regtest=1", "listen=1", "bind=127.0.0.1",
                             "dns=0", "dnsseed=0", "discover=0",
                             "upnp=0", "natpmp=0", "rpcbind=127.0.0.1",
                             "rpcallowip=127.0.0.1", "[regtest]"):
                    self.assertIn(line, lines)
                self.assertEqual(len([x for x in lines if x.startswith("connect=")]), 1)
                self.assertNotIn("connect=0", lines)
                self.assertFalse(any(x.startswith(("addnode=", "externalip=",
                                "mainnet=", "testnet=", "wallet=", "datadir="))
                                     for x in lines))

    def test_plan_cannot_claim_security_or_release_authority(self):
        plan = plan_two_node_topology(PORTS)
        self.assertEqual(plan.status, "BLOCKED_UNVERIFIED_CORE")
        for flag in ("real_regtest_qualified", "publisher_identity_verified",
                     "scanner_enabled", "signing_enabled", "release_allowed"):
            self.assertIs(getattr(plan, flag), False)

    def test_plan_records_are_frozen_and_do_not_hold_secrets(self):
        plan = plan_two_node_topology(PORTS)
        with self.assertRaises(FrozenInstanceError):
            plan.release_allowed = True
        with self.assertRaises(FrozenInstanceError):
            plan.nodes[0].rpc_port = 9999
        for token in ("cookie", "password", "private_key", "auth", "wallet_path",
                      "binary_path", "subprocess", "Popen"):
            self.assertNotIn(token, repr(plan).lower())
            self.assertFalse(hasattr(plan, token))

    def test_duplicate_ports_rejected_between_and_within_nodes(self):
        for ports in ((31001, 31001, 32001, 32002),
                      (31001, 31002, 31001, 32002),
                      (31001, 31002, 32001, 31002),
                      (31001, 31002, 32001, 32001)):
            with self.subTest(ports=ports):
                with self.assertRaisesRegex(
                    TwoNodeTopologyError, "^G1_TOPOLOGY_PORT_COLLISION$"
                ):
                    plan_two_node_topology(ports)

    def test_invalid_shape_and_mutable_inputs_denied(self):
        for ports in (None, (), (1, 2, 3), (1, 2, 3, 4, 5),
                      [31001, 31002, 32001, 32002], {},
                      "31001,31002,32001,32002"):
            with self.subTest(ports=repr(ports)):
                with self.assertRaisesRegex(
                    TwoNodeTopologyError, "^G1_TOPOLOGY_FOUR_PORTS_REQUIRED$"
                ):
                    plan_two_node_topology(ports)

    def test_invalid_port_types_and_ranges_denied(self):
        for bad in (None, True, False, 1023, 0, -1, 65536,
                    "31001", 31001.0, b"31001"):
            with self.subTest(bad=repr(bad)):
                with self.assertRaisesRegex(
                    TwoNodeTopologyError, "^G1_TOPOLOGY_INVALID_PORT$"
                ):
                    plan_two_node_topology((bad, 31002, 32001, 32002))

    def test_planning_never_spawns_reads_files_or_opens_network(self):
        with patch.object(socket, "socket", side_effect=AssertionError("NO SOCKET")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("NO SPAWN")), \
             patch("builtins.open", side_effect=AssertionError("NO FILE")):
            plan = plan_two_node_topology(PORTS)
        self.assertEqual(plan.status, "BLOCKED_UNVERIFIED_CORE")

    def test_deterministic_without_ambient_path_or_daemon_state(self):
        a = plan_two_node_topology(PORTS)
        b = plan_two_node_topology(PORTS)
        self.assertEqual(a, b)
        self.assertNotIn("~", repr(a))
        self.assertNotIn("/home/", repr(a))
        self.assertNotIn("Users\\", repr(a))


if __name__ == "__main__":
    unittest.main()
