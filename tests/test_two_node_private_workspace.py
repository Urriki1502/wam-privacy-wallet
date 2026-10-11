"""Native POSIX two-node disposable regtest config staging regressions.

No Core binary, subprocess, sockets or actual wallet data. Only previously
audited canonical G1 topology is admitted; Windows ACL is separately gated.
"""
from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node.two_node_topology import plan_two_node_topology
from wam_privacy_wallet.node.two_node_private_workspace import (
    TwoNodeWorkspaceError, prepare_private_two_node_workspace,
)

PORTS = (39101, 39102, 39103, 39104)


class PrivateTwoNodeWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_two_node_topology(PORTS)

    def _supported(self):
        return sys.platform in ("linux", "darwin") and os.name == "posix"

    def _unsupported(self):
        with self.assertRaisesRegex(
            TwoNodeWorkspaceError, "^REGTEST_WORKSPACE_PLATFORM_REVIEW_REQUIRED$",
        ):
            with prepare_private_two_node_workspace(self.plan):
                self.fail("unreviewed platform must not prepare filesystem")

    def test_real_temp_workspace_has_two_distinct_dirs_and_configs(self):
        if not self._supported():
            self._unsupported()
            return
        with prepare_private_two_node_workspace(self.plan) as w:
            a, b = w.nodes
            self.assertNotEqual(a.data_dir, b.data_dir)
            self.assertNotEqual(a.conf_path, b.conf_path)
            self.assertEqual((a.rpc_port, b.rpc_port), (39101, 39103))
            self.assertEqual((a.p2p_port, b.p2p_port), (39102, 39104))
            for item, node in zip(w.nodes, self.plan.nodes):
                self.assertEqual(item.conf_path.read_text("ascii"), node.config_preview)

    def test_private_posix_modes_for_root_both_dirs_and_both_files(self):
        if not self._supported():
            self._unsupported()
            return
        with prepare_private_two_node_workspace(self.plan) as w:
            root = w.nodes[0].data_dir.parent
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            for node in w.nodes:
                self.assertEqual(node.data_dir.stat().st_mode & 0o777, 0o700)
                self.assertEqual(node.conf_path.stat().st_mode & 0o777, 0o600)

    def test_ephemeral_workspace_is_removed_on_normal_exit(self):
        if not self._supported():
            self._unsupported()
            return
        with prepare_private_two_node_workspace(self.plan) as w:
            root = w.nodes[0].data_dir.parent
            self.assertTrue(root.is_dir())
        self.assertFalse(root.exists())

    def test_workspace_is_removed_on_exception_from_caller(self):
        if not self._supported():
            self._unsupported()
            return
        locations = []
        with self.assertRaisesRegex(RuntimeError, "SYNTHETIC_ERROR"):
            with prepare_private_two_node_workspace(self.plan) as w:
                locations.append(w.nodes[0].data_dir.parent)
                raise RuntimeError("SYNTHETIC_ERROR")
        self.assertFalse(locations[0].exists())

    def test_configs_are_loopback_regtest_with_explicit_peer_ports_only(self):
        if not self._supported():
            self._unsupported()
            return
        with prepare_private_two_node_workspace(self.plan) as w:
            for node in w.nodes:
                data = node.conf_path.read_text("ascii")
                self.assertIn("regtest=1\n", data)
                self.assertIn("bind=127.0.0.1", data)
                self.assertIn("rpcbind=127.0.0.1", data)
                self.assertIn("connect=127.0.0.1:", data)
                self.assertNotIn("mainnet=", data)
                self.assertNotIn("0.0.0.0", data)
                self.assertNotIn("rpcpassword=", data)
                self.assertNotIn(str(Path.home()), data)

    def test_no_cookies_keys_wallet_files_or_implicit_network(self):
        if not self._supported():
            self._unsupported()
            return
        with patch.object(subprocess, "Popen", side_effect=AssertionError("NO_PROCESS")), \
             patch.object(socket, "socket", side_effect=AssertionError("NO_NETWORK")):
            with prepare_private_two_node_workspace(self.plan) as w:
                root = w.nodes[0].data_dir.parent
                names = {p.name for p in root.rglob("*") if p.is_file()}
        self.assertEqual(names, {"wam.conf"})

    def test_evidence_never_admits_actual_core_process_or_money(self):
        if not self._supported():
            self._unsupported()
            return
        with prepare_private_two_node_workspace(self.plan) as w:
            self.assertTrue(w.private_filesystem_prepared)
            for key in (
                "core_options_runtime_verified", "core_process_started",
                "actual_two_node_regtest_qualified", "p2p_connected",
                "scanner_enabled", "wallet_enabled", "signing_allowed",
                "broadcasting_allowed", "mainnet_allowed",
            ):
                self.assertIs(getattr(w, key), False)

    def test_forged_approval_is_rejected_before_workspace_creation(self):
        if not self._supported():
            self._unsupported()
            return
        modified = replace(self.plan, real_regtest_qualified=True)
        with patch("wam_privacy_wallet.node.two_node_private_workspace.tempfile.TemporaryDirectory",
                   side_effect=AssertionError("NO_DISK")), \
             self.assertRaisesRegex(
                 TwoNodeWorkspaceError, "^REGTEST_WORKSPACE_POLICY_DENIED$",
             ):
            with prepare_private_two_node_workspace(modified):
                self.fail("forged real-regtest authority")

    def test_noncanonical_node_preview_denied_before_disk(self):
        if not self._supported():
            self._unsupported()
            return
        altered = replace(self.plan.nodes[0], config_preview="regtest=1\nrpcbind=0.0.0.0\n")
        forged = replace(self.plan, nodes=(altered, self.plan.nodes[1]))
        with self.assertRaisesRegex(
            TwoNodeWorkspaceError, "^REGTEST_WORKSPACE_POLICY_DENIED$",
        ):
            with prepare_private_two_node_workspace(forged):
                self.fail("noncanonical config")

    def test_unexpected_payload_type_denied(self):
        if not self._supported():
            self._unsupported()
            return
        for payload in (None, {}, (), "no-plan", object()):
            with self.subTest(payload=type(payload).__name__), self.assertRaisesRegex(
                TwoNodeWorkspaceError, "^REGTEST_WORKSPACE_POLICY_DENIED$",
            ):
                with prepare_private_two_node_workspace(payload):
                    self.fail("invalid payload")

    def test_windows_unreviewed_acl_denied_without_disk(self):
        with patch("wam_privacy_wallet.node.two_node_private_workspace.sys.platform", "win32"), \
             patch("wam_privacy_wallet.node.two_node_private_workspace.tempfile.TemporaryDirectory",
                   side_effect=AssertionError("NO_DISK")):
            self._unsupported()

    def test_port_policy_is_reused_not_reimplemented(self):
        if not self._supported():
            self._unsupported()
            return
        for ports in ((39101, 39101, 39102, 39103), (0, 39102, 39103, 39104)):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                plan_two_node_topology(ports)


if __name__ == "__main__":
    unittest.main()
