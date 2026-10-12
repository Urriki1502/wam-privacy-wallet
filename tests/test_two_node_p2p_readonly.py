"""Native TCP tests for fail-closed P2P auditing of two localhost RPC peers.

Servers are protocol fixtures, NOT WAM Core processes. These adversarial
tests exercise actual HTTP, authentication, redaction and topology checks.
"""
from __future__ import annotations

import base64
import json
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
from wam_privacy_wallet.node.two_node_p2p_readonly import (
    RegtestP2PAuditError, TwoNodeP2PReadOnlyAudit, _P2PReadOnlyWire,
)

TIP = "a" * 64
OTHER = "b" * 64
P2P_A = 39402
P2P_B = 39404
A_SOURCE_PORT = 41111
SECRET_A, SECRET_B = "SYNTHETIC_TEST_A", "SYNTHETIC_TEST_B"


class _HttpPeer(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        request = json.loads(raw)
        self.server.methods.append(request["method"])
        if self.headers.get("Authorization") != self.server.authorization:
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        method = request["method"]
        if method == "getblockhash":
            result = self.server.genesis if request["params"] == [0] else self.server.tip
        elif method == "getblockcount":
            result = 1
        elif method == "getbestblockhash":
            result = self.server.tip
        elif method == "getblockchaininfo":
            result = {
                "chain": self.server.chain, "blocks": 1,
                "headers": 1, "bestblockhash": self.server.tip, "pruned": False,
            }
        elif method == "getnetworkinfo":
            result = self.server.network
        elif method == "getpeerinfo":
            result = self.server.peers
            if self.server.mutate_after_peer:
                self.server.peers = []
        else:
            result = None
        wire = json.dumps({"result": result, "error": None, "id": 1}).encode("ascii")
        if self.server.override_method == method:
            wire = self.server.override_reply
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if self.server.encoding:
            self.send_header("Content-Encoding", self.server.encoding)
        announced = len(wire)
        if self.server.announced_length is not None:
            announced = self.server.announced_length
        self.send_header("Content-Length", str(announced))
        self.end_headers()
        try:
            self.wfile.write(wire)
        except (OSError, BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_args):
        pass


class TwoNodeP2PRealTcpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = []
        cls.threads = []
        for i, secret in enumerate((SECRET_A, SECRET_B)):
            server = ThreadingHTTPServer(("127.0.0.1", 0), _HttpPeer)
            server.authorization = "Basic " + base64.b64encode(
                ("regtest:" + secret).encode("ascii")
            ).decode("ascii")
            cls.servers.append(server)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.threads.append(thread)

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(timeout=5)

    def setUp(self):
        for i, server in enumerate(self.servers):
            server.methods = []
            server.genesis = WAM_REGTEST_GENESIS
            server.tip = TIP
            server.chain = "regtest"
            server.network = {
                "networkactive": True, "connections": 1,
                "connections_in": int(i == 1), "connections_out": int(i == 0),
                "localaddresses": [],
            }
            server.peers = [{
                "id": i + 1,
                "inbound": bool(i),
                "addr": f"127.0.0.1:{A_SOURCE_PORT if i else P2P_B}",
                "addrbind": f"127.0.0.1:{P2P_B if i else A_SOURCE_PORT}",
            }]
            server.mutate_after_peer = False
            server.override_method = None
            server.override_reply = b""
            server.encoding = None
            server.announced_length = None
        self.endpoint_a = LocalRegtestEndpoint("127.0.0.1", self.servers[0].server_port)
        self.endpoint_b = LocalRegtestEndpoint("127.0.0.1", self.servers[1].server_port)
        self.auth_a = ExplicitRpcAuth("regtest", SECRET_A)
        self.auth_b = ExplicitRpcAuth("regtest", SECRET_B)
        self.options = dict(
            node_a=self.endpoint_a, auth_a=self.auth_a,
            node_b=self.endpoint_b, auth_b=self.auth_b,
            node_a_p2p_port=P2P_A, node_b_p2p_port=P2P_B,
        )

    def _audit(self, **changes):
        return TwoNodeP2PReadOnlyAudit(**(self.options | changes)).audit()

    def _deny(self, code: str, **changes):
        with self.assertRaisesRegex(RegtestP2PAuditError, "^" + code + "$"):
            self._audit(**changes)

    def test_both_genuine_localhost_sockets_receive_p2p_methods(self):
        report = self._audit()
        self.assertEqual(report["status"], "UNTRUSTED_LOCAL_REGTEST_P2P_TOPOLOGY_ONLY")
        self.assertEqual((report["peer_count_a"], report["peer_count_b"]), (1, 1))
        for server in self.servers:
            self.assertEqual(server.methods.count("getnetworkinfo"), 2)
            self.assertEqual(server.methods.count("getpeerinfo"), 2)
            self.assertGreaterEqual(server.methods.count("getblockchaininfo"), 4)

    def test_report_is_redacted_and_permanently_nonauthorizing(self):
        report = self._audit()
        encoded = json.dumps(report)
        for value in (SECRET_A, SECRET_B, TIP, WAM_REGTEST_GENESIS,
                      str(A_SOURCE_PORT), "Authorization"):
            self.assertNotIn(value, encoded)
        for flag in (
            "genuine_wam_process_verified", "independent_processes_verified",
            "external_network_exclusion_proven", "real_two_node_regtest_qualified",
            "scanner_enabled", "wallet_ready", "signing_allowed",
            "broadcast_allowed", "mainnet_allowed",
        ):
            self.assertIs(report[flag], False)

    def test_remote_peer_address_denied(self):
        self.servers[0].peers[0]["addr"] = "203.0.113.42:39404"
        self._deny("REGTEST_P2P_PEER_ADDRESS_DENIED")

    def test_hostname_and_ipv6_mapped_peer_address_denied(self):
        for address in ("localhost:39404", "[::ffff:127.0.0.1]:39404",
                        "[::1]:39404", "127.0.0.1:039404"):
            self.servers[0].peers[0]["addr"] = address
            with self.subTest(address=address):
                self._deny("REGTEST_P2P_PEER_ADDRESS_DENIED")

    def test_wrong_remote_p2p_port_denied(self):
        self.servers[0].peers[0]["addr"] = "127.0.0.1:39777"
        self._deny("REGTEST_P2P_TOPOLOGY_DENIED")

    def test_wrong_inbound_bound_port_denied(self):
        self.servers[1].peers[0]["addrbind"] = "127.0.0.1:39888"
        self._deny("REGTEST_P2P_TOPOLOGY_DENIED")

    def test_unlinked_outbound_source_port_denied(self):
        self.servers[1].peers[0]["addr"] = "127.0.0.1:41222"
        self._deny("REGTEST_P2P_TOPOLOGY_DENIED")

    def test_multiple_or_missing_peers_denied(self):
        for items in ([], self.servers[0].peers * 2):
            with self.subTest(n=len(items)):
                self.servers[0].peers = items
                self._deny("REGTEST_P2P_PEER_COUNT_DENIED")

    def test_mismatched_direction_denied(self):
        self.servers[0].peers[0]["inbound"] = True
        self._deny("REGTEST_P2P_DIRECTION_DENIED")

    def test_network_disabled_or_zero_connections_denied(self):
        for key, value in (("networkactive", False), ("connections", 0),
                           ("connections", True), ("connections_in", 5)):
            with self.subTest(key=key, value=value):
                self.setUp()
                self.servers[0].network[key] = value
                self._deny("REGTEST_P2P_NETWORK_DENIED")

    def test_network_direction_counters_must_match_peerinfo(self):
        self.servers[0].network["connections_in"] = 1
        self._deny("REGTEST_P2P_NETWORK_DENIED")
        self.setUp()
        self.servers[1].network["connections_out"] = 1
        self._deny("REGTEST_P2P_NETWORK_DENIED")

    def test_missing_network_direction_counters_fail_closed(self):
        del self.servers[0].network["connections_out"]
        self._deny("REGTEST_P2P_NETWORK_DENIED")
        self.setUp()
        del self.servers[1].network["connections_in"]
        self._deny("REGTEST_P2P_NETWORK_DENIED")

    def test_external_local_advertisements_denied(self):
        self.servers[0].network["localaddresses"] = [
            {"address": "203.0.113.99", "port": P2P_A, "score": 1},
        ]
        self._deny("REGTEST_P2P_ADVERTISEMENT_DENIED")

    def test_profile_wrong_genesis_or_mainnet_denied(self):
        self.servers[1].genesis = OTHER
        self._deny("REGTEST_P2P_PROFILE_DENIED")
        self.setUp()
        self.servers[1].chain = "main"
        self._deny("REGTEST_P2P_PROFILE_DENIED")

    def test_wrong_password_redacted(self):
        with self.assertRaises(RegtestP2PAuditError) as caught:
            self._audit(auth_b=ExplicitRpcAuth("regtest", "DO_NOT_PRINT_ME"))
        self.assertEqual(str(caught.exception), "REGTEST_P2P_PROFILE_DENIED")
        self.assertNotIn("DO_NOT_PRINT_ME", str(caught.exception))

    def test_peer_mutation_between_bracketed_snapshots_denied(self):
        self.servers[1].mutate_after_peer = True
        with self.assertRaises(RegtestP2PAuditError) as caught:
            self._audit()
        self.assertIn(str(caught.exception), (
            "REGTEST_P2P_PEER_COUNT_DENIED", "REGTEST_P2P_CHANGED_DURING_READ",
        ))

    def test_refuse_duplicate_endpoint_and_colliding_ports_before_network(self):
        for changes, code in (
            ({"node_b": self.endpoint_a}, "REGTEST_P2P_ENDPOINT_DENIED"),
            ({"node_b_p2p_port": P2P_A}, "REGTEST_P2P_PORT_COLLISION"),
            ({"node_a_p2p_port": self.endpoint_a.port}, "REGTEST_P2P_PORT_COLLISION"),
            ({"node_a_p2p_port": True}, "REGTEST_P2P_PORT_DENIED"),
        ):
            with self.subTest(changes=changes):
                self._deny(code, **changes)
        self.assertFalse(self.servers[0].methods)

    def test_separate_p2p_rpc_allowlist_cannot_invoke_mutations(self):
        wire = _P2PReadOnlyWire(self.endpoint_a, self.auth_a)
        for method in ("addnode", "disconnectnode", "sendrawtransaction",
                       "getwalletinfo", "stop", "getblockchaininfo"):
            with self.subTest(method=method), self.assertRaisesRegex(
                RegtestP2PAuditError, "^REGTEST_P2P_METHOD_DENIED$",
            ):
                wire.call(method)
        self.assertFalse(self.servers[0].methods)

    def test_large_gzip_and_malformed_responses_denied(self):
        server = self.servers[0]
        server.override_method = "getnetworkinfo"
        for payload, encoding, limit in (
            (b"{", None, None),
            (b'{"result":{},"id":true,"error":null}', None, None),
            (b"{}", "gzip", None),
            (b"{}", None, 131073),
        ):
            with self.subTest(payload=payload, encoding=encoding, limit=limit):
                server.override_reply = payload
                server.encoding = encoding
                server.announced_length = limit
                with self.assertRaises(RegtestP2PAuditError):
                    self._audit()

    def test_no_core_subprocess_network_reconfiguration_or_wallet_file(self):
        with patch.object(subprocess, "Popen", side_effect=AssertionError("NO_EXEC")):
            report = self._audit()
        self.assertFalse(report["real_two_node_regtest_qualified"])


if __name__ == "__main__":
    unittest.main()
