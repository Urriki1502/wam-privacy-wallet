"""Validation-only tests; never open network connections or touch wallets."""

import unittest
from dataclasses import FrozenInstanceError

from wam_privacy_wallet.node import LocalRegtestEndpoint


class LocalRegtestEndpointTests(unittest.TestCase):
    def test_accepts_numeric_ipv4_loopback(self):
        endpoint = LocalRegtestEndpoint("127.0.0.1", 22222)
        self.assertEqual(endpoint.network, "regtest")
        self.assertEqual(endpoint.url, "http://127.0.0.1:22222")

    def test_accepts_ipv6_loopback_and_formats_url(self):
        endpoint = LocalRegtestEndpoint("::1", 49152)
        self.assertEqual(endpoint.host, "::1")
        self.assertEqual(endpoint.url, "http://[::1]:49152")

    def test_rejects_ambiguous_and_remote_hosts(self):
        bad_hosts = (
            "", "localhost", "example.org", "192.168.1.1", "10.0.0.1",
            "0.0.0.0", "::", "8.8.8.8", "127.0.0.1:18443",
            "http://127.0.0.1", "[::1]", "::1%lo0", "127.0.0.1\nHost: evil",
            " 127.0.0.1", "127.0.0.1 ", "::ffff:127.0.0.1",
        )
        for host in bad_hosts:
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    LocalRegtestEndpoint(host, 12345)

    def test_rejects_nonstrict_port_values(self):
        for port in (None, "12345", 12345.0, True, False, -1, 0, 65536):
            with self.subTest(port=port):
                with self.assertRaises(ValueError):
                    LocalRegtestEndpoint("127.0.0.1", port)

    def test_rejects_all_nonregtest_profiles(self):
        for network in ("mainnet", "testnet", "signet", "REGTEST", "", None, True):
            with self.subTest(network=network):
                with self.assertRaises(ValueError):
                    LocalRegtestEndpoint("127.0.0.1", 12345, network)

    def test_data_is_immutable(self):
        endpoint = LocalRegtestEndpoint("127.0.0.1", 12345)
        with self.assertRaises(FrozenInstanceError):
            endpoint.port = 23456

    def test_no_implicit_bitcoin_regtest_port(self):
        with self.assertRaises(TypeError):
            LocalRegtestEndpoint("127.0.0.1")


if __name__ == "__main__":
    unittest.main()
