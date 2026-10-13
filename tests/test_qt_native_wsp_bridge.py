"""REGTEST Qt source-qualified WSP live scanner scalar/read-only contract."""
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

from wam_privacy_wallet.application import qt_native_wsp_bridge as subject
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth


class NativeGuiScannerTests(unittest.TestCase):
    def setUp(self):
        self.params = dict(
            source_root=Path.cwd().resolve(), private_dir=Path.cwd().resolve(),
            passphrase=b"test-disposable-ONLY-secret",
            a=LocalRegtestEndpoint("127.0.0.1", 29554),
            aa=ExplicitRpcAuth("test_a", "test-a-secret"),
            b=LocalRegtestEndpoint("127.0.0.1", 29556),
            bb=ExplicitRpcAuth("test_b", "test-b-secret"),
            p2p_a=29555, p2p_b=29557,
            user_consented=True, unverified_core_ack=True,
            cancelled=Event(),
        )

    def test_invalid_and_cancel_never_open_a_socket(self):
        with patch.object(subject, "scan_two_existing_regtest_nodes") as scanner:
            for change in ({"user_consented": False},
                           {"unverified_core_ack": False},
                           {"passphrase": b"x"}, {"p2p_b": 29555}):
                with self.subTest(change=change):
                    with self.assertRaises(subject.QtNativeScanError):
                        subject.run_existing_two_node_scan(
                            **dict(self.params, **change))
            stop = Event()
            stop.set()
            with self.assertRaises(subject.QtNativeScanError):
                subject.run_existing_two_node_scan(
                    **dict(self.params, cancelled=stop))
            scanner.assert_not_called()

    def test_non_authorizing_dto_and_no_private_projection(self):
        proof = subject.QtNativeScanEvidence(42, True, 2, 3, 1)
        self.assertFalse(proof.wallet_operational)
        self.assertFalse(proof.signing_allowed)
        with self.assertRaises(subject.QtNativeScanError):
            subject.QtNativeScanEvidence(42, True, 2, 3, True)
        with self.assertRaises(subject.QtNativeScanError):
            subject.QtNativeScanEvidence(42, False, 2, 3, 1)
        if __import__("sys").platform != "linux":
            return
        receipt = {
            "status": "REAL_TWO_NODE_WSP_SCAN_UNQUALIFIED_BINARIES",
            "two_node_p2p_observed": True,
            "two_node_reported_chain_agrees": True,
            "core_binary_authenticated": False,
            "independent_core_processes_verified": False,
            "real_two_node_regtest_qualified": False,
            "wallet_operational": False,
            "signer_enabled": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
            "tip_height": 42,
            "chain_current": True,
            "blocks_processed": 2,
            "transactions_processed": 3,
            "observed_utxos": 1,
        }
        with patch.object(subject, "scan_two_existing_regtest_nodes", return_value=receipt):
            out = subject.run_existing_two_node_scan(**self.params)
            self.assertEqual(out.observed_utxos, 1)
        receipt["unqualified_confirmed_atoms"] = 1000
        with patch.object(subject, "scan_two_existing_regtest_nodes", return_value=receipt):
            with self.assertRaisesRegex(subject.QtNativeScanError, "QT_NATIVE_WSP_RECEIPT_DENIED"):
                subject.run_existing_two_node_scan(**self.params)
