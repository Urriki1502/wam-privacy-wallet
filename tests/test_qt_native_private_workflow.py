"""Native WSP private Qt workflow: fail-closed scope and private DTO contracts."""
import sys
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

from wam_privacy_wallet.application import qt_native_private_workflow as m
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth


class NativeQtPrivateWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.args = dict(
            operation="history",
            source_root=Path.cwd().resolve(), private_dir=Path.cwd().resolve(),
            passphrase=b"DISPOSABLE_SCA_ONLY_PASSPHRASE",
            a=LocalRegtestEndpoint("127.0.0.1", 29554),
            aa=ExplicitRpcAuth("test_a", "disposable-credential-A"),
            b=LocalRegtestEndpoint("127.0.0.1", 29556),
            bb=ExplicitRpcAuth("test_b", "disposable-credential-B"),
            p2p_a=29555, p2p_b=29557,
            user_consented=True, unverified_core_ack=True,
            private_display_ack=True, cancelled=Event(),
        )

    def test_negative_scope_never_calls_real_socket(self):
        cases = (
            {"operation": "sign"}, {"private_display_ack": False},
            {"user_consented": False}, {"unverified_core_ack": False},
            {"passphrase": b"X"}, {"p2p_b": 29554},
            {"source_root": Path(".")}, {"a": self.args["b"]},
        )
        with patch.object(m, "scan_two_existing_regtest_nodes") as backend:
            for changed in cases:
                with self.subTest(changed=changed):
                    with self.assertRaisesRegex(
                        m.QtPrivateWorkflowError, "^QT_PRIVATE_SCOPE_DENIED$"
                    ):
                        m.run_private_wsp_workflow(**dict(self.args, **changed))
            backend.assert_not_called()

    def test_cancel_before_network(self):
        cancelled = Event()
        cancelled.set()
        with patch.object(m, "scan_two_existing_regtest_nodes") as backend:
            with self.assertRaises(m.QtPrivateWorkflowError):
                m.run_private_wsp_workflow(
                    **dict(self.args, cancelled=cancelled)
                )
            backend.assert_not_called()

    def test_private_history_rows_require_actual_fields_and_hidden_repr(self):
        row = m.PrivateQtHistoryRow("a" * 64, 2, 1, 500, 0)
        receipt = m.PrivateQtWorkflowEvidence("history", 2, (row,))
        self.assertNotIn("a" * 64, repr(row))
        self.assertNotIn("a" * 64, repr(receipt))
        self.assertFalse(receipt.signing_allowed)
        self.assertFalse(receipt.broadcast_allowed)
        for bad in ("q" * 64, "a" * 63, "a" * 64 + "x"):
            with self.assertRaises(m.QtPrivateWorkflowError):
                m.PrivateQtHistoryRow(bad, 2, 1, 500, 0)
        with self.assertRaises(m.QtPrivateWorkflowError):
            m.PrivateQtHistoryRow("b" * 64, 2, True, 500, 0)
        with self.assertRaises(m.QtPrivateWorkflowError):
            m.PrivateQtWorkflowEvidence("checkpoint", 2, (row,))
        with self.assertRaises(m.QtPrivateWorkflowError):
            m.PrivateQtWorkflowEvidence("history", 2, (), signing_allowed=True)

    def source_receipt(self, action):
        receipt = {
            "status": "REAL_TWO_NODE_WSP_SCAN_UNQUALIFIED_BINARIES",
            "chain_current": True, "tip_height": 7,
            "two_node_p2p_observed": True,
            "two_node_reported_chain_agrees": True,
            "core_binary_authenticated": False,
            "independent_core_processes_verified": False,
            "real_two_node_regtest_qualified": False,
            "wallet_operational": False,
            "signer_enabled": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
            "checkpoint_created": action == "checkpoint",
            "checkpoint_restored_then_reattested": action == "restore",
        }
        if action == "history":
            receipt["private_history"] = [{
                "txid": "c" * 64, "height": 7, "confirmations": 1,
                "credit_atoms": 100_000, "debit_atoms": 0,
            }]
        return receipt

    def test_actual_operational_seam_and_no_authority(self):
        if sys.platform != "linux":
            return
        for action in ("history", "checkpoint", "restore"):
            original = self.source_receipt(action)
            with patch.object(m, "scan_two_existing_regtest_nodes",
                              return_value=original) as backend:
                proof = m.run_private_wsp_workflow(
                    **dict(self.args, operation=action)
                )
                self.assertEqual(proof.operation, action)
                self.assertFalse(proof.wallet_operational)
                self.assertFalse(proof.broadcast_allowed)
                self.assertEqual(len(proof.rows), int(action == "history"))
                opts = backend.call_args.kwargs
                self.assertEqual(opts["history_limit"],
                                 20 if action == "history" else None)
                self.assertEqual(opts["save_checkpoint"], action == "checkpoint")
                self.assertEqual(opts["restore_checkpoint"], action == "restore")
                self.assertTrue(callable(opts["cancelled"]))
                self.assertNotIn("mock_peer", opts)

    def test_forged_authority_and_forged_checkpoint_denied(self):
        if sys.platform != "linux":
            return
        for mutation in (
            {"signer_enabled": True},
            {"core_binary_authenticated": True},
            {"chain_current": False},
            {"checkpoint_created": True},
            {"unqualified_receive_code": "SECRET-LEAK"},
            {"unqualified_confirmed_atoms": 500},
            {"private_history": [{"txid": "not-valid"}]},
        ):
            receipt = self.source_receipt("history")
            receipt.update(mutation)
            with self.subTest(mutation=mutation), patch.object(
                m, "scan_two_existing_regtest_nodes", return_value=receipt
            ):
                with self.assertRaises(m.QtPrivateWorkflowError):
                    m.run_private_wsp_workflow(**self.args)
