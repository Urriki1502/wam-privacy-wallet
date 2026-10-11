"""Synthetic WSP scanner reply-shape tests; never performs RPC or imports WSP."""
from dataclasses import FrozenInstanceError
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

from wam_privacy_wallet.integrations.scanner_response_contract import (
    OfflineScannerResponseSummary, ScannerResponseShapeError,
    validate_offline_confirmed_block, validate_offline_mempool_ids,
)

H = "a" * 64
PREV = "b" * 64
TX = "c" * 64


def block():
    return {"hash": H, "previousblockhash": PREV, "height": 7,
            "tx": [{"txid": TX, "vout": [{"scriptPubKey": {"hex": "5120"}}]}]}


def check(value=None, **overrides):
    return validate_offline_confirmed_block(
        block() if value is None else value,
        expected_hash=overrides.get("expected_hash", H),
        expected_previous_hash=overrides.get("expected_previous_hash", PREV),
        height=overrides.get("height", 7),
    )


class ScannerResponseShapeTests(unittest.TestCase):
    def test_confirmed_summary_has_no_transactions_or_secrets(self):
        result = check()
        self.assertEqual((result.item_count, result.height, result.phase),
                         (1, 7, "confirmed"))
        self.assertEqual(result.status, "SHAPE_ONLY_UNTRUSTED")
        self.assertIs(result.scanner_enabled, False)
        self.assertIs(result.chain_identity_verified, False)
        self.assertIs(result.wallet_ready, False)
        for forbidden in ("tx", "txid", "amount", "address", "key", "rpc"):
            self.assertFalse(hasattr(result, forbidden))
        self.assertNotIn(TX, repr(result))

    def test_evidence_immutable_no_approval_constructor(self):
        result = check()
        with self.assertRaises(FrozenInstanceError):
            result.scanner_enabled = True
        for claim in ("scanner_enabled", "chain_identity_verified",
                      "wallet_ready", "status"):
            with self.subTest(claim=claim), self.assertRaises(TypeError):
                OfflineScannerResponseSummary(1, 7, "confirmed",
                                              **{claim: True})

    def test_wrong_hash_or_previous_hash_or_height_rejected(self):
        for field, value in (("hash", PREV), ("previousblockhash", H),
                             ("height", 8), ("height", True)):
            payload = block()
            payload[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(ScannerResponseShapeError,
                                            "^SCAN_BLOCK_CHAIN_MISMATCH$"):
                    check(payload)

    def test_bad_expectation_fail_closed(self):
        for name, value in (("expected_hash", "g" * 64),
                            ("expected_hash", H.upper()),
                            ("expected_previous_hash", "short"),
                            ("height", 0), ("height", 100000001),
                            ("height", True), ("height", "7")):
            with self.subTest(field=name, value=value), self.assertRaisesRegex(
                    ScannerResponseShapeError, "^SCAN_BLOCK_EXPECTATION_INVALID$"):
                check(**{name: value})

    def test_subclass_and_non_dict_payload_rejected(self):
        class ForgedDict(dict):
            pass
        for item in (None, [], True, ForgedDict(block()), "SECRET"):
            with self.subTest(kind=type(item).__name__), self.assertRaisesRegex(
                    ScannerResponseShapeError, "^SCAN_BLOCK_SHAPE_DENIED$"):
                validate_offline_confirmed_block(item, expected_hash=H,
                                                  expected_previous_hash=PREV, height=7)

    def test_missing_or_wrong_tx_list_rejected(self):
        for value in (None, {}, (), "TX", True):
            payload = block()
            if value is None:
                del payload["tx"]
            else:
                payload["tx"] = value
            with self.subTest(kind=type(value).__name__), self.assertRaisesRegex(
                    ScannerResponseShapeError, "^SCAN_BLOCK_TX_LIMIT$"):
                check(payload)

    def test_block_transaction_limit_uses_pinned_wsp_boundary(self):
        payload = block()
        payload["tx"] = [{"txid": TX}] * 10001
        with self.assertRaisesRegex(ScannerResponseShapeError,
                                    "^SCAN_BLOCK_TX_LIMIT$"):
            check(payload)

    def test_malformed_transaction_ids_and_types_rejected(self):
        for tx in (None, {}, {"txid": True}, {"txid": "bad"},
                   {"txid": TX.upper()}, ["not-a-tx"]):
            payload = block()
            payload["tx"] = [tx]
            with self.subTest(tx=str(type(tx))), self.assertRaisesRegex(
                    ScannerResponseShapeError, "^SCAN_BLOCK_TX_SHAPE_DENIED$"):
                check(payload)

    def test_duplicate_confirmed_txids_rejected(self):
        payload = block()
        payload["tx"].append({"txid": TX})
        with self.assertRaisesRegex(ScannerResponseShapeError,
                                    "^SCAN_BLOCK_DUPLICATE_TX$"):
            check(payload)

    def test_empty_confirmed_block_is_only_a_shape_check(self):
        payload = block()
        payload["tx"] = []
        result = check(payload)
        self.assertEqual(result.item_count, 0)
        self.assertIs(result.chain_identity_verified, False)

    def test_mempool_empty_and_bounded_valid_lists(self):
        for ids, count in (([], 0), ([H], 1), ([H, PREV], 2)):
            with self.subTest(count=count):
                result = validate_offline_mempool_ids(ids)
                self.assertEqual((result.item_count, result.height, result.phase),
                                 (count, None, "mempool"))
                self.assertIs(result.scanner_enabled, False)

    def test_mempool_non_list_and_oversized_rejected(self):
        for value in (None, True, {}, (H,), "SECRET", [H] * 10001):
            with self.subTest(kind=type(value).__name__), self.assertRaisesRegex(
                    ScannerResponseShapeError, "^SCAN_MEMPOOL_LIMIT$"):
                validate_offline_mempool_ids(value)

    def test_mempool_duplicates_and_invalid_hex_rejected(self):
        with self.assertRaisesRegex(ScannerResponseShapeError,
                                    "^SCAN_MEMPOOL_DUPLICATE_TX$"):
            validate_offline_mempool_ids([H, H])
        for invalid in (None, True, "short", H.upper(), b"a" * 64):
            with self.subTest(kind=type(invalid).__name__), self.assertRaisesRegex(
                    ScannerResponseShapeError, "^SCAN_MEMPOOL_TXID_DENIED$"):
                validate_offline_mempool_ids([invalid])

    def test_no_files_sockets_subprocess_or_wsp_imports(self):
        # These validators are only local scalar/list validators.
        with patch("builtins.open", side_effect=AssertionError("NO_FILE")), \
             patch.object(socket, "socket", side_effect=AssertionError("NO_SOCKET")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("NO_PROCESS")):
            self.assertEqual(check().item_count, 1)
            self.assertEqual(validate_offline_mempool_ids([H]).item_count, 1)
        import sys
        self.assertFalse(any(name.startswith("wam_sp") for name in sys.modules))


if __name__ == "__main__":
    unittest.main()
