"""Offline synthetic reorg/window regressions; no WAM Core or wallet."""
from dataclasses import FrozenInstanceError
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

from wam_privacy_wallet.integrations.scanner_window_contract import (
    OfflineScanWindowError, OfflineScanWindowSummary,
    validate_offline_scan_window,
)

H0, H1, H2, H3 = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)


def block(height, previous, current, txids=()):
    return {
        "hash": current, "previousblockhash": previous, "height": height,
        "tx": [{"txid": txid} for txid in txids],
    }


def fixture(**overrides):
    inputs = {
        "start_height": 4,
        "start_hash": H0,
        "reported_tip_before": (6, H2),
        "reported_tip_after": (6, H2),
        "blocks": (
            block(5, H0, H1, (H3,)),
            block(6, H1, H2),
        ),
    }
    inputs.update(overrides)
    return validate_offline_scan_window(**inputs)


class OfflineScanWindowTests(unittest.TestCase):
    def test_contiguous_two_block_fixture_only_reports_untrusted_counts(self):
        result = fixture()
        self.assertEqual(
            (result.start_height, result.end_height, result.block_count, result.transaction_count),
            (4, 6, 2, 1),
        )
        self.assertEqual(result.status, "SYNTHETIC_COHERENCE_ONLY")
        for flag in ("chain_identity_verified", "rpc_authenticated",
                     "scanner_enabled", "wallet_ready"):
            self.assertIs(getattr(result, flag), False)
        for secret in ("rpc", "txids", "private_key", "block_hash", "keyring"):
            self.assertFalse(hasattr(result, secret))

    def test_partial_window_is_allowed_only_as_untrusted_structure(self):
        state = fixture(
            reported_tip_before=(7, H3), reported_tip_after=(7, H3)
        )
        self.assertEqual(state.end_height, 6)
        self.assertIs(state.chain_identity_verified, False)

    def test_equal_start_tip_empty_is_allowed_but_never_authorized(self):
        state = fixture(
            start_height=4, start_hash=H0,
            reported_tip_before=(4, H0), reported_tip_after=(4, H0), blocks=(),
        )
        self.assertEqual((state.block_count, state.transaction_count), (0, 0))
        self.assertFalse(state.scanner_enabled)

    def test_bad_anchor_type_hash_and_height_denied(self):
        for field, val in (("start_height", True), ("start_height", -1),
                           ("start_height", 100000001), ("start_height", "4"),
                           ("start_hash", True), ("start_hash", H0.upper()),
                           ("start_hash", "private")):
            with self.subTest(field=field, val=val):
                with self.assertRaisesRegex(
                    OfflineScanWindowError, "^SCAN_WINDOW_ANCHOR_DENIED$"
                ):
                    fixture(**{field: val})

    def test_malformed_tip_container_denied(self):
        for val in ([], [6, H2], None, {}, (6,), (6, H2, H3)):
            with self.subTest(val=repr(val)), self.assertRaisesRegex(
                OfflineScanWindowError, "^SCAN_WINDOW_TIP_SHAPE_DENIED$"
            ):
                fixture(reported_tip_before=val)

    def test_malformed_tip_height_or_hash_denied(self):
        for val in ((True, H2), (-1, H2), ("6", H2), (6, H2.upper()),
                    (6, b"invalid"), (100000001, H2)):
            with self.subTest(val=repr(val)), self.assertRaisesRegex(
                OfflineScanWindowError, "^SCAN_WINDOW_TIP_SHAPE_DENIED$"
            ):
                fixture(reported_tip_after=val)

    def test_changing_reported_tip_denied(self):
        for changed in ((5, H1), (6, H1), (7, H3)):
            with self.subTest(changed=changed), self.assertRaisesRegex(
                OfflineScanWindowError, "^SCAN_WINDOW_TIP_CHANGED$"
            ):
                fixture(reported_tip_after=changed)

    def test_reported_tip_below_start_denied(self):
        with self.assertRaisesRegex(
            OfflineScanWindowError, "^SCAN_WINDOW_HEIGHT_REWIND$"
        ):
            fixture(reported_tip_before=(3, H0), reported_tip_after=(3, H0))

    def test_batch_requires_exact_tuple_and_max16(self):
        for val in (None, [], True, {}, list(fixture_blocks()),
                    (block(5, H0, H1),) * 17):
            with self.subTest(kind=type(val).__name__), self.assertRaisesRegex(
                OfflineScanWindowError, "^SCAN_WINDOW_BATCH_DENIED$"
            ):
                fixture(blocks=val)

    def test_window_may_not_exceed_reported_tip_height(self):
        with self.assertRaisesRegex(
            OfflineScanWindowError, "^SCAN_WINDOW_OVERRUN$"
        ):
            fixture(reported_tip_before=(5, H1), reported_tip_after=(5, H1))

    def test_empty_while_tip_is_ahead_is_denied(self):
        with self.assertRaisesRegex(
            OfflineScanWindowError, "^SCAN_WINDOW_EMPTY_BEHIND$"
        ):
            fixture(blocks=())

    def test_equal_tip_requires_matching_anchor_hash(self):
        with self.assertRaisesRegex(
            OfflineScanWindowError, "^SCAN_WINDOW_ANCHOR_MISMATCH$"
        ):
            fixture(reported_tip_before=(4, H1),
                    reported_tip_after=(4, H1), blocks=())

    def test_non_dictionary_or_non_hex_block_denied(self):
        for blocks in ((True,), ({"hash": True},),
                       ({"hash": "not-a-hash"},)):
            with self.subTest(value=repr(blocks)), self.assertRaisesRegex(
                OfflineScanWindowError, "^SCAN_WINDOW_BLOCK_DENIED$"
            ):
                fixture(blocks=blocks)

    def test_wrong_previous_hash_reorg_or_height_denied(self):
        for payload in (
            block(5, H1, H1),
            block(99, H0, H1),
            block(True, H0, H1),
        ):
            with self.subTest(payload=repr(payload)), self.assertRaisesRegex(
                OfflineScanWindowError, "^SCAN_WINDOW_BLOCK_DENIED$"
            ):
                fixture(blocks=(payload, block(6, H1, H2)))

    def test_last_returned_tip_must_match_reported_tip(self):
        with self.assertRaisesRegex(
            OfflineScanWindowError, "^SCAN_WINDOW_TIP_LINK_DENIED$"
        ):
            fixture(reported_tip_before=(6, H3),
                    reported_tip_after=(6, H3))

    def test_malformed_nested_tx_or_duplicate_denied(self):
        for transactions in ([{"txid": True}], [{"txid": H0}, {"txid": H0}],
                             [{"txid": "unexpected-private"}]):
            first = block(5, H0, H1)
            first["tx"] = transactions
            with self.subTest(count=len(transactions)), self.assertRaisesRegex(
                OfflineScanWindowError, "^SCAN_WINDOW_BLOCK_DENIED$"
            ):
                fixture(blocks=(first, block(6, H1, H2)))

    def test_cumulative_transaction_work_limit_fail_closed(self):
        first = block(5, H0, H1, [f"{x:064x}" for x in range(10000)])
        second = block(6, H1, H2, [f"{x:064x}" for x in range(10000, 20000)])
        evidence = fixture(blocks=(first, second))
        self.assertEqual(evidence.transaction_count, 20000)
        third = block(7, H2, H3, (H0,))
        with self.assertRaisesRegex(
            OfflineScanWindowError, "^SCAN_WINDOW_WORK_DENIED$"
        ):
            fixture(
                reported_tip_before=(7, H3),
                reported_tip_after=(7, H3),
                blocks=(first, second, third),
            )

    def test_immutable_summary_and_no_io_or_wsp_imports(self):
        with patch("builtins.open", side_effect=AssertionError("NO_FILE")), \
             patch.object(socket, "socket", side_effect=AssertionError("NO_SOCKET")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("NO_PROCESS")):
            result = fixture()
        with self.assertRaises(FrozenInstanceError):
            result.rpc_authenticated = True
        with self.assertRaises(TypeError):
            OfflineScanWindowSummary(4, 6, 2, 1, scanner_enabled=True)
        self.assertFalse(any(n.startswith("wam_sp") for n in sys.modules))


def fixture_blocks():
    return (block(5, H0, H1), block(6, H1, H2))


if __name__ == "__main__":
    unittest.main()
