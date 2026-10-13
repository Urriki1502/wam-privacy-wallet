"""Offline WAM structures, not captured transactions or Core E2E evidence."""
from __future__ import annotations

from copy import deepcopy
from decimal import Decimal, localcontext
import unittest

from wam_privacy_wallet.integrations.wam_transaction_shape import (
    validate_wam_transaction, WamTransactionShapeError,
)
from wam_privacy_wallet.node.rpc_json import decode_rpc_json

TX = "a" * 64
PREV = "b" * 64


def coinbase():
    return {"txid": TX, "vin": [{"coinbase": "0101"}], "vout": [
        {"n": 0, "value": Decimal("47.5"), "scriptPubKey": {"hex": "51"}},
        {"n": 1, "value": Decimal("2.5"), "scriptPubKey": {"hex": "51"}},
        {"n": 2, "value": 0, "scriptPubKey": {"hex": "6a24aa21a9ed" + "00" * 32}},
    ]}


def ordinary():
    return {"txid": TX, "vin": [{"txid": PREV, "vout": 0,
        "prevout": {"value": Decimal("0.2"),
                    "scriptPubKey": {"hex": "0014" + "00" * 20}},
        "scriptSig": {"hex": ""}, "txinwitness": ["01"]}],
        "vout": [{"n": 0, "value": Decimal("0.1"),
                  "scriptPubKey": {"hex": "5120" + "01" * 32}}]}


class WamTransactionShapeTests(unittest.TestCase):
    def deny(self, tx, *, require=True):
        with self.assertRaisesRegex(WamTransactionShapeError, "^WAM_TX_SHAPE_DENIED$"):
            validate_wam_transaction(tx, require_prevouts=require)

    def test_dev_three_output_coinbase_without_spent_prevout(self):
        self.assertTrue(validate_wam_transaction(coinbase(), require_prevouts=True))

    def test_output_count_is_variable_without_reward_assumptions(self):
        for count in (1, 2, 3, 4, 20):
            tx = coinbase()
            tx["vout"] = [{"n": i, "value": 0, "scriptPubKey": {"hex": "51"}}
                          for i in range(count)]
            self.assertTrue(validate_wam_transaction(tx, require_prevouts=True))

    def test_regular_confirmed_prevout_and_decimal_money(self):
        self.assertFalse(validate_wam_transaction(ordinary(), require_prevouts=True))

    def test_one_atom_and_supply_bound_are_exact(self):
        for amount in (Decimal("0.00000001"), Decimal("22000000"), 0):
            tx = ordinary()
            tx["vout"][0]["value"] = amount
            self.assertFalse(validate_wam_transaction(tx, require_prevouts=True))

    def test_raw_parent_lookup_can_omit_prevout_without_fabrication(self):
        tx = ordinary()
        del tx["vin"][0]["prevout"]
        before = deepcopy(tx)
        self.assertFalse(validate_wam_transaction(tx, require_prevouts=False))
        self.assertEqual(tx, before)
        self.deny(tx)

    def test_malformed_supplied_prevout_is_never_treated_as_missing(self):
        for prevout in (None, {}, [], {"value": 1}, {"scriptPubKey": {"hex": "51"}},
                        {"value": True, "scriptPubKey": {"hex": "51"}}):
            tx = ordinary()
            tx["vin"][0]["prevout"] = prevout
            self.deny(tx, require=False)

    def test_coinbase_cannot_mix_ordinary_fields_or_inputs(self):
        for field in ("txid", "vout", "prevout"):
            tx = coinbase()
            tx["vin"][0][field] = 0
            self.deny(tx)
        tx = coinbase()
        tx["vin"].append(ordinary()["vin"][0])
        self.deny(tx)

    def test_coinbase_encoding_is_bounded_canonical_hex(self):
        for value in (None, True, "", "gg", "0", "00 00", "00" * 101):
            tx = coinbase()
            tx["vin"][0]["coinbase"] = value
            self.deny(tx)

    def test_duplicate_spent_outpoint_denied(self):
        tx = ordinary()
        tx["vin"].append(deepcopy(tx["vin"][0]))
        self.deny(tx)

    def test_invalid_txid_or_input_outpoint_denied(self):
        for value in (None, "a" * 63, "A" * 64, "g" * 64):
            tx = ordinary()
            tx["txid"] = value
            self.deny(tx)
            tx = ordinary()
            tx["vin"][0]["txid"] = value
            self.deny(tx)
        for n in (None, True, -1, 0x100000000, Decimal("1")):
            tx = ordinary()
            tx["vin"][0]["vout"] = n
            self.deny(tx)

    def test_amount_bool_float_string_negative_nonfinite_and_fractional_denied(self):
        for value in (True, 0.1, "0.1", -1, Decimal("NaN"), Decimal("Infinity"),
                      Decimal("-0.00000001"), Decimal("22000000.00000001"),
                      Decimal("0.000000001"),
                      Decimal("0.1000000000000000000000000000000000000000000001")):
            tx = ordinary()
            tx["vout"][0]["value"] = value
            self.deny(tx)

    def test_amount_validation_independent_of_ambient_decimal_precision(self):
        tx = ordinary()
        tx["vout"][0]["value"] = Decimal("0.100000000000000000000000000000000001")
        with localcontext() as ctx:
            ctx.prec = 2
            self.deny(tx)

    def test_sum_of_outputs_cannot_exceed_supply_bound(self):
        tx = ordinary()
        tx["vout"] = [{"n": i, "value": 22_000_000, "scriptPubKey": {"hex": "51"}}
                      for i in range(2)]
        self.deny(tx)

    def test_empty_or_oversized_input_output_vectors_denied(self):
        for field, values in (("vin", []), ("vin", [ordinary()["vin"][0]] * 2049),
                              ("vout", []), ("vout", [ordinary()["vout"][0]] * 4097)):
            tx = ordinary()
            tx[field] = values
            self.deny(tx)

    def test_output_numbers_are_exact_and_sequential(self):
        for value in (None, True, -1, 1, "0"):
            tx = ordinary()
            tx["vout"][0]["n"] = value
            self.deny(tx)

    def test_script_bytes_validated_without_address_annotation_trust(self):
        tx = ordinary()
        spk = tx["vout"][0]["scriptPubKey"]
        spk.update(address="wamrt1synthetic", type="unknown-future-script")
        before = deepcopy(tx)
        self.assertFalse(validate_wam_transaction(tx, require_prevouts=True))
        self.assertEqual(before, tx)
        # Unknown eligibility remains the pinned WSP scanner's decision;
        # this boundary never turns a label into a derivation or an address.
        for value in (None, 1, "f", "gg", "51 51", "AA", "00" * 10001):
            spk["hex"] = value
            self.deny(tx)

    def test_invalid_script_sig_or_witness_encoding_denied(self):
        for field, value in (("scriptSig", None), ("scriptSig", {"hex": "no"}),
                             ("txinwitness", None), ("txinwitness", ["f"]),
                             ("txinwitness", ["00"] * 1001)):
            tx = ordinary()
            tx["vin"][0][field] = value
            self.deny(tx)

    def test_aggregate_witness_budget_denied(self):
        tx = ordinary()
        tx["vin"][0]["txinwitness"] = ["00" * 10000] * 101
        self.deny(tx)

    def test_json_money_never_converted_to_float(self):
        value = decode_rpc_json(b'{"value":0.00000001,"reward":47.5}')
        self.assertIs(type(value["value"]), Decimal)
        self.assertEqual(value["value"], Decimal("0.00000001"))
        self.assertEqual(value["reward"], Decimal("47.5"))

    def test_json_duplicate_keys_rejected_at_nested_depth(self):
        for raw in (b'{"x":1,"x":2}', b'{"vin":[{"prevout":{"value":1,"value":2}}]}'):
            with self.assertRaisesRegex(ValueError, "^RPC_JSON_DENIED$"):
                decode_rpc_json(raw)

    def test_json_nonfinite_and_unbounded_number_literals_rejected(self):
        for literal in (b'NaN', b'Infinity', b'-Infinity', b'1e65', b'1e-65',
                        b'0.' + b'1' * 64, b'1' * 129):
            with self.assertRaisesRegex(ValueError, "^RPC_JSON_DENIED$"):
                decode_rpc_json(b'{"value":' + literal + b'}')

    def test_json_wrong_encoding_or_excessive_depth_rejected(self):
        for raw in ('{"x":1}'.encode('utf-16'), b'\xff', b'[' * 1100 + b']' * 1100):
            with self.assertRaisesRegex(ValueError, "^RPC_JSON_DENIED$"):
                decode_rpc_json(raw)


if __name__ == "__main__":
    unittest.main()
