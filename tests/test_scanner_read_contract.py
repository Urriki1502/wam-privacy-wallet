"""Offline adversarial tests for the proposed WSP-1 scanner read shape.

No wallet, scanner, RPC server, real keys, dependency import or Core binary.
"""

import dataclasses
import unittest

from wam_privacy_wallet.integrations.scan_read_contract import (
    ScannerReadContractError,
    ScannerReadShape,
    validate_scanner_read_shape,
)

H = "a" * 64
TX = "b" * 64


class ScannerReadShapeTests(unittest.TestCase):
    def check_error(self, code, method, params=None, *, scope="confirmed"):
        with self.assertRaises(ScannerReadContractError) as ctx:
            validate_scanner_read_shape(method, params, scope=scope)
        self.assertEqual(str(ctx.exception), code)

    def test_confirmed_identity_methods_and_normalization(self):
        for method in ("getblockchaininfo", "getblockcount", "getbestblockhash"):
            with self.subTest(method=method):
                value = validate_scanner_read_shape(method)
                self.assertEqual(
                    value, ScannerReadShape(method=method, params=(), scope="confirmed")
                )

    def test_confirmed_block_hash_and_verbose_block(self):
        for height in (0, 1, 100_000_000):
            with self.subTest(height=height):
                self.assertEqual(
                    validate_scanner_read_shape("getblockhash", [height]).params,
                    (height,),
                )
        self.assertEqual(
            validate_scanner_read_shape("getblock", [H, 3]).params, (H, 3)
        )

    def test_mempool_requires_explicit_scope(self):
        self.check_error("SCAN_RPC_METHOD_DENIED", "getrawmempool")
        self.check_error("SCAN_RPC_METHOD_DENIED", "getrawtransaction", [TX, 2])
        self.assertEqual(
            validate_scanner_read_shape("getrawmempool", scope="mempool").params, ()
        )
        for verbosity in (1, 2):
            with self.subTest(verbosity=verbosity):
                value = validate_scanner_read_shape(
                    "getrawtransaction", [TX, verbosity], scope="mempool"
                )
                self.assertEqual(value.params, (TX, verbosity))

    def test_mempool_does_not_implicitly_allow_getblock(self):
        self.check_error(
            "SCAN_RPC_METHOD_DENIED", "getblock", [H, 3], scope="mempool"
        )

    def test_mutating_or_unrelated_rpc_methods_never_allowed(self):
        methods = (
            "sendrawtransaction", "submitblock", "sendtoaddress", "signrawtransactionwithwallet",
            "walletpassphrase", "dumpprivkey", "importprivkey", "getwalletinfo",
            "gettxout", "testmempoolaccept", "getblocktemplate", "stop",
            "GetBlock", "", "getblock\x00", "getblock ", "getblockchaininfo/../../wallet",
        )
        for scope in ("confirmed", "mempool"):
            for method in methods:
                with self.subTest(scope=scope, method=method):
                    self.check_error(
                        "SCAN_RPC_METHOD_DENIED", method, [], scope=scope
                    )

    def test_rejects_unsupported_scope_and_method_types(self):
        for scope in ("", "mainnet", "testnet", "both", "CONFIRMED", None, 0, True):
            with self.subTest(scope=scope):
                self.check_error("SCAN_RPC_SCOPE_DENIED", "getblockcount", scope=scope)
        for method in (None, 0, True, b"getblockcount", ["getblockcount"], {}):
            with self.subTest(method=method):
                self.check_error("SCAN_RPC_METHOD_DENIED", method)

    def test_rejects_nonlist_parameters(self):
        for bad in ((), "[]", {}, (0,), False, 1, b""):
            with self.subTest(bad=bad):
                self.check_error(
                    "SCAN_RPC_PARAMS_INVALID", "getblockhash", bad
                )

    def test_no_extra_positional_or_keyword_parameters(self):
        for method, scope in (
            ("getblockcount", "confirmed"),
            ("getrawmempool", "mempool"),
            ("getblockchaininfo", "confirmed"),
        ):
            with self.subTest(method=method):
                self.check_error(
                    "SCAN_RPC_PARAMS_INVALID", method, [1], scope=scope
                )

    def test_invalid_heights_rejected(self):
        for height in (-1, 100_000_001, 1.5, True, False, "0", None, 0.0, [], {}):
            with self.subTest(height=height):
                self.check_error(
                    "SCAN_RPC_PARAMS_INVALID", "getblockhash", [height]
                )
        for params in ([], [1, 2], [0, None]):
            with self.subTest(params=params):
                self.check_error(
                    "SCAN_RPC_PARAMS_INVALID", "getblockhash", params
                )

    def test_getblock_requires_canonical_hash_and_exact_verbosity_three(self):
        bad_hashes = ("A" * 64, "a" * 63, "a" * 65, "g" * 64, "", None, H + "\n", b"a" * 64)
        for bad in bad_hashes:
            with self.subTest(hash=bad):
                self.check_error("SCAN_RPC_PARAMS_INVALID", "getblock", [bad, 3])
        for verbosity in (0, 1, 2, 4, True, "3", None):
            with self.subTest(verbosity=verbosity):
                self.check_error(
                    "SCAN_RPC_PARAMS_INVALID", "getblock", [H, verbosity]
                )
        for params in ([], [H], [H, 3, "extra"]):
            self.check_error("SCAN_RPC_PARAMS_INVALID", "getblock", params)

    def test_mempool_transaction_shape_strict(self):
        for params in (
            [TX], [TX, 0], [TX, 3], [TX, True], [TX, "2"],
            [TX.upper(), 2], [TX, 2, "x"], ["x" * 64, 2],
            [TX + "\n", 2], [TX, None],
        ):
            with self.subTest(params=params):
                self.check_error(
                    "SCAN_RPC_PARAMS_INVALID", "getrawtransaction",
                    params, scope="mempool"
                )

    def test_result_is_immutable_shape_not_network_authorization(self):
        obj = validate_scanner_read_shape("getblock", [H, 3])
        self.assertEqual(obj.scope, "confirmed")
        self.assertEqual(obj.params, (H, 3))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            obj.method = "sendrawtransaction"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            obj.params = (TX,)
        self.assertFalse(hasattr(obj, "attest"))
        self.assertFalse(hasattr(obj, "call"))


if __name__ == "__main__":
    unittest.main()
