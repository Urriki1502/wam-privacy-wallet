"""Adversarial actual upstream privacy-aware selection application tests."""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from wam_privacy_wallet.application import coin_selection_review as app
from wam_privacy_wallet.research_models.wallet_privacy.model import Coin, Intent, Policy


def coin(n: int, amount: int, cluster: str = "a",
         confirmations: int = 6, reserved: bool = False) -> Coin:
    return Coin(f"{n:064x}", 0, amount, cluster, confirmations, reserved)


class CoinSelectionApplicationTests(unittest.TestCase):
    def setUp(self):
        self.coins = (coin(1, 51_000), coin(2, 60_000))
        self.intents = (Intent("SECRET-RECIPIENT", 50_000),)

    def review(self, **changes):
        args = dict(coins=self.coins, intents=self.intents,
                    fee_atoms=1_000, user_consented=True)
        args.update(changes)
        return app.review_regtest_coin_selection(**args)

    def test_exact_coin_without_change(self):
        r = self.review()
        self.assertEqual((r.selected_inputs, r.cluster_count,
                          r.change_created), (1, 1, False))
        self.assertEqual(r.warning_codes, ())
        self.assertEqual(r.status, "REGTEST_POLICY_REVIEW_UNTRUSTED")

    def test_excludes_reserved_and_unconfirmed(self):
        r = self.review(coins=(coin(1, 51_000, reserved=True),
                               coin(2, 51_000, confirmations=0),
                               coin(3, 51_000)))
        self.assertEqual(r.selected_inputs, 1)

    def test_cluster_merge_forbidden_by_default(self):
        with self.assertRaisesRegex(app.CoinSelectionReviewError,
                                    "^APP_COIN_SELECTION_POLICY_DENIED$"):
            self.review(coins=(coin(1, 30_000, "a"),
                               coin(2, 30_000, "b")))

    def test_explicit_merge_policy_and_consent_required(self):
        candidate = (coin(1, 30_000, "a"), coin(2, 30_000, "b"))
        with self.assertRaisesRegex(app.CoinSelectionReviewError,
                                    "^APP_COIN_SELECTION_CLUSTER_CONSENT_DENIED$"):
            self.review(coins=candidate, policy=Policy(allow_cluster_merge=True))
        with self.assertRaises(app.CoinSelectionReviewError):
            self.review(coins=candidate, allow_cluster_merge=True)
        value = self.review(coins=candidate, allow_cluster_merge=True,
                            policy=Policy(allow_cluster_merge=True))
        self.assertEqual(value.cluster_count, 2)
        self.assertIn("CLUSTER_MERGE", value.warning_codes)

    def test_duplicate_outpoints_denied_by_actual_policy(self):
        c = coin(1, 60_000)
        with self.assertRaisesRegex(app.CoinSelectionReviewError,
                                    "^APP_COIN_SELECTION_POLICY_DENIED$"):
            self.review(coins=(c, c))

    def test_dust_change_denied(self):
        with self.assertRaises(app.CoinSelectionReviewError):
            self.review(coins=(coin(1, 51_100),))

    def test_order_determinism(self):
        a = self.review(coins=(coin(1, 20_000), coin(2, 31_000),
                               coin(3, 60_000)))
        b = self.review(coins=(coin(3, 60_000), coin(2, 31_000),
                               coin(1, 20_000)))
        self.assertEqual(a, b)

    def test_consent_denied_before_source_io(self):
        with patch.object(app, "_verify_source",
                          side_effect=AssertionError("DO_NOT_READ")):
            with self.assertRaisesRegex(app.CoinSelectionReviewError,
                                        "^APP_COIN_SELECTION_INPUT_DENIED$"):
                self.review(user_consented=False)

    def test_truthy_nonboolean_consent_denied(self):
        for value in (1, "yes", None):
            with self.subTest(value=value), self.assertRaises(app.CoinSelectionReviewError):
                self.review(user_consented=value)

    def test_nonboolean_cluster_consent_denied(self):
        with self.assertRaises(app.CoinSelectionReviewError):
            self.review(allow_cluster_merge=1)

    def test_empty_oversized_or_list_input_denied(self):
        for coins in ((), tuple(coin(i+1, 51_000) for i in range(129)), []):
            with self.subTest(size=len(coins)), self.assertRaises(app.CoinSelectionReviewError):
                self.review(coins=coins)

    def test_multiple_or_untyped_intents_denied(self):
        for intents in ((), self.intents * 2, list(self.intents)):
            with self.subTest(count=len(intents)), self.assertRaises(app.CoinSelectionReviewError):
                self.review(intents=intents)

    def test_boolean_or_invalid_fee_denied(self):
        for fee in (True, 0, -1, 1_000_001):
            with self.subTest(fee=fee), self.assertRaises(app.CoinSelectionReviewError):
                self.review(fee_atoms=fee)

    def test_imposter_models_denied(self):
        for kw in ({"coins": (object(),)}, {"intents": (object(),)},
                   {"policy": object()}):
            with self.subTest(kw=str(kw.keys())):
                with self.assertRaisesRegex(app.CoinSelectionReviewError,
                                            "^APP_COIN_SELECTION_MODEL_DENIED$"):
                    self.review(**kw)

    def test_tampered_source_copy_denied_before_import(self):
        with TemporaryDirectory() as temp:
            with patch.object(app, "_ROOT", Path(temp)):
                with self.assertRaisesRegex(app.CoinSelectionReviewError,
                                            "^APP_COIN_SELECTION_SOURCE_DENIED$"):
                    self.review()

    def test_cancelled_before_source_io(self):
        with patch.object(app, "_verify_source",
                          side_effect=AssertionError("CANCEL_PRE_SOURCE")):
            with self.assertRaisesRegex(app.CoinSelectionReviewError,
                                        "^APP_COIN_SELECTION_CANCELLED$"):
                self.review(cancelled=lambda: True)

    def test_invalid_cancel_callback_denied(self):
        with self.assertRaisesRegex(app.CoinSelectionReviewError,
                                    "^APP_COIN_SELECTION_CANCELLED$"):
            self.review(cancelled=lambda: 1 / 0)

    def test_redacted_result_contains_no_coin_or_payment_data(self):
        result = self.review(coins=(coin(1, 51_000, "PRIVATE-CLUSTER"),))
        payload = repr(result)
        for secret in ("PRIVATE-CLUSTER", "SECRET-RECIPIENT",
                       f"{1:064x}", "50000", "51000"):
            self.assertNotIn(secret, payload)

    def test_authority_flags_always_false(self):
        result = self.review()
        for flag in ("core_authenticated", "wallet_operational",
                     "wallet_balance_qualified", "signing_allowed",
                     "broadcast_allowed", "mainnet_allowed"):
            self.assertIs(getattr(result, flag), False)

    def test_no_signer_rpc_or_broadcast_api(self):
        for name in ("sign", "broadcast", "Keyring", "WamCore",
                     "sendrawtransaction"):
            self.assertFalse(hasattr(app, name))


if __name__ == "__main__":
    unittest.main()
