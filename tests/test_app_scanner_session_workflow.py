"""Application scanner-only observation: typed, consented, no wallet authority.

Stage 1 tests already cover actual HTTP loopback. Here the RPC is a deterministic
non-wallet stand-in so no WSP package, Core, secrets, UI or network is launched.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import scanner_session_workflow as app
from wam_privacy_wallet.application.presentation_lifecycle import (
    OfflineLifecycleError, OfflinePresentationController,
)
from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import WspScannerRpcError
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth

TIP = "a" * 64
TX = "b" * 64


class FixtureSession:
    def __init__(self):
        self.height = 3
        self.calls = []
        self.attest_count = 0
        self.fail_method = None
        self.change_height_on_last_read = False
        self.height_calls = 0

    def attest(self):
        self.attest_count += 1

    def call(self, method, params=None):
        self.calls.append((method, params))
        if method == self.fail_method:
            raise WspScannerRpcError("REMOTE_ACCESS_TOKEN_NEVER_LEAK")
        if method == "getblockcount":
            self.height_calls += 1
            return 4 if self.change_height_on_last_read and self.height_calls > 1 else self.height
        if method == "getbestblockhash":
            return TIP
        if method == "getblockhash":
            return TIP
        if method == "getblock":
            return {"hash": TIP, "tx": [{"txid": TX}, {"txid": "c" * 64}]}
        if method == "getrawmempool":
            return [TX, "c" * 64]
        raise AssertionError("unexpected non-read method")


class AppScannerSessionTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = LocalRegtestEndpoint("127.0.0.1", 28555)
        self.auth = ExplicitRpcAuth("synthetic", "NO_REAL_SECRET")
        self.fake = FixtureSession()
        self.constructor = patch.object(
            app, "Wsp1ScannerOnlyRpc", return_value=self.fake,
        )
        self.created = self.constructor.start()
        self.addCleanup(self.constructor.stop)

    def observe(self, **kwargs):
        return app.observe_local_scanner_session(
            self.endpoint, self.auth, user_consented=True, **kwargs,
        )

    def test_no_consent_means_no_rpc_constructor_or_observation(self):
        with self.assertRaisesRegex(app.ScannerObservationError,
                                    "^APP_SCANNER_INPUT_DENIED$"):
            app.observe_local_scanner_session(self.endpoint, self.auth,
                                              user_consented=False)
        self.created.assert_not_called()
        self.assertEqual(self.fake.calls, [])

    def test_type_forgery_denied_before_rpc(self):
        cases = (
            {"user_consented": 1},
            {"user_consented": "yes"},
            {"user_consented": True, "max_blocks": True},
            {"user_consented": True, "max_blocks": 0},
            {"user_consented": True, "max_blocks": 17},
            {"user_consented": True, "first_height": 0},
            {"user_consented": True, "first_height": 1.2},
            {"user_consented": True, "include_mempool": 1},
            {"user_consented": True, "cancelled": object()},
        )
        for kw in cases:
            with self.subTest(kw=kw), self.assertRaisesRegex(
                app.ScannerObservationError, "^APP_SCANNER_INPUT_DENIED$",
            ):
                app.observe_local_scanner_session(self.endpoint, self.auth, **kw)
        self.created.assert_not_called()

    def test_bounded_two_block_observation_has_only_scalar_output(self):
        view = self.observe(first_height=2, max_blocks=2)
        self.assertEqual((view.reported_tip_height, view.blocks_observed,
                          view.transactions_observed, view.mempool_ids_observed),
                         (3, 2, 4, 0))
        self.assertEqual(self.fake.attest_count, 2)
        self.assertEqual(sum(m == "getblock" for m, _ in self.fake.calls), 2)
        self.assertNotIn("getrawmempool", [m for m, _ in self.fake.calls])

    def test_no_block_range_observes_only_reported_tip(self):
        view = self.observe()
        self.assertEqual((view.blocks_observed, view.transactions_observed), (0, 0))
        self.assertEqual(view.reported_tip_height, 3)
        self.assertNotIn("getblock", [m for m, _ in self.fake.calls])

    def test_opt_in_mempool_observes_counts_without_raw_tx_payload(self):
        view = self.observe(include_mempool=True)
        self.assertEqual(view.mempool_ids_observed, 2)
        self.assertIn(("getrawmempool", []), self.fake.calls)
        self.assertNotIn("getrawtransaction", [m for m, _ in self.fake.calls])
        self.assertFalse(any(n in vars(view) for n in ("password", "endpoint"))
                         if hasattr(view, "__dict__") else False)

    def test_batch_stops_at_tip_even_if_max_is_larger(self):
        view = self.observe(first_height=3, max_blocks=16)
        self.assertEqual(view.blocks_observed, 1)

    def test_ahead_of_reported_tip_denied(self):
        with self.assertRaisesRegex(
            app.ScannerObservationError, "^APP_SCANNER_HEIGHT_AHEAD$",
        ):
            self.observe(first_height=4, max_blocks=1)
        self.assertNotIn("getblock", [m for m, _ in self.fake.calls])

    def test_cancellation_before_first_block_denied_without_block_rpc(self):
        with self.assertRaisesRegex(
            app.ScannerObservationError, "^APP_SCANNER_CANCELLED$",
        ):
            self.observe(first_height=1, max_blocks=2, cancelled=lambda: True)
        self.assertNotIn("getblock", [m for m, _ in self.fake.calls])

    def test_invalid_cancellation_result_and_callback_exception_fail_closed(self):
        with self.assertRaisesRegex(
            app.ScannerObservationError, "^APP_SCANNER_CANCELLED$",
        ):
            self.observe(first_height=1, cancelled=lambda: "no")
        def fail():
            raise RuntimeError("NO_REAL_SECRET")
        with self.assertRaisesRegex(
            app.ScannerObservationError, "^APP_SCANNER_OBSERVATION_DENIED$",
        ):
            self.observe(first_height=1, cancelled=fail)

    def test_rpc_failures_redact_credentials_and_response_content(self):
        self.fake.fail_method = "getblock"
        with self.assertRaisesRegex(
            app.ScannerObservationError, "^APP_SCANNER_OBSERVATION_DENIED$",
        ) as e:
            self.observe(first_height=1)
        self.assertNotIn("REMOTE_ACCESS_TOKEN", str(e.exception))
        self.assertNotIn("NO_REAL_SECRET", repr(e.exception))

    def test_final_tip_recheck_denies_observed_chain_change(self):
        self.fake.change_height_on_last_read = True
        with self.assertRaisesRegex(
            app.ScannerObservationError, "^APP_SCANNER_CHAIN_DRIFT$",
        ):
            self.observe(first_height=1)

    def test_all_wallet_and_scanner_authority_flags_immutable_false(self):
        view = self.observe()
        self.assertEqual(view.status, "LOCAL_RPC_OBSERVED_UNTRUSTED")
        for name in ("scanner_enabled", "wallet_ready", "chain_verified",
                     "core_execution_allowed", "signer_enabled",
                     "broadcast_allowed", "mainnet_allowed"):
            self.assertIs(getattr(view, name), False)
        with self.assertRaises(FrozenInstanceError):
            view.blocks_observed = 100
        self.assertFalse({"endpoint", "auth", "password", "keys", "wallet"}
                         & {f.name for f in fields(view)})

    def test_controller_accepts_untrusted_read_only_snapshot_and_reset(self):
        view = self.observe(first_height=1)
        ctl = OfflinePresentationController()
        state = ctl.replace(0, scanner_observation=view)
        self.assertEqual(state.scanner_session, "LOCAL_RPC_OBSERVED_UNTRUSTED")
        self.assertEqual((state.wallet, state.authority),
                         ("NO_WALLET_LOADED", "BLOCKED"))
        cleared = ctl.reset()
        self.assertEqual(cleared.scanner_session, "ABSENT")

    def test_controller_rejects_forged_snapshot_and_poisoned_revision(self):
        view = self.observe()
        object.__setattr__(view, "scanner_enabled", True)  # malicious DTO mutation
        ctl = OfflinePresentationController()
        with self.assertRaisesRegex(
            OfflineLifecycleError, "^APP_OFFLINE_LIFECYCLE_DENIED$",
        ):
            ctl.replace(0, scanner_observation=view)
        self.assertEqual(ctl.state.scanner_session, "ABSENT")
        self.assertEqual(ctl.state.transition, "REJECTED")
        with self.assertRaises(OfflineLifecycleError):
            ctl.replace(0, scanner_observation=view)
        self.assertEqual(ctl.state.scanner_session, "ABSENT")


if __name__ == "__main__":
    unittest.main()
