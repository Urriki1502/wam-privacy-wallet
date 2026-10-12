"""Fail-closed immutable offline presentation lifecycle regression tests."""
import unittest
from dataclasses import FrozenInstanceError

from wam_privacy_wallet.application.presentation_lifecycle import (
    OfflineLifecycleError, OfflinePresentationController,
)
from wam_privacy_wallet.application.node_status import NodeOverview
from wam_privacy_wallet.application.privacy_readiness import research_readiness
from wam_privacy_wallet.application.receive_vector import inspect_pinned_public_vector


def node():
    return NodeOverview("regtest", 42, "READ_ONLY_SNAPSHOT", "EXPERIMENTAL_NO_REAL_FUNDS")


class OfflinePresentationLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.controller = OfflinePresentationController()

    def test_psbt_receipt_is_untrusted_and_not_retained_in_state(self):
        from wam_privacy_wallet.application.psbt_v2_review import PsbtV2Review
        s = self.controller.replace(0, psbt_review=PsbtV2Review(1, 2))
        self.assertEqual((s.psbt, s.authority), ("UNSIGNED_PARSED_UNTRUSTED", "BLOCKED"))
        self.assertFalse(hasattr(s, "input_count") or hasattr(s, "source_root"))

    def test_psbt_receipt_omission_and_reset_clear_it(self):
        from wam_privacy_wallet.application.psbt_v2_review import PsbtV2Review
        self.controller.replace(0, psbt_review=PsbtV2Review(1, 1))
        self.assertEqual(self.controller.replace(1).psbt, "ABSENT")
        self.controller.replace(2, psbt_review=PsbtV2Review(1, 1))
        self.assertEqual(self.controller.reset().psbt, "ABSENT")

    def test_psbt_forged_authority_or_pin_rejects_whole_snapshot(self):
        from dataclasses import replace
        from wam_privacy_wallet.application.psbt_v2_review import PsbtV2Review
        for kw in ({"sign_allowed": True}, {"broadcast_allowed": True},
                   {"ownership_verified": True}, {"chain_verified": True},
                   {"source_commit": "forged"}, {"evidence": "VERIFIED"}):
            c = OfflinePresentationController()
            c.replace(0, node=node())
            with self.assertRaises(OfflineLifecycleError):
                c.replace(1, psbt_review=replace(PsbtV2Review(1, 1), **kw))
            self.assertEqual((c.state.psbt, c.state.node), ("ABSENT", "ABSENT"))

    def test_psbt_nonprimitive_or_out_of_range_counts_are_denied(self):
        from wam_privacy_wallet.application.psbt_v2_review import PsbtV2Review
        for a, b in ((True, 1), (1, False), (0, 1), (129, 1), (1, 257)):
            with self.assertRaises(OfflineLifecycleError):
                self.controller.replace(self.controller.state.revision, psbt_review=PsbtV2Review(a, b))
        self.assertEqual(self.controller.state.psbt, "ABSENT")

    def test_initial_state_is_unprivileged_and_empty(self):
        s = self.controller.state
        self.assertEqual((s.revision, s.transition), (0, "INITIAL"))
        self.assertEqual((s.node, s.privacy, s.policy, s.receive), ("ABSENT",) * 4)
        self.assertEqual((s.authority, s.wallet, s.network),
                         ("BLOCKED", "NO_WALLET_LOADED", "OFFLINE_REGTEST_ONLY"))

    def test_valid_node_is_unverified_and_never_authorized(self):
        s = self.controller.replace(0, node=node())
        self.assertEqual((s.revision, s.node, s.authority), (1, "UNVERIFIED", "BLOCKED"))

    def test_omitted_fields_are_not_inherited(self):
        self.controller.replace(0, node=node())
        s = self.controller.replace(1)
        self.assertEqual((s.node, s.privacy, s.policy, s.receive), ("ABSENT",) * 4)

    def test_stale_revision_clears_previous_evidence(self):
        self.controller.replace(0, node=node())
        with self.assertRaisesRegex(OfflineLifecycleError, "^APP_OFFLINE_LIFECYCLE_DENIED$"):
            self.controller.replace(0, node=node())
        self.assertEqual(self.controller.state.transition, "REJECTED")
        self.assertEqual(self.controller.state.node, "ABSENT")

    def test_bool_revision_rejected_without_leaking_input(self):
        with self.assertRaisesRegex(OfflineLifecycleError, "^APP_OFFLINE_LIFECYCLE_DENIED$"):
            self.controller.replace(True)
        self.assertEqual(self.controller.state.revision, 1)

    def test_malformed_input_clears_all_prior_evidence(self):
        self.controller.replace(0, node=node())
        with self.assertRaisesRegex(OfflineLifecycleError, "^APP_OFFLINE_LIFECYCLE_DENIED$"):
            self.controller.replace(1, node={"private": "DO_NOT_ECHO"})
        self.assertEqual(self.controller.state.node, "ABSENT")
        self.assertEqual(self.controller.state.authority, "BLOCKED")

    def test_reset_invalidates_revision(self):
        self.controller.replace(0, node=node())
        s = self.controller.reset()
        self.assertEqual((s.revision, s.transition, s.node), (2, "CLEARED", "ABSENT"))
        with self.assertRaises(OfflineLifecycleError):
            self.controller.replace(1)

    def test_state_is_immutable(self):
        s = self.controller.state
        with self.assertRaises(FrozenInstanceError):
            s.authority = "ALLOWED"

    def test_public_fixture_is_fingerprint_only(self):
        s = self.controller.replace(0, receive=inspect_pinned_public_vector())
        self.assertEqual((s.receive, s.authority), ("PUBLIC_FIXTURE", "BLOCKED"))
        self.assertNotIn("fingerprint", vars(type(s)).keys())

    def test_invalid_mixed_update_never_commits_partial_node(self):
        with self.assertRaises(OfflineLifecycleError):
            self.controller.replace(0, node=node(), privacy={"invalid": True})
        self.assertEqual(self.controller.state.node, "ABSENT")
        self.assertEqual(self.controller.state.privacy, "ABSENT")


if __name__ == "__main__":
    unittest.main()
