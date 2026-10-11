"""Synthetic two-snapshot rollback/migration regressions, zero wallet IO."""
from dataclasses import FrozenInstanceError, replace
import socket
import subprocess
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS
from wam_privacy_wallet.application.recovery_transition import (
    OfflineRecoveryTransition, OfflineRecoveryTransitionError,
    evaluate_offline_recovery_transition,
)

A, B, C = "a" * 64, "b" * 64, "c" * 64


def record(*, version=3, height=5, block=A, tip_height=None, tip=None, **updates):
    payload = {
        "schema": "wam-wallet-storage-review/v1",
        "profile": "WSP-1", "network": "regtest",
        "genesis": WAM_REGTEST_GENESIS,
        "store_schema_version": version, "checkpoint_height": height,
        "checkpoint_hash": block,
        "reported_height": height if tip_height is None else tip_height,
        "reported_tip": block if tip is None else tip,
        "writer_lock": "UNATTESTED", "db_integrity": "UNATTESTED",
        "wallet_identity": "UNATTESTED",
    }
    payload.update(updates)
    return payload


def transition(*, old=None, candidate=None, old_revision=7, new_revision=8):
    return evaluate_offline_recovery_transition(
        old=record() if old is None else old,
        candidate=record() if candidate is None else candidate,
        old_revision=old_revision, new_revision=new_revision,
    )


class OfflineRecoveryTransitionTests(unittest.TestCase):
    def test_matching_synthetic_checkpoint_remains_unverified(self):
        r = transition()
        self.assertEqual(r.reason, "NO_TRUSTED_RECOVERY_EVIDENCE")
        self.assertEqual(r.decision, "REVIEW_ONLY_NOT_VERIFIED")
        self.assertEqual((r.old_revision, r.new_revision, r.checkpoint_height), (7, 8, 5))
        self.assertEqual(r.status, "SYNTHETIC_TRANSITION_UNTRUSTED")
        self.assertFalse(any((
            r.writer_verified, r.chain_verified, r.recovery_completed, r.wallet_enabled,
        )))

    def test_advancing_matching_height_still_not_ready(self):
        r = transition(candidate=record(height=6, block=B))
        self.assertEqual(r.decision, "REVIEW_ONLY_NOT_VERIFIED")
        self.assertFalse(r.wallet_enabled)

    def test_legacy_version_two_to_three_does_not_prove_rescan(self):
        r = transition(old=record(version=2))
        self.assertEqual((r.reason, r.decision),
                         ("MIGRATION_RESCAN_REQUIRED", "MIGRATION_RESCAN_REQUIRED"))

    def test_legacy_zero_to_two_remains_migration_rescan(self):
        r = transition(old=record(version=0), candidate=record(version=2))
        self.assertEqual(r.decision, "MIGRATION_RESCAN_REQUIRED")

    def test_downgrade_to_legacy_is_fail_closed(self):
        r = transition(candidate=record(version=2))
        self.assertEqual((r.reason, r.decision),
                         ("VERSION_DOWNGRADE", "MIGRATION_RESCAN_REQUIRED"))

    def test_checkpoint_height_rollback_is_detected(self):
        r = transition(candidate=record(height=4, block=B))
        self.assertEqual((r.reason, r.decision),
                         ("CHECKPOINT_ROLLBACK", "RESCAN_REQUIRED"))

    def test_reported_tip_rewind_independent_of_checkpoint_height(self):
        old = record(height=4, block=A, tip_height=7, tip=B)
        new = record(height=4, block=A, tip_height=6, tip=C)
        r = transition(old=old, candidate=new)
        self.assertEqual((r.reason, r.decision),
                         ("REPORTED_TIP_REWIND", "RESCAN_REQUIRED"))

    def test_same_height_changed_checkpoint_hash_triggers_rescan(self):
        r = transition(candidate=record(height=5, block=B))
        self.assertEqual((r.reason, r.decision),
                         ("CHECKPOINT_FORK_OR_RESTORE", "RESCAN_REQUIRED"))

    def test_same_tip_height_changed_tip_hash_triggers_rescan(self):
        old = record(height=4, block=A, tip_height=5, tip=B)
        new = record(height=4, block=A, tip_height=5, tip=C)
        r = transition(old=old, candidate=new)
        self.assertEqual((r.reason, r.decision),
                         ("CHECKPOINT_FORK_OR_RESTORE", "RESCAN_REQUIRED"))

    def test_candidate_stale_reported_height_is_not_ready(self):
        r = transition(candidate=record(tip_height=6, tip=B))
        self.assertEqual((r.reason, r.decision), ("RESCAN_REQUIRED", "RESCAN_REQUIRED"))

    def test_strict_sequential_revision_and_integer_bounds(self):
        cases = ((-1, 0), (True, 2), (0, True), (1, 3),
                 (3, "4"), (2**63 - 1, 2**63), (8, 8), (None, 1))
        for old, new in cases:
            with self.subTest(old=old, new=new), self.assertRaisesRegex(
                OfflineRecoveryTransitionError, "^RECOVERY_TRANSITION_REVISION_DENIED$"
            ):
                transition(old_revision=old, new_revision=new)

    def test_invalid_old_and_candidate_rejected_without_details(self):
        for field in ("old", "candidate"):
            for bad in (True, [], "SEED SHOULD NOT LEAK", {"seed": "SHOULD_NOT_LEAK"}):
                with self.subTest(field=field, typ=type(bad).__name__), self.assertRaisesRegex(
                    OfflineRecoveryTransitionError, "^RECOVERY_TRANSITION_INPUT_DENIED$"
                ):
                    transition(**{field: bad})

    def test_foreign_network_and_unattested_claims_rejected(self):
        for payload in (
            record(network="mainnet"),
            record(writer_lock="VERIFIED"),
            record(genesis=C),
            record(store_schema_version=4),
        ):
            with self.subTest(payload=payload.get("network")), self.assertRaisesRegex(
                OfflineRecoveryTransitionError, "^RECOVERY_TRANSITION_INPUT_DENIED$"
            ):
                transition(candidate=payload)

    def test_output_never_retains_raw_hashes_secrets_or_inputs(self):
        r = transition(old=record(block=A), candidate=record(height=6, block=B))
        self.assertNotIn(A, repr(r))
        self.assertNotIn(B, repr(r))
        for field in ("checkpoint_hash", "reported_tip", "seed", "path",
                      "wallet_handle", "rpc", "private_key", "input", "candidate"):
            self.assertFalse(hasattr(r, field))

    def test_authority_claims_are_constructor_and_replace_protected(self):
        r = transition()
        with self.assertRaises(FrozenInstanceError):
            r.wallet_enabled = True
        for field in ("writer_verified", "chain_verified", "wallet_enabled",
                      "recovery_completed", "status"):
            with self.subTest(field=field), self.assertRaises(TypeError):
                OfflineRecoveryTransition("NO_TRUSTED_RECOVERY_EVIDENCE",
                    "REVIEW_ONLY_NOT_VERIFIED", 7, 8, 5, **{field: True})
            with self.assertRaises(ValueError):
                replace(r, **{field: True})

    def test_no_file_socket_subprocess_or_wsp_imports(self):
        old, candidate = record(), record(height=6, block=B)
        with patch("builtins.open", side_effect=AssertionError("NO_FILE")), \
             patch.object(socket, "socket", side_effect=AssertionError("NO_SOCKET")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("NO_PROCESS")):
            result = transition(old=old, candidate=candidate)
        self.assertFalse(result.wallet_enabled)
        import sys
        self.assertFalse(any(name.startswith("wam_sp") for name in sys.modules))


if __name__ == "__main__":
    unittest.main()
