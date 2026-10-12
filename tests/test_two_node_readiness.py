"""Synthetic readiness contracts; no Core process or node connections."""
import unittest
from unittest.mock import patch
from wam_privacy_wallet.node.two_node_readiness import TwoNodeReadiness


class TwoNodeReadinessTests(unittest.TestCase):
    def test_default_is_blocked(self):
        receipt = TwoNodeReadiness().receipt()
        self.assertEqual(receipt["status"], "BLOCKED_REQUIRES_GENUINE_CORE_REVIEW")
        self.assertFalse(receipt["real_two_node_regtest_qualified"])

    def test_all_claimed_evidence_still_cannot_grant_authority(self):
        receipt = TwoNodeReadiness(True, True, True, True, True, True).receipt()
        self.assertFalse(receipt["core_execution_allowed"])
        self.assertFalse(receipt["wallet_ready"])
        self.assertFalse(receipt["mainnet_allowed"])
        self.assertFalse(receipt["evidence_complete"])

    def test_non_boolean_evidence_denied(self):
        with self.assertRaisesRegex(ValueError, "REGTEST_READINESS_INVALID"):
            TwoNodeReadiness(verified_executable_binding=1)

    def test_receipt_has_no_secrets_or_hashes(self):
        receipt = TwoNodeReadiness().receipt()
        self.assertEqual(set(receipt), {
            "status", "evidence_complete", "real_two_node_regtest_qualified",
            "core_execution_allowed", "scanner_enabled", "wallet_ready",
            "signing_allowed", "broadcast_allowed", "mainnet_allowed"})

    def test_readiness_never_launches_core(self):
        with patch("subprocess.Popen", side_effect=AssertionError("NO_LAUNCH")):
            TwoNodeReadiness(True, True, True, True, True, True).receipt()


if __name__ == "__main__":
    unittest.main()
