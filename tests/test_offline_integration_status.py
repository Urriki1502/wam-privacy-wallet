"""Cross-module fail-closed interaction tests (offline; no operational wallet)."""
from dataclasses import FrozenInstanceError, replace
import socket
import subprocess
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application.node_status import NodeOverview
from wam_privacy_wallet.application.presentation_lifecycle import (
    OfflinePresentationController, OfflinePresentationState,
)
from wam_privacy_wallet.application.recovery_disposition import (
    evaluate_offline_recovery_disposition,
)
from wam_privacy_wallet.application.offline_integration_status import (
    OfflineIntegrationStatus, OfflineIntegrationStatusError,
    inspect_offline_integration,
)
from wam_privacy_wallet.integrations.scanner_window_contract import (
    OfflineScanWindowSummary, validate_offline_scan_window,
)
from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS

A, B = "a" * 64, "b" * 64


def presentation():
    return OfflinePresentationController()


def scan():
    return validate_offline_scan_window(
        start_height=0, start_hash=A,
        reported_tip_before=(1, B), reported_tip_after=(1, B),
        blocks=({
            "hash": B, "previousblockhash": A, "height": 1,
            "tx": [{"txid": "c" * 64}],
        },),
    )


def storage(version=3, checkpoint=1, reported=1, tip=B):
    return evaluate_offline_recovery_disposition({
        "schema": "wam-wallet-storage-review/v1",
        "profile": "WSP-1", "network": "regtest",
        "genesis": WAM_REGTEST_GENESIS, "store_schema_version": version,
        "checkpoint_height": checkpoint, "checkpoint_hash": B,
        "reported_height": reported, "reported_tip": tip,
        "writer_lock": "UNATTESTED", "db_integrity": "UNATTESTED",
        "wallet_identity": "UNATTESTED",
    })


class OfflineIntegrationStatusTests(unittest.TestCase):
    def test_empty_state_remains_no_authority(self):
        result = inspect_offline_integration(presentation().state)
        self.assertEqual(
            (result.revision, result.presentation, result.scan_window, result.storage),
            (0, "EMPTY", "ABSENT", "ABSENT"),
        )
        self.assertEqual(result.status, "REVIEW_ONLY_UNTRUSTED")
        self.assertFalse(result.release_allowed)

    def test_all_three_synthetic_evidence_types_never_make_a_wallet(self):
        controller = presentation()
        overview = NodeOverview(
            "regtest", 1, "READ_ONLY_SNAPSHOT", "EXPERIMENTAL_NO_REAL_FUNDS"
        )
        state = controller.replace(0, node=overview)
        result = inspect_offline_integration(
            state, scan_window=scan(), storage=storage()
        )
        self.assertEqual(
            (result.revision, result.presentation, result.scan_window, result.storage),
            (1, "SYNTHETIC_ONLY", "SYNTHETIC_ONLY", "REVIEW_ONLY_NOT_VERIFIED"),
        )
        self.assertFalse(any((
            result.core_verified, result.scanner_enabled, result.storage_verified,
            result.signer_enabled, result.send_enabled, result.release_allowed,
        )))

    def test_scanner_only_and_storage_only_preserve_no_authority(self):
        empty = presentation().state
        scanner = inspect_offline_integration(empty, scan_window=scan())
        recovery = inspect_offline_integration(empty, storage=storage())
        self.assertEqual((scanner.scan_window, scanner.storage),
                         ("SYNTHETIC_ONLY", "ABSENT"))
        self.assertEqual((recovery.scan_window, recovery.storage),
                         ("ABSENT", "REVIEW_ONLY_NOT_VERIFIED"))
        self.assertFalse(scanner.scanner_enabled)
        self.assertFalse(recovery.storage_verified)

    def test_reset_clears_research_display_without_promoting_other_sources(self):
        c = presentation()
        c.replace(0, node=NodeOverview(
            "regtest", 1, "READ_ONLY_SNAPSHOT", "EXPERIMENTAL_NO_REAL_FUNDS"))
        cleared = c.reset()
        result = inspect_offline_integration(
            cleared, scan_window=scan(), storage=storage()
        )
        self.assertEqual((result.revision, result.presentation), (2, "EMPTY"))
        self.assertFalse(result.scanner_enabled)
        self.assertFalse(result.wallet_ready if hasattr(result, "wallet_ready")
                         else result.storage_verified)

    def test_foreign_presentation_and_subclass_denied(self):
        class ForgedPresentation(OfflinePresentationState):
            pass
        s = presentation().state
        bad = [None, {}, True, ForgedPresentation(*(
            getattr(s, key) for key in
            ("revision", "node", "privacy", "policy", "receive",
             "authority", "network", "wallet", "transition")
        ))]
        for item in bad:
            with self.subTest(t=type(item).__name__), self.assertRaisesRegex(
                OfflineIntegrationStatusError,
                "^APP_INTEGRATION_PRESENTATION_DENIED$",
            ):
                inspect_offline_integration(item)

    def test_forged_presentation_network_claim_denied(self):
        bad = replace(presentation().state, network="mainnet")
        with self.assertRaisesRegex(
            OfflineIntegrationStatusError, "^APP_INTEGRATION_PRESENTATION_DENIED$"
        ):
            inspect_offline_integration(bad)

    def test_forged_presentation_operational_claim_denied(self):
        s = presentation().state
        object.__setattr__(s, "authority", "RELEASE_ALLOWED")
        with self.assertRaisesRegex(
            OfflineIntegrationStatusError, "^APP_INTEGRATION_PRESENTATION_DENIED$"
        ):
            inspect_offline_integration(s)

    def test_bool_or_negative_revision_is_denied(self):
        for revision in (True, -1, 2**64, "1"):
            with self.subTest(revision=revision), self.assertRaisesRegex(
                OfflineIntegrationStatusError, "^APP_INTEGRATION_PRESENTATION_DENIED$"
            ):
                inspect_offline_integration(
                    replace(presentation().state, revision=revision)
                )

    def test_cleared_or_rejected_state_cannot_claim_evidence(self):
        for transition in ("CLEARED", "REJECTED"):
            original = presentation().reset()
            contradictory = replace(original, transition=transition, node="UNVERIFIED")
            with self.subTest(transition=transition), self.assertRaisesRegex(
                OfflineIntegrationStatusError,
                "^APP_INTEGRATION_PRESENTATION_DENIED$",
            ):
                inspect_offline_integration(contradictory)

    def test_initial_and_replaced_revision_order_cannot_be_forged(self):
        initial = presentation().state
        for invalid in (
            replace(initial, revision=1),
            replace(initial, transition="REPLACED"),
            replace(initial, transition="CLEARED"),
        ):
            with self.subTest(state=invalid), self.assertRaisesRegex(
                OfflineIntegrationStatusError,
                "^APP_INTEGRATION_PRESENTATION_DENIED$",
            ):
                inspect_offline_integration(invalid)

    def test_foreign_scan_summary_and_subclass_denied(self):
        class ForgedScan(OfflineScanWindowSummary):
            pass
        s = scan()
        for value in (True, {}, ForgedScan(
            s.start_height, s.end_height, s.block_count, s.transaction_count,
        )):
            with self.subTest(value=type(value).__name__), self.assertRaisesRegex(
                OfflineIntegrationStatusError, "^APP_INTEGRATION_SCANNER_DENIED$"
            ):
                inspect_offline_integration(presentation().state, scan_window=value)

    def test_in_place_scan_authority_forgery_denied(self):
        s = scan()
        object.__setattr__(s, "rpc_authenticated", True)
        with self.assertRaisesRegex(
            OfflineIntegrationStatusError, "^APP_INTEGRATION_SCANNER_DENIED$"
        ):
            inspect_offline_integration(presentation().state, scan_window=s)

    def test_scan_malformed_window_counts_denied(self):
        s = scan()
        for field, val in (("end_height", 3), ("block_count", True),
                           ("transaction_count", 20001), ("start_height", -1)):
            with self.subTest(field=field), self.assertRaisesRegex(
                OfflineIntegrationStatusError, "^APP_INTEGRATION_SCANNER_DENIED$"
            ):
                inspect_offline_integration(
                    presentation().state, scan_window=replace(s, **{field: val})
                )

    def test_empty_window_with_forged_transaction_count_denied(self):
        # The scanner validator cannot produce this contradictory DTO;
        # downstream integration must reject a forged exact-type summary.
        base = OfflineScanWindowSummary(3, 3, 0, 0)
        good = inspect_offline_integration(
            presentation().state, scan_window=base
        )
        self.assertEqual(good.scan_window, "SYNTHETIC_ONLY")
        forged = replace(base, transaction_count=1)
        with self.assertRaisesRegex(
            OfflineIntegrationStatusError,
            "^APP_INTEGRATION_SCANNER_DENIED$",
        ):
            inspect_offline_integration(
                presentation().state, scan_window=forged
            )

    def test_bad_storage_decision_on_legacy_denied(self):
        bad = replace(storage(version=2), decision="REVIEW_ONLY_NOT_VERIFIED")
        with self.assertRaisesRegex(
            OfflineIntegrationStatusError, "^APP_INTEGRATION_STORAGE_DENIED$"
        ):
            inspect_offline_integration(presentation().state, storage=bad)

    def test_storage_review_claim_with_mismatched_heights_denied(self):
        bad = replace(storage(), observed_height=3)
        with self.assertRaisesRegex(
            OfflineIntegrationStatusError, "^APP_INTEGRATION_STORAGE_DENIED$"
        ):
            inspect_offline_integration(presentation().state, storage=bad)

    def test_in_place_storage_writer_claim_denied(self):
        bad = storage()
        object.__setattr__(bad, "writer_verified", True)
        with self.assertRaisesRegex(
            OfflineIntegrationStatusError, "^APP_INTEGRATION_STORAGE_DENIED$"
        ):
            inspect_offline_integration(presentation().state, storage=bad)

    def test_legacy_storage_remains_migration_rescan_required(self):
        s = inspect_offline_integration(
            presentation().state, scan_window=scan(), storage=storage(version=2)
        )
        self.assertEqual(s.storage, "MIGRATION_RESCAN_REQUIRED")
        self.assertFalse(s.storage_verified)

    def test_immutable_output_cannot_be_escalated(self):
        s = inspect_offline_integration(presentation().state)
        with self.assertRaises(FrozenInstanceError):
            s.scanner_enabled = True
        for name in ("core_verified", "scanner_enabled", "storage_verified",
                     "signer_enabled", "send_enabled", "release_allowed", "status"):
            with self.subTest(field=name), self.assertRaises(TypeError):
                OfflineIntegrationStatus(0, "EMPTY", "ABSENT", "ABSENT",
                                         **{name: True})
            with self.assertRaises(ValueError):
                replace(s, **{name: True})

    def test_summary_drops_all_hashes_paths_keys_and_source_objects(self):
        state = presentation().state
        w, r = scan(), storage()
        summary = inspect_offline_integration(state, scan_window=w, storage=r)
        self.assertNotIn(A, repr(summary))
        self.assertNotIn(B, repr(summary))
        for name in ("source", "scan", "checkpoint_hash", "endpoint", "rpc",
                     "seed", "password", "txid", "path", "wallet_handle"):
            self.assertFalse(hasattr(summary, name))
        self.assertFalse(any(value is w or value is r or value is state
                             for value in vars(summary).values())
                         if hasattr(summary, "__dict__") else False)

    def test_recovery_only_managed_presentation_is_research_not_ready(self):
        from wam_privacy_wallet.application.recovery_transition import (
            OfflineRecoveryTransition,
        )
        receipt = OfflineRecoveryTransition(
            "NO_TRUSTED_RECOVERY_EVIDENCE",
            "REVIEW_ONLY_NOT_VERIFIED", 5, 6, 5,
        )
        controller = presentation()
        state = controller.replace(0, recovery=receipt)
        summary = inspect_offline_integration(state)
        self.assertEqual((state.revision, state.recovery),
                         (1, "REVIEW_ONLY_NOT_VERIFIED"))
        self.assertEqual(summary.presentation, "SYNTHETIC_ONLY")
        self.assertEqual(summary.status, "REVIEW_ONLY_UNTRUSTED")
        self.assertFalse(summary.storage_verified)

    def test_cleared_state_cannot_retain_recovery_preview(self):
        clear_state = presentation().reset()
        forged = replace(clear_state, recovery="RESCAN_REQUIRED")
        with self.assertRaisesRegex(
            OfflineIntegrationStatusError,
            "^APP_INTEGRATION_PRESENTATION_DENIED$",
        ):
            inspect_offline_integration(forged)

    def test_conflicting_storage_and_presentation_recovery_denied(self):
        from wam_privacy_wallet.application.recovery_transition import (
            OfflineRecoveryTransition,
        )
        receipt = OfflineRecoveryTransition(
            "RESCAN_REQUIRED", "RESCAN_REQUIRED", 5, 6, 5,
        )
        controller = presentation()
        display = controller.replace(0, recovery=receipt)
        self.assertEqual(display.recovery, "RESCAN_REQUIRED")
        with self.assertRaisesRegex(
            OfflineIntegrationStatusError, "^APP_INTEGRATION_STORAGE_DENIED$"
        ):
            inspect_offline_integration(display, storage=storage())
        self.assertFalse(inspect_offline_integration(display).release_allowed)

    def test_no_network_file_subprocess_or_operational_engine(self):
        s, w, r = presentation().state, scan(), storage()
        with patch("builtins.open", side_effect=AssertionError("NO_FILE")), \
             patch.object(socket, "socket", side_effect=AssertionError("NO_SOCKET")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("NO_PROC")):
            result = inspect_offline_integration(s, scan_window=w, storage=r)
        self.assertFalse(result.release_allowed)
        import sys
        self.assertFalse(any(k.startswith("wam_sp") for k in sys.modules))


if __name__ == "__main__":
    unittest.main()
