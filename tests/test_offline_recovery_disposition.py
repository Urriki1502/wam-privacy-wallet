"""No-key, no-IO WSP-1 storage and recovery policy regression suite."""
from dataclasses import FrozenInstanceError, replace
import socket
import subprocess
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS
from wam_privacy_wallet.application.recovery_disposition import (
    OfflineRecoveryDisposition, RecoveryDispositionError,
    evaluate_offline_recovery_disposition,
)

H = "a" * 64
OTHER = "b" * 64


def sample(**changes):
    input_data = {
        "schema": "wam-wallet-storage-review/v1",
        "profile": "WSP-1",
        "network": "regtest",
        "genesis": WAM_REGTEST_GENESIS,
        "store_schema_version": 3,
        "checkpoint_height": 7,
        "checkpoint_hash": H,
        "reported_height": 7,
        "reported_tip": H,
        "writer_lock": "UNATTESTED",
        "db_integrity": "UNATTESTED",
        "wallet_identity": "UNATTESTED",
    }
    input_data.update(changes)
    return input_data


def check(**changes):
    return evaluate_offline_recovery_disposition(sample(**changes))


class OfflineRecoveryDispositionTests(unittest.TestCase):
    def test_current_schema_matching_checkpoint_remains_unverified(self):
        decision = check()
        self.assertEqual(decision.decision, "REVIEW_ONLY_NOT_VERIFIED")
        self.assertEqual((decision.checkpoint_height, decision.observed_height), (7, 7))
        self.assertEqual(decision.store_schema_version, 3)
        self.assertEqual(decision.authority, "BLOCKED")
        for flag in ("writer_verified", "chain_verified", "wallet_enabled",
                     "recovery_completed"):
            self.assertIs(getattr(decision, flag), False)

    def test_stale_checkpoint_requires_rescan(self):
        d = check(checkpoint_height=5, reported_height=7)
        self.assertEqual(d.decision, "RESCAN_REQUIRED")
        self.assertFalse(d.wallet_enabled)

    def test_tip_hash_mismatch_requires_rescan(self):
        d = check(reported_tip=OTHER)
        self.assertEqual(d.decision, "RESCAN_REQUIRED")

    def test_local_ahead_of_claimed_tip_requires_rescan(self):
        d = check(checkpoint_height=8, reported_height=7)
        self.assertEqual(d.decision, "RESCAN_REQUIRED")

    def test_pinned_wsp_legacy_versions_require_migration_rescan(self):
        for version in (0, 2):
            with self.subTest(version=version):
                d = check(store_schema_version=version)
                self.assertEqual(d.decision, "MIGRATION_RESCAN_REQUIRED")
                self.assertIs(d.recovery_completed, False)

    def test_legacy_migration_takes_precedence_over_matching_tip(self):
        d = check(store_schema_version=2, checkpoint_hash=OTHER)
        self.assertEqual(d.decision, "MIGRATION_RESCAN_REQUIRED")

    def test_bogus_schema_and_non_mapping_rejected(self):
        for payload in (None, True, [], "secret", {}, {"schema": 1}):
            with self.subTest(kind=type(payload).__name__), self.assertRaisesRegex(
                RecoveryDispositionError, "^RECOVERY_SCHEMA_DENIED$"
            ):
                evaluate_offline_recovery_disposition(payload)

    def test_missing_or_extra_schema_fields_fail_closed(self):
        data = sample()
        for field in tuple(data):
            changed = dict(data)
            del changed[field]
            with self.subTest(missing=field), self.assertRaisesRegex(
                RecoveryDispositionError, "^RECOVERY_SCHEMA_DENIED$"
            ):
                evaluate_offline_recovery_disposition(changed)
        data["release_allowed"] = True
        with self.assertRaisesRegex(
            RecoveryDispositionError, "^RECOVERY_SCHEMA_DENIED$"
        ):
            evaluate_offline_recovery_disposition(data)

    def test_alias_field_names_are_rejected(self):
        class Alias(str):
            pass
        data = sample()
        data[Alias("network")] = data.pop("network")
        with self.assertRaisesRegex(
            RecoveryDispositionError, "^RECOVERY_SCHEMA_DENIED$"
        ):
            evaluate_offline_recovery_disposition(data)

    def test_wrong_network_genesis_profile_or_schema_denied(self):
        for field, val in (
            ("network", "mainnet"), ("network", True),
            ("profile", "WSP-2"), ("profile", True),
            ("genesis", OTHER), ("genesis", None),
            ("schema", "wam-wallet-storage-review/v2"),
        ):
            with self.subTest(field=field, val=val), self.assertRaisesRegex(
                RecoveryDispositionError, "^RECOVERY_PROFILE_DENIED$"
            ):
                check(**{field: val})

    def test_unaccepted_versions_bool_and_string_denied(self):
        for version in (True, False, "3", None, 1, 4, -1):
            with self.subTest(version=version), self.assertRaisesRegex(
                RecoveryDispositionError, "^RECOVERY_VERSION_DENIED$"
            ):
                check(store_schema_version=version)

    def test_malformed_checkpoint_or_reported_height_denied(self):
        for key in ("checkpoint_height", "reported_height"):
            for value in (-1, 100000001, True, "7", None, 7.0):
                with self.subTest(key=key, val=value), self.assertRaisesRegex(
                    RecoveryDispositionError, "^RECOVERY_HEIGHT_DENIED$"
                ):
                    check(**{key: value})

    def test_malformed_hashes_denied(self):
        for key in ("checkpoint_hash", "reported_tip"):
            for value in (True, None, "short", "G" * 64, H.upper(), H + "\n"):
                with self.subTest(key=key, value=repr(value)), self.assertRaisesRegex(
                    RecoveryDispositionError, "^RECOVERY_HASH_DENIED$"
                ):
                    check(**{key: value})

    def test_no_caller_can_claim_verified_writer_identity_or_integrity(self):
        for key in ("writer_lock", "wallet_identity", "db_integrity"):
            for value in ("VERIFIED", True, False, None, 0, "READY"):
                with self.subTest(field=key, value=value), self.assertRaisesRegex(
                    RecoveryDispositionError, "^RECOVERY_AUTHORITY_DENIED$"
                ):
                    check(**{key: value})

    def test_immutable_output_cannot_set_operational_flags(self):
        disposition = check()
        with self.assertRaises(FrozenInstanceError):
            disposition.wallet_enabled = True
        for claim in ("wallet_enabled", "chain_verified", "writer_verified",
                      "recovery_completed", "authority"):
            with self.subTest(claim=claim), self.assertRaises(TypeError):
                OfflineRecoveryDisposition("REVIEW_ONLY_NOT_VERIFIED", 7, 7, 3,
                                           **{claim: True})
            with self.assertRaises(ValueError):
                replace(disposition, **{claim: True})

    def test_output_contains_no_secrets_or_keys(self):
        disposition = check()
        for name in ("seed", "password", "private_key", "db_path", "account",
                     "scanner", "rpc", "credential", "txid", "address"):
            self.assertFalse(hasattr(disposition, name))
        self.assertNotIn(H, repr(disposition))

    def test_readonly_policy_never_uses_file_socket_or_subprocess(self):
        with patch("builtins.open", side_effect=AssertionError("NO_IO")), \
             patch.object(socket, "socket", side_effect=AssertionError("NO_SOCKET")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("NO_PROC")):
            disposition = check()
        self.assertEqual(disposition.decision, "REVIEW_ONLY_NOT_VERIFIED")

    def test_untrusted_payload_subclasses_are_rejected(self):
        class Alias(str):
            pass
        for field in ("profile", "network", "genesis", "schema"):
            p = sample()
            p[field] = Alias(p[field])
            with self.subTest(field=field), self.assertRaises(
                RecoveryDispositionError
            ):
                evaluate_offline_recovery_disposition(p)


if __name__ == "__main__":
    unittest.main()
