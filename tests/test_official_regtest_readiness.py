"""Official signed WAM Core readiness report: mocked I/O, NO EXEC.

Real native release/GPG verification remains a separate required workflow;
these cases prove that even cryptographically authenticated input cannot
authorize the wallet, process execution, signing, broadcast, or mainnet.
"""
from __future__ import annotations

from contextlib import contextmanager
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import verify_official_regtest_readiness as readiness


@contextmanager
def _metadata():
    root = Path.cwd()
    yield {"key": root / "key", "checksums": root / "SHA256SUMS",
           "signature": root / "SHA256SUMS.asc"}


@contextmanager
def _fake_signed_review(**_):
    receipt = SimpleNamespace(
        sha256="a" * 64, byte_count=1024,
        core_execution_allowed=False,
        execution_identity_bound=False, mainnet_allowed=False,
    )
    yield SimpleNamespace(_descriptor=123, evidence=receipt, audit=lambda: True)


class OfficialRegtestReadinessTests(unittest.TestCase):
    def _inputs(self) -> dict[str, str]:
        root = Path.cwd()
        return {"archive": str(root / "official-v0.1.11.tar.gz"),
                "gpg": str(root / "gpg")}

    def _patched(self):
        return (
            patch.object(readiness, "official_release_metadata", side_effect=_metadata),
            patch.object(readiness, "sealed_signed_linux_wamd",
                         side_effect=_fake_signed_review),
        )

    def test_known_signed_exec_stack_is_explicitly_blocked(self):
        meta, snapshot = self._patched()
        with meta, snapshot, patch.object(
            readiness, "inspect_sealed_linux_elf",
            side_effect=readiness.SealedElfError("CORE_ELF_EXECUTABLE_STACK_DENIED"),
        ):
            report = readiness.inspect_official_regtest_readiness(**self._inputs())
        self.assertEqual(report["status"], "OFFICIAL_WAM_CORE_REGTEST_BLOCKED_NO_EXEC")
        self.assertTrue(report["known_elf_exec_stack_denial"])
        self.assertEqual(report["elf_policy_denial"], "CORE_ELF_EXECUTABLE_STACK_DENIED")
        self.assertEqual(report["signed_official_member_sha256"], "a" * 64)
        for field in (
            "publisher_build_mapping_approved", "dynamic_loader_and_dso_authenticated",
            "kernel_executed_image_bound", "dev_wam_binary_approved",
            "genuine_two_node_regtest_qualified", "wam_core_executed",
            "wallet_enabled", "signing_allowed", "broadcast_allowed", "mainnet_allowed",
        ):
            self.assertIs(report[field], False, field)

    def test_clean_elf_still_cannot_grant_wam_process_launch(self):
        meta, snapshot = self._patched()
        with meta, snapshot, patch.object(
            readiness, "inspect_sealed_linux_elf", return_value=object(),
        ):
            report = readiness.inspect_official_regtest_readiness(**self._inputs())
        self.assertFalse(report["known_elf_exec_stack_denial"])
        self.assertEqual(report["elf_policy_denial"], "")
        self.assertFalse(report["wam_core_executed"])
        self.assertFalse(report["kernel_executed_image_bound"])
        self.assertFalse(report["dev_wam_binary_approved"])

    def test_malformed_elf_is_not_mislabeled_as_known_execstack_hold(self):
        meta, snapshot = self._patched()
        with meta, snapshot, patch.object(
            readiness, "inspect_sealed_linux_elf",
            side_effect=readiness.SealedElfError("CORE_ELF_HEADER_DENIED"),
        ):
            with self.assertRaisesRegex(
                readiness.SealedElfError, "^CORE_ELF_HEADER_DENIED$",
            ):
                readiness.inspect_official_regtest_readiness(**self._inputs())

    def test_untrusted_review_claim_is_denied_before_elf_read(self):
        @contextmanager
        def forged(**_):
            yield SimpleNamespace(
                _descriptor=123, audit=lambda: True,
                evidence=SimpleNamespace(
                    sha256="a" * 64, byte_count=1024,
                    core_execution_allowed=True,
                    execution_identity_bound=False, mainnet_allowed=False,
                ),
            )
        with patch.object(readiness, "official_release_metadata", side_effect=_metadata), \
             patch.object(readiness, "sealed_signed_linux_wamd", side_effect=forged), \
             patch.object(readiness, "inspect_sealed_linux_elf") as parser:
            with self.assertRaisesRegex(
                readiness.SignedNodeSealError,
                "^CORE_REGTEST_READINESS_AUTHORITY_DENIED$",
            ):
                readiness.inspect_official_regtest_readiness(**self._inputs())
            parser.assert_not_called()

    def test_failed_signature_emits_only_redacted_error_without_json(self):
        meta, _snapshot = self._patched()
        with meta, patch.object(
            readiness, "sealed_signed_linux_wamd",
            side_effect=readiness.SignedNodeSealError("SECRET_PATH_OR_GPG_KEY"),
        ), patch("sys.stdout", new_callable=io.StringIO) as out, \
             patch("sys.stderr", new_callable=io.StringIO) as err:
            exit_code = readiness.main([
                "--archive", self._inputs()["archive"], "--gpg", self._inputs()["gpg"],
            ])
        self.assertEqual(exit_code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(err.getvalue().strip(), "CORE_REGTEST_READINESS_DENIED")
        self.assertNotIn("SECRET", err.getvalue())


if __name__ == "__main__":
    unittest.main()
