"""Unsigned test headers only. Never launch or extract WAM Core."""
import struct
import unittest
from unittest.mock import patch
from pathlib import Path

from tools import ci_macos_arm64_core_intake as subject


def macho(cpu=0x0100000C, filetype=2, magic=0xFEEDFACF):
    return struct.pack("<IiiIIIII", magic, cpu, 0, filetype, 2, 128, 0, 0)


class MacSignedIntakeTests(unittest.TestCase):
    def test_thin_arm64_executable_header(self):
        self.assertEqual(subject.classify_arm64_macho(macho()),
                         "THIN_MACHO64_ARM64_EXECUTE")

    def test_rejects_x86_fat_object_malformed_or_oversized(self):
        for body in (
            macho(cpu=0x01000007), macho(filetype=6),
            macho(magic=0xCAFEBABE), b"", b"0" * 31,
            struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 0, 0, 1),
        ):
            with self.subTest(body=body[:4]), self.assertRaises(subject.MacCoreIntakeError):
                subject.classify_arm64_macho(body)

    def test_operator_must_select_official_arm64_archive_before_network(self):
        with patch.object(subject, "verify_official_release") as verify:
            for path in (
                Path("relative.tar.gz"), Path("/tmp/arbitrary.tar.gz"),
                Path("/tmp/wam-coin-v0.1.11-x86_64-linux-gnu.tar.gz"),
            ):
                with self.assertRaisesRegex(subject.MacCoreIntakeError,
                                            "^CORE_MAC_INPUT_DENIED$"):
                    subject.review_macos_core_arm64(path, Path("/usr/bin/gpg"))
            verify.assert_not_called()

    def test_receipt_never_authorizes_binary_execution(self):
        valid = {
            "status": "SIGNED_ARCHIVE_REVIEW_ONLY",
            "archive_name": subject._ASSET,
            "node_entry": subject._MEMBER,
            "signer_fingerprint": subject._FINGERPRINT,
            "metadata_origin": "PINNED_WAM_HTTPS_V0_1_11",
            "node_sha256": "a" * 64,
            "archive_sha256": "b" * 64,
            "core_execution_allowed": False, "execution_identity_bound": False,
            "mainnet_allowed": False, "real_wallet_allowed": False,
            "real_regtest_qualified": False,
        }
        target = Path.cwd().resolve() / subject._ASSET
        with patch.object(subject, "verify_official_release", return_value=valid):
            with patch.object(subject, "_hash_exact_member") as read:
                for change in ("core_execution_allowed", "mainnet_allowed",
                               "real_regtest_qualified"):
                    invalid = dict(valid, **{change: True})
                    with patch.object(subject, "verify_official_release", return_value=invalid):
                        with self.assertRaisesRegex(subject.MacCoreIntakeError,
                                                    "^CORE_MAC_SIGNED_RECEIPT_DENIED$"):
                            subject.review_macos_core_arm64(target, Path("/usr/bin/gpg"))
                read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
