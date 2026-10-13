"""Future WAM signed successor intake is fail-closed, no Core process.

GPG replies are fixtures: this suite does NOT assert a genuine DEV signature.
Genuine v0.1.11 signed archive is already tested independently elsewhere;
future signed artifacts must be supplied and checked by the operator/DEV.
"""
import hashlib
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node import core_next_signed_intake as target
from wam_privacy_wallet.node import core_signed_release as signed

_ROOT = "wam-coin-v0.1.12"
_NAME = _ROOT + "-x86_64-linux-gnu.tar.gz"
_EHDR = struct.Struct("<HHIQQQIHHHHHH")
_PHDR = struct.Struct("<IIQQQQQQ")


def good_elf(stack=6):
    blob = bytearray(512)
    blob[:16] = b"\x7fELF" + bytes((2, 1, 1)) + bytes(9)
    blob[16:64] = _EHDR.pack(3, 62, 1, 0x401000, 64, 0, 0,
                            64, 56, 2, 0, 0, 0)
    blob[64:120] = _PHDR.pack(1, 5, 0, 0x400000, 0, 512, 512, 4096)
    blob[120:176] = _PHDR.pack(0x6474E551, stack, 0, 0, 0, 0, 0, 0)
    return bytes(blob)


class SuccessorIntakeTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory(prefix="core-successor-test-")
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.archive = self.root / _NAME
        self.key = self.root / "SIGNING-KEY.asc"
        self.sums = self.root / "SHA256SUMS"
        self.signature = self.root / "SHA256SUMS.asc"
        self.gpg = self.root / "trusted-gpg"  # absolute on every OS; never launched
        self.key.write_bytes(b"FICTIONAL_KEY_FOR_NEGATIVE_TEST_ONLY\n")
        self.signature.write_bytes(b"FICTIONAL_SIGNATURE_NO_REAL_AUTHENTICATION\n")
        self.make_archive()
        self.write_sums()
        self.args = {
            "archive": self.archive, "signing_key": self.key,
            "sha256sums": self.sums,
            "detached_signature": self.signature,
            "gpg_executable": self.gpg,
        }

    def make_archive(self, stack=6):
        with tarfile.open(self.archive, "w:gz") as tf:
            for name, payload in (
                (_ROOT + "/bin/wamd", good_elf(stack)),
                (_ROOT + "/bin/wam-cli", good_elf()),
                (_ROOT + "/share/examples/wam.conf",
                 b"#server=1\n#regtest=1\n#rpcbind=127.0.0.1\n"),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                member.mode = 0o644
                tf.addfile(member, io.BytesIO(payload))

    def write_sums(self, wrong=False):
        sha = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.sums.write_text(
            (("0" * 64 if wrong else sha) + "  " + _NAME + "\n"),
            encoding="ascii",
        )

    def fake_gpg(self, exe, home, args):
        if "--with-colons" in args:
            return (0, "pub:::::::::\n"
                       "fpr:::::::::" + signed.WAM_RELEASE_SIGNING_FINGERPRINT
                       + ":\n")
        if "--status-fd" in args:
            return (0, "[GNUPG:] GOODSIG 1 fake\n"
                       "[GNUPG:] VALIDSIG " +
                       signed.WAM_RELEASE_SIGNING_FINGERPRINT + "\n")
        return 0, ""

    def inspect(self):
        with patch.object(target, "_run_gpg", side_effect=self.fake_gpg), \
             patch("subprocess.Popen",
                   side_effect=AssertionError("CORE_EXECUTION_FORBIDDEN")):
            return target.inspect_signed_successor(**self.args)

    def denied(self, code):
        with self.assertRaisesRegex(target.CoreSuccessorIntakeError,
                                    "^" + code + "$"):
            self.inspect()

    def test_fixture_checks_complete_but_no_runtime_authority(self):
        receipt = self.inspect()
        self.assertEqual(receipt.status,
                         "SIGNED_SUCCESSOR_STATIC_ARCHIVE_INSPECTED_NO_EXEC")
        self.assertTrue(receipt.detached_signature_verified)
        self.assertEqual(receipt.binary_names, ("wam-cli", "wamd"))
        for key in ("published_key_freshness_verified", "source_build_mapping_verified",
                    "help_options_parity_verified", "os_loader_identity_verified",
                    "process_identity_verified", "core_execution_allowed",
                    "genuine_two_node_regtest_qualified", "wallet_operational",
                    "signer_enabled", "broadcast_allowed", "mainnet_allowed"):
            self.assertIs(getattr(receipt, key), False)

    def test_unsupported_original_release_is_not_a_successor(self):
        other = self.root / "wam-coin-v0.1.11-x86_64-linux-gnu.tar.gz"
        other.write_bytes(self.archive.read_bytes())
        with self.assertRaisesRegex(target.CoreSuccessorIntakeError,
                                    "^CORE_SUCCESSOR_VERSION_DENIED$"):
            target.inspect_signed_successor(**dict(self.args, archive=other))

    def test_signed_digest_mismatch_never_reaches_elf_reader(self):
        self.write_sums(wrong=True)
        self.denied("CORE_SUCCESSOR_STATIC_DENIED")

    def test_bad_signature_status_rejected_without_archive_parsing(self):
        with patch.object(target, "_run_gpg",
                          return_value=(1, "[GNUPG:] BADSIG")):
            with patch.object(target, "inspect_next_linux_release") as inspector:
                with self.assertRaises(target.CoreSuccessorIntakeError):
                    target.inspect_signed_successor(**self.args)
                inspector.assert_not_called()

    def test_tampered_archive_after_checksum(self):
        self.archive.write_bytes(self.archive.read_bytes() + b"X")
        self.denied("CORE_SUCCESSOR_STATIC_DENIED")

    def test_real_elf_execstack_denied_even_if_checksum_signed(self):
        self.make_archive(stack=7)
        self.write_sums()
        self.denied("CORE_SUCCESSOR_STATIC_DENIED")

    def test_inert_example_is_mandatory(self):
        with tarfile.open(self.archive, "w:gz") as tf:
            payload = good_elf()
            member = tarfile.TarInfo(_ROOT + "/bin/wamd")
            member.size = len(payload)
            tf.addfile(member, io.BytesIO(payload))
        self.write_sums()
        self.denied("CORE_SUCCESSOR_STATIC_DENIED")

    def test_ambiguous_signed_inventory_fails(self):
        content = self.sums.read_text("ascii")
        self.sums.write_text(content + content)
        self.denied("CORE_SUCCESSOR_SUMS_DENIED")

    def test_no_arbitrary_expected_digest_or_mock_peer_parameter(self):
        import inspect
        keys = inspect.signature(target.inspect_signed_successor).parameters
        for k in ("expected_sha256", "trusted_digest", "mock", "signer",
                  "launch", "allow_mainnet", "fallback"):
            self.assertNotIn(k, keys)
