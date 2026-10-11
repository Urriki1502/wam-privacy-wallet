"""Adversarial read-only WAM archive inventory tests, never extract/run node."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import io
import os
from pathlib import Path
import socket
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from wam_privacy_wallet.node import core_archive_inventory as inventory
from wam_privacy_wallet.node.core_archive_inventory import (
    CoreArchiveInventoryError, inspect_wam_core_archive,
)
from wam_privacy_wallet.node.core_signed_release import SignedDistributionEvidence

LINUX = "wam-coin-v0.1.11-x86_64-linux-gnu.tar.gz"
MAC = "wam-coin-v0.1.11-arm64-apple-darwin.tar.gz"
WIN = "wam-coin-v0.1.11-x86_64-w64-mingw32.zip"
ROOT = "wam-coin-v0.1.11"
ELF = b"\x7fELF" + b"synthetic offline node bytes" * 4
PE = b"MZ" + b"synthetic fake PE node" * 5


class CoreArchiveInventoryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="wam-archive-synthetic-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def tar(self, files=None, *, name=LINUX, modes=None):
        files = files if files is not None else {
            f"{ROOT}/bin/wamd": ELF, f"{ROOT}/README.md": b"test only"
        }
        target = self.root / name
        modes = modes or {}
        with tarfile.open(target, "w:gz") as tar:
            root = tarfile.TarInfo(ROOT + "/")
            root.type = tarfile.DIRTYPE
            tar.addfile(root)
            for path, content in files.items() if isinstance(files, dict) else files:
                info = tarfile.TarInfo(path)
                info.type = modes.get(path, tarfile.REGTYPE)
                info.size = len(content) if info.type == tarfile.REGTYPE else 0
                info.linkname = f"{ROOT}/bin/wamd" if info.type in (
                    tarfile.SYMTYPE, tarfile.LNKTYPE
                ) else ""
                tar.addfile(info, io.BytesIO(content) if info.type == tarfile.REGTYPE else None)
        return target

    def zip(self, files=None):
        files = files if files is not None else {
            f"{ROOT}/bin/wamd.exe": PE, f"{ROOT}/README.md": b"test only"
        }
        target = self.root / WIN
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as pkg:
            pkg.writestr(ROOT + "/", "")
            for name, data in files.items() if isinstance(files, dict) else files:
                pkg.writestr(name, data)
        return target

    def review(self, archive, name=None, sha=None):
        name = name or archive.name
        sha = sha or hashlib.sha256(archive.read_bytes()).hexdigest()
        return inspect_wam_core_archive(
            archive=archive, signed_receipt=SignedDistributionEvidence(name, sha),
        )

    def assert_code(self, code, archive):
        with self.assertRaisesRegex(
            CoreArchiveInventoryError, "^" + code + "$"
        ):
            self.review(archive)

    def test_linux_tar_contains_readonly_node_hash_and_counts(self):
        archive = self.tar()
        with patch.object(subprocess, "Popen",
                          side_effect=AssertionError("REAL_CORE_FORBIDDEN")) as proc:
            result = self.review(archive)
            proc.assert_not_called()
        self.assertEqual(result.archive_name, LINUX)
        self.assertEqual(result.node_entry, f"{ROOT}/bin/wamd")
        self.assertEqual(result.node_sha256, hashlib.sha256(ELF).hexdigest())
        self.assertEqual(result.node_byte_count, len(ELF))
        self.assertEqual((result.file_count, result.member_count), (2, 3))
        self.assertEqual(result.status, "UNTRUSTED_ARCHIVE_INVENTORY")
        self.assertFalse(any((
            result.archive_signer_revalidated, result.extracted_binary_verified,
            result.execution_identity_bound, result.core_execution_allowed,
            result.mainnet_allowed, result.real_wallet_allowed,
        )))

    def test_macos_tar_node_path_same_as_linux(self):
        result = self.review(self.tar(name=MAC))
        self.assertEqual(result.archive_name, MAC)
        self.assertEqual(result.node_entry, f"{ROOT}/bin/wamd")
        self.assertEqual(result.node_sha256, hashlib.sha256(ELF).hexdigest())

    def test_windows_zip_reads_expected_exe_bytes(self):
        result = self.review(self.zip())
        self.assertEqual(result.archive_name, WIN)
        self.assertEqual(result.node_entry, f"{ROOT}/bin/wamd.exe")
        self.assertEqual(result.node_sha256, hashlib.sha256(PE).hexdigest())
        self.assertEqual((result.file_count, result.member_count), (2, 3))
        self.assertFalse(result.core_execution_allowed)

    def test_reject_missing_node_even_if_other_binaries_exist(self):
        self.assert_code(
            "CORE_ARCHIVE_NODE_MISSING",
            self.tar({f"{ROOT}/bin/wam-cli": ELF}),
        )
        self.assert_code(
            "CORE_ARCHIVE_NODE_MISSING",
            self.zip({f"{ROOT}/bin/wam-cli.exe": PE}),
        )

    def test_reject_tar_traversal_and_absolute_paths(self):
        for path in (
            f"{ROOT}/../pwned", "/tmp/pwned", f"{ROOT}/./bin/evil",
            f"{ROOT}//bin/evil", f"{ROOT}/bin\\wamd", f"{ROOT}/bin/a:b",
            "OTHER/bin/wamd", f"{ROOT}/bin/\x00evil",
        ):
            with self.subTest(path=repr(path)):
                self.assert_code(
                    "CORE_ARCHIVE_PATH_DENIED",
                    self.tar([(f"{ROOT}/bin/wamd", ELF), (path, b"bad")]),
                )

    def test_reject_zip_slip_casefold_and_windows_drive(self):
        for path in (
            f"{ROOT}/../evil", "C:/evil",
            f"{ROOT}//bin/evil", f"{ROOT}/./evil",
        ):
            with self.subTest(path=path):
                self.assert_code(
                    "CORE_ARCHIVE_PATH_DENIED",
                    self.zip([(f"{ROOT}/bin/wamd.exe", PE), (path, b"bad")]),
                )
        # Python's zipfile silently normalizes backslash to slash when
        # creating a ZIP on Windows. Modify raw archive filename bytes in
        # both local+central records (same length), so the hostile on-disk
        # member actually contains a backslash on every native OS.
        crafted = self.zip([
            (f"{ROOT}/bin/wamd.exe", PE),
            (f"{ROOT}/bin/evil", b"bad"),
        ])
        raw = crafted.read_bytes()
        self.assertEqual(raw.count(b"bin/evil"), 2)
        crafted.write_bytes(raw.replace(b"bin/evil", b"bin\\\\evil"))
        self.assert_code("CORE_ARCHIVE_PATH_DENIED", crafted)

    def test_reject_tar_symlink_and_hardlink(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind):
                name = f"{ROOT}/bin/redirect"
                archive = self.tar(
                    [(f"{ROOT}/bin/wamd", ELF), (name, b"")],
                    modes={name:kind},
                )
                self.assert_code("CORE_ARCHIVE_TYPE_DENIED", archive)

    def test_reject_zip_unix_symlink(self):
        archive = self.root / WIN
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr(f"{ROOT}/bin/wamd.exe", PE)
            entry = zipfile.ZipInfo(f"{ROOT}/bin/link")
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(entry, "wamd.exe")
        self.assert_code("CORE_ARCHIVE_TYPE_DENIED", archive)

    def test_tar_duplicate_names_fail_closed(self):
        archive = self.tar([
            (f"{ROOT}/bin/wamd", ELF),
            (f"{ROOT}/bin/wamd", ELF),
        ])
        self.assert_code("CORE_ARCHIVE_COLLISION_DENIED", archive)

    def test_zip_duplicate_names_fail_closed(self):
        with patch("warnings.warn"):
            archive = self.zip([
                (f"{ROOT}/bin/wamd.exe", PE),
                (f"{ROOT}/bin/wamd.exe", PE),
            ])
        self.assert_code("CORE_ARCHIVE_COLLISION_DENIED", archive)

    def test_cross_platform_case_insensitive_collision_denied(self):
        archive = self.tar([
            (f"{ROOT}/bin/wamd", ELF),
            (f"{ROOT}/bin/WAMD", ELF),
        ])
        self.assert_code("CORE_ARCHIVE_COLLISION_DENIED", archive)

    def test_excessive_members_denied(self):
        files = [(f"{ROOT}/bin/wamd", ELF)]
        files += [(f"{ROOT}/extras/f{i:03d}", b"a") for i in range(70)]
        self.assert_code("CORE_ARCHIVE_MEMBER_LIMIT_DENIED", self.tar(files))

    def test_declared_total_size_budget_denied_before_reading(self):
        target = self.tar()
        with patch.object(inventory, "_MAX_TOTAL_BYTES", 4):
            self.assert_code("CORE_ARCHIVE_SIZE_DENIED", target)

    def test_declared_single_file_budget_denied_before_reading(self):
        target = self.zip()
        with patch.object(inventory, "_MAX_MEMBER_BYTES", 8):
            self.assert_code("CORE_ARCHIVE_SIZE_DENIED", target)

    def test_zip_compression_ratio_denies_bomb(self):
        target = self.zip({
            f"{ROOT}/bin/wamd.exe": PE,
            f"{ROOT}/bin/zeros.dat": b"0" * 150_000,
        })
        self.assert_code("CORE_ARCHIVE_RATIO_DENIED", target)

    def test_bogus_archive_digest_denied_before_container_inspection(self):
        a = self.tar()
        with patch.object(inventory, "_read_tar",
                          side_effect=AssertionError("UNVERIFIED_ARCHIVE_OPENED")):
            with self.assertRaisesRegex(
                CoreArchiveInventoryError, "^CORE_ARCHIVE_DIGEST_DENIED$"
            ):
                inspect_wam_core_archive(
                    archive=a,
                    signed_receipt=SignedDistributionEvidence(LINUX, "0" * 64),
                )

    def test_forged_receipt_flags_and_unknown_archive_denied(self):
        a = self.tar()
        good = SignedDistributionEvidence(
            LINUX, hashlib.sha256(a.read_bytes()).hexdigest()
        )
        mutated = replace(good)
        object.__setattr__(mutated, "core_execution_allowed", True)
        unknown = SignedDistributionEvidence(
            "wam-coin-v0.1.99-x86_64-linux-gnu.tar.gz",
            good.distribution_sha256,
        )
        for evidence in (mutated, unknown, {}, None, True,
                         SignedDistributionEvidence(LINUX, "faked")):
            with self.subTest(kind=type(evidence).__name__), \
                 self.assertRaisesRegex(
                    CoreArchiveInventoryError, "^CORE_ARCHIVE_RECEIPT_DENIED$"
                 ):
                inspect_wam_core_archive(archive=a, signed_receipt=evidence)

    def test_malformed_or_corrupt_tar_denied(self):
        bad = self.root / LINUX
        bad.write_bytes(b"NOT_A_GZIP_FILE")
        self.assert_code("CORE_ARCHIVE_CONTAINER_DENIED", bad)

    def test_malformed_or_corrupt_zip_denied(self):
        bad = self.root / WIN
        bad.write_bytes(b"NOT_A_ZIP_FILE")
        self.assert_code("CORE_ARCHIVE_CONTAINER_DENIED", bad)

    def test_node_empty_is_denied(self):
        self.assert_code(
            "CORE_ARCHIVE_NODE_DENIED",
            self.tar({f"{ROOT}/bin/wamd": b""}),
        )

    def test_no_extraction_file_creation_process_or_sockets(self):
        a = self.zip()
        originals = set(self.root.iterdir())
        with patch.object(subprocess, "Popen",
                          side_effect=AssertionError("PROCESS_FORBIDDEN")), \
             patch.object(socket, "socket",
                          side_effect=AssertionError("NETWORK_FORBIDDEN")), \
             patch.object(zipfile.ZipFile, "extract",
                          side_effect=AssertionError("EXTRACTION_FORBIDDEN")), \
             patch.object(zipfile.ZipFile, "extractall",
                          side_effect=AssertionError("EXTRACTION_FORBIDDEN")):
            outcome = self.review(a)
        self.assertFalse(outcome.extracted_binary_verified)
        self.assertEqual(set(self.root.iterdir()), originals)

    def test_receipt_output_frozen_redacted_and_no_path(self):
        result = self.review(self.tar())
        with self.assertRaises(FrozenInstanceError):
            result.core_execution_allowed = True
        for name in ("core_execution_allowed", "real_wallet_allowed",
                     "extracted_binary_verified", "execution_identity_bound",
                     "status"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                replace(result, **{name: True})
        self.assertNotIn(result.node_sha256, repr(result))
        for name in ("archive_path", "staged_path", "wallet", "seed", "rpc",
                     "private_key", "data_dir", "binary_path"):
            self.assertFalse(hasattr(result, name))

    def test_stream_content_integrity_across_random_chunk_boundaries(self):
        a = self.tar({f"{ROOT}/bin/wamd": b"X" * 15_019})
        with patch.object(inventory, "_CHUNK", 17):
            r = self.review(a)
        self.assertEqual(r.node_sha256, hashlib.sha256(b"X" * 15_019).hexdigest())
        self.assertEqual(r.node_byte_count, 15_019)


if __name__ == "__main__":
    unittest.main()
