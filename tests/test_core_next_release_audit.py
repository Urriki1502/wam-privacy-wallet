"""No-exec next-release candidate smoke/adversarial tests; fake ELF only.

These synthetic fixtures exercise the structural reader, *not* official release
verification. Actual future Core artifacts need DEV GPG verification separately.
"""
from __future__ import annotations

from dataclasses import fields
import hashlib
import io
import os
from pathlib import Path
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node import core_next_release_audit as candidate

_ROOT = "wam-coin-v0.1.12"
_NAME = "wam-coin-v0.1.12-x86_64-linux-gnu.tar.gz"
_EHDR = struct.Struct("<HHIQQQIHHHHHH")
_PHDR = struct.Struct("<IIQQQQQQ")


def _elf(stack_flags=6, *, missing_note=False, load_flags=5, valid=True):
    blob = bytearray(512)
    blob[:16] = b"\x7fELF" + bytes((2, 1, 1)) + bytes(9)
    blob[16:64] = _EHDR.pack(3, 62, 1, 0x401000, 64, 0, 0,
                             64, 56, 2, 0, 0, 0)
    blob[64:120] = _PHDR.pack(1, load_flags, 0, 0x400000, 0, 512, 512, 4096)
    blob[120:176] = _PHDR.pack(0 if missing_note else 0x6474E551,
                               stack_flags, 0, 0, 0, 0, 0, 0)
    if not valid:
        blob[:4] = b"BORK"
    return bytes(blob)


class NextCoreReleaseCandidateTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(prefix="next-core-tar-fixture-")
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        self.archive = self.root / _NAME
        self.default = [
            (_ROOT + "/bin/wamd", _elf(), tarfile.REGTYPE),
            (_ROOT + "/bin/wam-miner", _elf(), tarfile.REGTYPE),
            (_ROOT + "/bin/wam-qt", _elf(), tarfile.REGTYPE),
            (_ROOT + "/bin/wam-cli", _elf(), tarfile.REGTYPE),
            (_ROOT + "/share/examples/wam.conf",
             b"#server=1\n#rpcbind=127.0.0.1\n#regtest=1\n",
             tarfile.REGTYPE),
        ]

    def build(self, records=None):
        with tarfile.open(self.archive, "w:gz") as tar:
            for name, content, kind in (
                self.default if records is None else records
            ):
                member = tarfile.TarInfo(name)
                member.type = kind
                member.mode = 0o755 if "/bin/" in name else 0o644
                if kind == tarfile.REGTYPE:
                    member.size = len(content)
                    tar.addfile(member, io.BytesIO(content))
                else:
                    member.linkname = _ROOT + "/bin/wamd"
                    tar.addfile(member)
        return hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def inspect(self, records=None):
        digest = self.build(records)
        return candidate.inspect_next_linux_release(self.archive, digest)

    def denied(self, code, records=None):
        with self.assertRaisesRegex(
                candidate.CoreCandidateAuditError, "^"+code+"$"):
            self.inspect(records)

    def test_read_all_binaries_and_inert_example_no_auth_claims(self):
        with patch.object(subprocess, "Popen",
                          side_effect=AssertionError("RUN_FORBIDDEN")) as launch:
            result = self.inspect()
            launch.assert_not_called()
        self.assertEqual(result.binary_names,
                         ("wam-cli", "wam-miner", "wam-qt", "wamd"))
        self.assertEqual(len(result.binary_sha256), 4)
        self.assertEqual(len(result.config_sha256), 64)
        self.assertEqual(result.status, "CANDIDATE_RELEASE_STATIC_INSPECTION_ONLY")
        for name in ("signed_provenance_verified", "help_parity_verified",
                     "dynamic_loader_verified", "kernel_process_identity_verified",
                     "core_execution_allowed", "real_regtest_qualified",
                     "signer_enabled", "broadcast_allowed", "mainnet_allowed"):
            self.assertIs(getattr(result, name), False)

    def test_each_broken_binary_is_rejected_independently(self):
        for i in range(4):
            changed = list(self.default)
            name, _, kind = changed[i]
            changed[i] = (name, _elf(stack_flags=7), kind)
            with self.subTest(binary=name):
                self.denied("CORE_CANDIDATE_EXECSTACK_DENIED", changed)

    def test_missing_gnu_stack_note_rejected(self):
        changed = list(self.default)
        changed[1] = (_ROOT+"/bin/wam-miner", _elf(missing_note=True),
                      tarfile.REGTYPE)
        self.denied("CORE_CANDIDATE_STACK_HEADER_DENIED", changed)

    def test_wx_load_segment_rejected(self):
        changed = list(self.default)
        changed[0] = (_ROOT+"/bin/wamd", _elf(load_flags=7), tarfile.REGTYPE)
        self.denied("CORE_CANDIDATE_ELF_WX_DENIED", changed)

    def test_invalid_elf_header_rejected(self):
        changed = list(self.default)
        changed[0] = (_ROOT+"/bin/wamd", _elf(valid=False), tarfile.REGTYPE)
        self.denied("CORE_CANDIDATE_ELF_HEADER_DENIED", changed)

    def test_active_rpc_binding_configuration_is_denied(self):
        for dangerous in (b"rpcbind=0.0.0.0\n", b"server=1\n",
                          b"[main]\n", b"regtest=1\n"):
            changed = list(self.default)
            changed[-1] = (_ROOT+"/share/examples/wam.conf",
                           dangerous,tarfile.REGTYPE)
            with self.subTest(value=dangerous):
                self.denied("CORE_CANDIDATE_ACTIVE_CONFIG_DENIED", changed)

    def test_invalid_text_config_is_denied(self):
        changed = list(self.default)
        changed[-1] = (_ROOT+"/share/examples/wam.conf",
                       b"\xff\x00",tarfile.REGTYPE)
        self.denied("CORE_CANDIDATE_EXAMPLE_DENIED", changed)

    def test_missing_example_is_denied(self):
        self.denied("CORE_CANDIDATE_EXAMPLE_MISSING", self.default[:-1])

    def test_missing_daemon_is_denied(self):
        self.denied("CORE_CANDIDATE_DAEMON_MISSING", self.default[1:])

    def test_symlink_and_hardlink_are_denied_even_if_unrelated(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind):
                self.denied("CORE_CANDIDATE_TYPE_DENIED",
                            self.default+[( _ROOT+"/doc/alias", b"", kind)])

    def test_tar_traversal_rejected_without_extraction(self):
        for name in (_ROOT+"/../outside", _ROOT+"/./bin/evil",
                     _ROOT+"//bin/evil", "/tmp/evil"):
            with self.subTest(path=name):
                self.denied("CORE_CANDIDATE_PATH_DENIED",
                            self.default+[(name,b"x",tarfile.REGTYPE)])

    def test_casefold_archive_duplicates_fail_closed(self):
        self.denied("CORE_CANDIDATE_DUPLICATE_DENIED", self.default + [
            (_ROOT + "/bin/WAMD", _elf(), tarfile.REGTYPE)
        ])

    def test_archive_bytes_must_match_pinned_digest(self):
        self.build()
        with self.assertRaisesRegex(candidate.CoreCandidateAuditError,
                                    "^CORE_CANDIDATE_DIGEST_DENIED$"):
            candidate.inspect_next_linux_release(self.archive,"0"*64)

    def test_symlink_archive_denied(self):
        self.build()
        link = self.root/"symlink"
        link.symlink_to(self.archive)
        with self.assertRaisesRegex(candidate.CoreCandidateAuditError,
                                    "^CORE_CANDIDATE_PATH_DENIED$"):
            candidate.inspect_next_linux_release(
                link,hashlib.sha256(self.archive.read_bytes()).hexdigest()
            )

    def test_nonabsolute_path_and_untrusted_sha_denied(self):
        for path, sha in ((Path("archive.tar.gz"),"0"*64),
                          (self.archive,"BAD"), (self.archive,None)):
            with self.subTest(path=path,sha=sha):
                with self.assertRaisesRegex(candidate.CoreCandidateAuditError,
                                            "^CORE_CANDIDATE_INPUT_DENIED$"):
                    candidate.inspect_next_linux_release(path,sha)

    def test_wrong_release_filename_denied(self):
        self.build()
        old = self.root/"wam-coin-v0.1.11-other-platform.tar.gz"
        old.write_bytes(self.archive.read_bytes())
        with self.assertRaisesRegex(candidate.CoreCandidateAuditError,
                                    "^CORE_CANDIDATE_NAME_DENIED$"):
            candidate.inspect_next_linux_release(
                old, hashlib.sha256(old.read_bytes()).hexdigest()
            )

    def test_uncompressed_size_budget_denied(self):
        with patch.object(candidate, "_MAX_TOTAL", 128):
            self.denied("CORE_CANDIDATE_BOUNDS_DENIED")

    def test_all_dataclass_authority_defaults_false(self):
        names={field.name for field in fields(candidate.CoreCandidateObservation)}
        self.assertIn("core_execution_allowed",names)
        self.assertIn("signed_provenance_verified",names)
        self.assertIn("help_parity_verified",names)
        self.assertFalse(hasattr(candidate,"launch_core"))
        self.assertFalse(hasattr(candidate,"execveat"))


if __name__ == "__main__":
    unittest.main()
