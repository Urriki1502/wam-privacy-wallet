"""No-authority versioned encrypted snapshot tests (Linux + cross-platform)."""
from __future__ import annotations

from functools import wraps
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch
from wam_privacy_wallet.application import versioned_checkpoint_journal as j

_LINUX = sys.platform == "linux"
_BYTES = b"WAMSP02\x00" + b"V"*56
_A = "a"*64
_B = "b"*64
_Z = "0"*64


def linux_or_deny(fn):
    @wraps(fn)
    def check(self):
        if not _LINUX:
            with self.assertRaisesRegex(j.VersionedCheckpointError,
                                        "^SNAPSHOT_PLATFORM_DENIED$"):
                self.write()
            return
        return fn(self)
    return check


class VersionedCheckpointJournalTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory(prefix="wsp-versioned-gen-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def write(self, **kw):
        opts = dict(scope_digest=_A, tip_height=2, tip_hash=_B,
                    predecessor_digest=_Z)
        opts.update(kw)
        return j.write_unanchored_regtest_generation(
            self.root, 1, _BYTES, **opts
        )

    def read(self, generation=1, **kw):
        return j.read_unanchored_regtest_generation(
            self.root, generation, **kw
        )

    def test_production_read_denied_without_external_anchor(self):
        with self.assertRaisesRegex(j.VersionedCheckpointError,
                                    "^SNAPSHOT_TRUSTED_ANCHOR_REQUIRED$"):
            self.read()
        self.assertFalse((self.root / "versions").exists())

    def test_unsupported_platform_refused_even_with_real_directory(self):
        with patch.object(j.sys, "platform", "darwin"):
            with self.assertRaisesRegex(j.VersionedCheckpointError,
                                        "^SNAPSHOT_PLATFORM_DENIED$"):
                self.write()

    def test_bad_generation_or_bool_denied_before_io(self):
        for n in (True, 0, -1, 2**63, 1.0):
            with self.subTest(n=n), self.assertRaises(j.VersionedCheckpointError):
                j.write_unanchored_regtest_generation(
                    self.root, n, _BYTES, scope_digest=_A,
                    tip_height=2, tip_hash=_B, predecessor_digest=_Z)
        self.assertFalse((self.root / "versions").exists())

    def test_invalid_scopes_and_ciphertext_denied_before_io(self):
        for kw in ({"scope_digest":"wrong"}, {"tip_hash":"wrong"},
                   {"tip_height":True}, {"tip_height":-1},
                   {"predecessor_digest":_A}):
            with self.subTest(kw=kw), self.assertRaises(j.VersionedCheckpointError):
                self.write(**kw)
        with self.assertRaises(j.VersionedCheckpointError):
            j.write_unanchored_regtest_generation(
                self.root,1,b"plaintext",scope_digest=_A,tip_height=2,
                tip_hash=_B,predecessor_digest=_Z)
        self.assertFalse((self.root / "versions").exists())

    def test_no_crypto_signer_or_auto_latest_selector(self):
        for name in ("AESGCM", "Keyring", "sendrawtransaction",
                     "select_latest", "sign"):
            self.assertFalse(hasattr(j,name))

    @linux_or_deny
    def test_stored_version_has_valid_manifest_and_ciphertext(self):
        digest = self.write()
        manifest, payload = self.read(allow_unanchored_synthetic=True)
        self.assertEqual(payload,_BYTES)
        self.assertEqual(manifest["network"],"regtest")
        self.assertEqual(manifest["generation"],1)
        self.assertEqual(len(digest),64)
        p=self.root/"versions"/"0000000000000001"
        self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o700)
        self.assertEqual({f.name for f in p.iterdir()},
                         {"checkpoint.wsp.enc","manifest.json","ready.sha256"})

    @linux_or_deny
    def test_no_overwrite_generation_or_file(self):
        self.write()
        with self.assertRaisesRegex(j.VersionedCheckpointError,
                                    "^SNAPSHOT_WRITE_DENIED$"):
            self.write()
        _,payload=self.read(allow_unanchored_synthetic=True)
        self.assertEqual(payload,_BYTES)

    @linux_or_deny
    def test_tampered_ciphertext_rejected_even_if_ready_unchanged(self):
        self.write()
        (self.root/"versions"/"0000000000000001"/"checkpoint.wsp.enc").write_bytes(
            b"WAMSP02\x00"+b"Q"*56)
        with self.assertRaisesRegex(j.VersionedCheckpointError,
                                    "^SNAPSHOT_READ_DENIED$"):
            self.read(allow_unanchored_synthetic=True)

    @linux_or_deny
    def test_tampered_manifest_rejected(self):
        self.write()
        path=self.root/"versions"/"0000000000000001"/"manifest.json"
        path.write_bytes(path.read_bytes().replace(b"regtest",b"mainnet"))
        with self.assertRaises(j.VersionedCheckpointError):
            self.read(allow_unanchored_synthetic=True)

    @linux_or_deny
    def test_symlinked_versions_dir_rejected(self):
        other=self.root/"redirect"
        other.mkdir(mode=0o700)
        (self.root/"versions").symlink_to(other, target_is_directory=True)
        with self.assertRaises(j.VersionedCheckpointError):
            self.write()

    @linux_or_deny
    def test_file_symlink_and_hardlink_rejected(self):
        self.write()
        gen=self.root/"versions"/"0000000000000001"
        marker=gen/"ready.sha256"
        outside=gen/"elsewhere"
        marker.rename(outside)
        marker.symlink_to(outside)
        with self.assertRaises(j.VersionedCheckpointError):
            self.read(allow_unanchored_synthetic=True)
        marker.unlink()
        os.link(outside,marker)
        with self.assertRaises(j.VersionedCheckpointError):
            self.read(allow_unanchored_synthetic=True)

    @linux_or_deny
    def test_premature_partial_version_not_readable(self):
        self.write()
        (self.root/"versions"/"0000000000000001"/"ready.sha256").unlink()
        with self.assertRaisesRegex(j.VersionedCheckpointError,
                                    "^SNAPSHOT_READ_DENIED$"):
            self.read(allow_unanchored_synthetic=True)

    @linux_or_deny
    def test_concurrent_same_generation_one_writer_only(self):
        barrier=threading.Barrier(2)
        out=[]
        def work():
            barrier.wait()
            try: self.write();out.append("written")
            except j.VersionedCheckpointError: out.append("denied")
        a=threading.Thread(target=work)
        b=threading.Thread(target=work)
        a.start();b.start();a.join(5);b.join(5)
        self.assertEqual(sorted(out),["denied","written"])

    @linux_or_deny
    def test_second_generation_uses_predecessor_hash(self):
        digest=self.write()
        d2=j.write_unanchored_regtest_generation(
            self.root,2,_BYTES,scope_digest=_A,tip_height=3,
            tip_hash=_B,predecessor_digest=digest)
        obj,_=self.read(2,allow_unanchored_synthetic=True)
        self.assertEqual(obj["predecessor"],digest)
        self.assertNotEqual(digest,d2)

    @linux_or_deny
    def test_untrusted_hash_chain_does_not_enable_automatic_restore(self):
        digest=self.write()
        j.write_unanchored_regtest_generation(
            self.root,2,_BYTES,scope_digest=_A,tip_height=3,
            tip_hash=_B,predecessor_digest=digest)
        for n in (1,2):
            with self.assertRaisesRegex(j.VersionedCheckpointError,
                                        "^SNAPSHOT_TRUSTED_ANCHOR_REQUIRED$"):
                self.read(n)
