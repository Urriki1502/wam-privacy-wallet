"""Adversarial contracts for read-only pinned WSP-1 AST qualification."""
from __future__ import annotations

from contextlib import contextmanager
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import wsp1_pinned_surface as review


_API = '''class SilentWallet:
    def get_silent_address(self): pass
    def scan(self): pass
    def export_signing_request(self): pass
    def backup(self): pass
    @classmethod
    def restore(cls): pass
    def broadcast(self): pass
    def close(self): pass
'''
_SCANNER = '''class Scanner:
    def sync(self, rpc):
        rpc.attest()
        rpc.call("getbestblockhash")
        rpc.call("getblockcount")
        rpc.call("getblockhash")
        rpc.call("getblock")
    def sync_mempool(self, rpc):
        rpc.call("getrawmempool")
        rpc.call("getrawtransaction")
    def close(self): pass
'''
_SIGNER = '''raise RuntimeError("EXTERNAL_MODULE_MUST_NOT_EXECUTE")
def main(): pass
'''
_BACKUP = '''def create(): pass
def restore(): pass
'''
_FILES = {
    "src/wam_sp/api.py": _API,
    "src/wam_sp/scanner.py": _SCANNER,
    "src/wam_sp/offline_signer.py": _SIGNER,
    "src/wam_sp/backup.py": _BACKUP,
}


@contextmanager
def _synthetic_source():
    with tempfile.TemporaryDirectory(prefix="synthetic-wsp-source-") as d:
        root = Path(d)
        pins = {}
        for rel, source in _FILES.items():
            path = root / rel
            path.parent.mkdir(parents=True,exist_ok=True)
            raw = source.encode("utf-8")
            path.write_bytes(raw)
            pins[rel] = review._git_blob_sha(raw)
        # Synthetic pins are only installed in this unit test. Real CI
        # verifies the immutable authentic upstream Git blobs, not fixtures.
        with patch.object(review, "_PINNED", pins):
            yield root


class PinnedWspSourceTests(unittest.TestCase):
    def test_synthetic_source_detects_real_scanner_rpc_gap_without_enabling(self):
        with _synthetic_source() as root:
            report = review.verify_pinned_wsp1_sources(root)
        self.assertEqual(report["status"],"WSP1_PINNED_SOURCE_INSPECTED_NO_INTEGRATION")
        self.assertEqual(report["source_files_verified"],4)
        self.assertEqual(report["wallet_read_rpc_missing"],[
            "getblock","getrawmempool","getrawtransaction",
        ])
        for field in ("scanner_enabled","signer_enabled","broadcast_allowed",
                      "mainnet_allowed","core_execution_allowed"):
            self.assertIs(report[field],False)

    def test_git_blob_byte_mutation_is_rejected_even_when_ast_still_valid(self):
        raw=_API.encode("utf-8")
        expected=review._git_blob_sha(raw)
        review._inspect_one(raw,blob_sha=expected,role="api")
        with self.assertRaisesRegex(review.WspSourceReviewError,
                                    "^WSP1_SOURCE_REVIEW_DENIED$"):
            review._inspect_one(raw+b"\n# harmless comment",blob_sha=expected,role="api")

    def test_missing_required_wallet_or_scanner_methods_are_rejected(self):
        for role,raw in (("api",b"class SilentWallet:\n    def scan(self): pass\n"),
                         ("scanner",b"class Scanner:\n    def sync(self): pass\n")):
            with self.subTest(role=role), self.assertRaisesRegex(
                review.WspSourceReviewError,"^WSP1_SOURCE_REVIEW_DENIED$"
            ):
                review._inspect_one(raw,blob_sha=review._git_blob_sha(raw),role=role)

    def test_ast_review_never_executes_external_signer_code(self):
        # If imported/executed this raises; AST parse must only see main().
        raw=_SIGNER.encode("utf-8")
        tree, _=review._inspect_one(
            raw,blob_sha=review._git_blob_sha(raw),role="signer"
        )
        self.assertIsNotNone(tree)

    def test_missing_or_symlinked_source_is_denied(self):
        with _synthetic_source() as root:
            item=root/"src/wam_sp/api.py"
            item.unlink()
            with self.assertRaisesRegex(review.WspSourceReviewError,
                                        "^WSP1_SOURCE_REVIEW_DENIED$"):
                review.verify_pinned_wsp1_sources(root)
            item.symlink_to(root/"src/wam_sp/scanner.py")
            with self.assertRaisesRegex(review.WspSourceReviewError,
                                        "^WSP1_SOURCE_REVIEW_DENIED$"):
                review.verify_pinned_wsp1_sources(root)

    def test_cli_redacts_error_and_never_prints_untrusted_source(self):
        with patch("sys.stdout",new_callable=io.StringIO) as out, \
             patch("sys.stderr",new_callable=io.StringIO) as err:
            rc=review.main(["--source-root","/nonexistent/secret/wsp-source"])
        self.assertEqual(rc,2)
        self.assertEqual(out.getvalue(),"")
        self.assertEqual(err.getvalue().strip(),"WSP1_SOURCE_REVIEW_DENIED")
        self.assertNotIn("secret",err.getvalue())


if __name__=="__main__":
    unittest.main()
