"""Synthetic adversarial package-closure tests. Native WSP CI checks actual Git."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import wsp1_full_source_closure as gate
from tools.wsp1_pinned_surface import _git_blob_sha

PYTHON_FILES = sorted(gate._REQUIRED_PY)
DEPENDS = (
    b'[project]\n'
    b'dependencies = ["coincurve==21.0.0", '
    b'"cryptography==50.0.0", "pycryptodome==3.23.0"]\n'
)


class WspFullSourceClosureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="wsp-full-tree-synthetic-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.files = {p: b"# pinned synthetic Python module\n" for p in PYTHON_FILES}
        self.files["pyproject.toml"] = DEPENDS
        for rel, value in self.files.items():
            file = self.root / rel
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(value)

        def mock_git(_root, *args):
            if args == ("rev-parse", "--verify", "HEAD"):
                return gate.PINNED_COMMIT.encode() + b"\n"
            if args == ("rev-parse", "--show-toplevel"):
                return str(self.root).encode() + b"\n"
            if args[:3] == ("ls-tree", "-r", "-z"):
                records = [
                    b"100644 blob " + _git_blob_sha(blob).encode()
                    + b"\t" + name.encode()
                    for name, blob in sorted(self.files.items())
                ]
                return b"\0".join(records) + b"\0"
            self.fail("unexpected simulated Git invocation")
        self.mock_git = patch.object(gate, "_git", side_effect=mock_git)
        self.mock_git.start()
        self.addCleanup(self.mock_git.stop)

    def test_pinned_whole_package_passes_with_no_operational_authority(self):
        proof = gate.verify_wsp1_full_source_closure(self.root)
        self.assertEqual(proof["pinned_commit"], gate.PINNED_COMMIT)
        self.assertEqual(proof["python_modules_verified"], len(PYTHON_FILES))
        self.assertEqual(proof["git_blobs_verified"], len(self.files))
        for flag in ("scanner_enabled", "signer_enabled",
                     "broadcast_allowed", "mainnet_allowed",
                     "core_execution_allowed"):
            self.assertIs(proof[flag], False)

    def test_one_untracked_importable_module_denied_even_with_api_pins(self):
        (self.root / "src/wam_sp/untracked_payload.py").write_text("evil=1")
        with self.assertRaisesRegex(
            gate.WspFullSourceError, "^WSP1_FULL_SOURCE_CLOSURE_DENIED$",
        ):
            gate.verify_wsp1_full_source_closure(self.root)

    def test_non_api_transitive_module_tampering_denied(self):
        # Old four-blob review would not detect this keystore mutation.
        (self.root / "src/wam_sp/keystore.py").write_text("modified = True")
        with self.assertRaises(gate.WspFullSourceError):
            gate.verify_wsp1_full_source_closure(self.root)

    def test_missing_declared_source_denied(self):
        (self.root / "src/wam_sp/watcher.py").unlink()
        with self.assertRaises(gate.WspFullSourceError):
            gate.verify_wsp1_full_source_closure(self.root)

    def test_symlink_to_transitive_module_denied(self):
        original = self.root / "src/wam_sp/core.py"
        other = self.root / "outside.py"
        other.write_bytes(original.read_bytes())
        original.unlink()
        try:
            original.symlink_to(other)
        except (OSError, NotImplementedError):
            self.skipTest("native symlink unavailable on this platform")
        with self.assertRaises(gate.WspFullSourceError):
            gate.verify_wsp1_full_source_closure(self.root)

    def test_injected_native_shared_library_denied(self):
        (self.root / "src/wam_sp/native_extension.so").write_bytes(b"bad")
        with self.assertRaises(gate.WspFullSourceError):
            gate.verify_wsp1_full_source_closure(self.root)

    def test_runtime_dependency_pin_is_verified_before_import(self):
        # Reflect a supply-chain dependency alteration not in 4 source files.
        path = self.root / "pyproject.toml"
        path.write_text(path.read_text().replace("coincurve==21.0.0",
                                                "coincurve>=1"))
        with self.assertRaises(gate.WspFullSourceError):
            gate.verify_wsp1_full_source_closure(self.root)

    def test_extra_git_tree_file_must_exist_and_match_hash(self):
        self.files["src/wam_sp/hidden.py"] = b"print('unsafe')\n"
        with self.assertRaises(gate.WspFullSourceError):
            gate.verify_wsp1_full_source_closure(self.root)

    def test_relative_and_untrusted_root_types_denied_without_git(self):
        for root in ("relative", Path("relative"), None, object()):
            with self.subTest(root=str(root)[:20]), self.assertRaises(
                gate.WspFullSourceError,
            ):
                gate.verify_wsp1_full_source_closure(root)

    def test_unpinned_commit_denied_even_if_package_bytes_match(self):
        with patch.object(gate, "_git", return_value=b"0" * 40 + b"\n"):
            with self.assertRaises(gate.WspFullSourceError):
                gate.verify_wsp1_full_source_closure(self.root)


if __name__ == "__main__":
    unittest.main()
