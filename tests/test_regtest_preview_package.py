"""Pure stdlib packaging inspector checks; no Core, accounts, or GUI required."""
import tempfile
import unittest
from pathlib import Path
from tools.inspect_regtest_package import inspect, PreviewPackageError

class PreviewInspectionTests(unittest.TestCase):
    def test_actual_file_hash_and_non_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            executable = folder / "WAM-Privacy-Wallet-REGTEST"
            executable.write_bytes(b"public artifact bytes")
            result = inspect(folder, executable, "linux-x64", "a" * 40)
            self.assertEqual(result["status"], "EXPERIMENTAL_REGTEST_GUI_PREVIEW_ONLY")
            for field in ("core_binary_authenticated", "core_e2e_passed",
                          "scanner_operational", "signing_allowed", "broadcast_allowed",
                          "mainnet_allowed", "release_signed", "notarized"):
                self.assertIs(result[field], False)
    def test_disallow_bundled_node_and_credential_files(self):
        for name in ("wamd", "wamd.exe", ".cookie", "wallet.dat", "seed.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                folder = Path(tmp)
                executable = folder / "WAM-Privacy-Wallet-REGTEST"
                executable.write_bytes(b"public bytes")
                (folder / name).write_bytes(b"forbidden")
                with self.assertRaisesRegex(PreviewPackageError,
                                            "^PREVIEW_BUNDLED_CORE_OR_SECRET_DENIED$"):
                    inspect(folder, executable, "linux-x64", "a" * 40)
    def test_symlink_cannot_escape_package(self):
        with tempfile.TemporaryDirectory() as parent:
            folder = Path(parent) / "package"
            folder.mkdir()
            executable = folder / "WAM-Privacy-Wallet-REGTEST"
            executable.write_bytes(b"public bytes")
            external = Path(parent) / "external"
            external.write_bytes(b"not bundled")
            (folder / "external-link").symlink_to(external)
            with self.assertRaisesRegex(PreviewPackageError,
                                        "^PREVIEW_SYMLINK_ESCAPE_DENIED$"):
                inspect(folder, executable, "linux-x64", "a" * 40)
if __name__ == "__main__":
    unittest.main()
