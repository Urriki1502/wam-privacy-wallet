"""Actual pinned WSP scan-only AES-GCM through native macOS envelope custody.

Public disposable fixture accounts only. No Core, SQLite, scanner, signer,
real secrets, trusted recovery or operational application qualification.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import stat
import struct
import sys
from tempfile import TemporaryDirectory

from tools.ci_wsp1_scanner_process_lock import _qualify
from tools.ci_wsp1_scanner_native_only import _no_signer
from wam_privacy_wallet.application.macos_encrypted_scan_backup import (
    MacosEncryptedScanBackupError,
    load_macos_encrypted_scan_backup,
    provision_macos_encrypted_scan_backup,
)

CASES = (
    "ACTUAL_EXPORT_PRIVATE_MACOS_STORAGE",
    "ACTUAL_SCAN_IMPORT_IDENTITY",
    "WRONG_PASSWORD_AUTHENTICATION_DENIED",
    "TAMPERED_CIPHERTEXT_AUTHENTICATION_DENIED",
    "CREATE_ONCE_PRESERVES_AUTHENTICATED_BYTES",
    "ACTUAL_INTERPROCESS_CREATE_ONCE",
    "ACTUAL_FLUSHED_OWNER_TERMINATION_RESTART",
)


def _platform():
    if not __debug__:
        raise RuntimeError("MACOS_SCAN_CRYPTO_OPTIMIZED_TESTS_DENIED")
    if sys.platform != "darwin" or struct.calcsize("P") != 8:
        raise RuntimeError("MACOS_SCAN_CRYPTO_PLATFORM_UNQUALIFIED")


def run(root: Path) -> tuple[str, ...]:
    _platform()
    _qualify(root)
    previous_profile = sys.getprofile()
    sys.setprofile(_no_signer)
    try:
        from wam_sp.core import pub
        from wam_sp.keystore import ScanAccount, export_scan, import_scan
        account = ScanAccount(0, 1, pub(2), birthday=1)
        password = b"PUBLIC_DISPOSABLE_REGTEST_TEST_PASSWORD"
        envelope = export_scan((account,), password)
        passed = []
        with TemporaryDirectory(prefix="public-macos-scan-crypto-", dir="/private/tmp") as name:
            directory = Path(name)
            provision_macos_encrypted_scan_backup(directory, envelope)
            loaded = load_macos_encrypted_scan_backup(directory)
            info = (directory / "scan-only.wsp.enc").stat()
            assert loaded == envelope and info.st_nlink == 1
            assert stat.S_IMODE(info.st_mode) == 0o600
            passed.append(CASES[0])
            assert import_scan(loaded, password) == (account,)
            passed.append(CASES[1])
            try:
                import_scan(loaded, b"PUBLIC_WRONG_TEST_PASSWORD")
            except ValueError as error:
                assert str(error) == "SCAN_BACKUP_RESTORE"
            else:
                raise RuntimeError("MACOS_SCAN_CRYPTO_WRONG_PASSWORD_ACCEPTED")
            passed.append(CASES[2])
            tampered_directory = directory / "tampered"
            tampered_directory.mkdir(mode=0o700)
            tampered = loaded[:-1] + bytes((loaded[-1] ^ 1,))
            provision_macos_encrypted_scan_backup(tampered_directory, tampered)
            opaque = load_macos_encrypted_scan_backup(tampered_directory)
            assert opaque == tampered
            try:
                import_scan(opaque, password)
            except ValueError as error:
                assert str(error) == "SCAN_BACKUP_RESTORE"
            else:
                raise RuntimeError("MACOS_SCAN_CRYPTO_TAMPER_ACCEPTED")
            passed.append(CASES[3])
            alternate = export_scan((account,), password)
            try:
                provision_macos_encrypted_scan_backup(directory, alternate)
            except MacosEncryptedScanBackupError as error:
                assert str(error) == "MACOS_SCAN_BACKUP_STORE_DENIED"
            else:
                raise RuntimeError("MACOS_SCAN_CRYPTO_OVERWRITE_ACCEPTED")
            unchanged = load_macos_encrypted_scan_backup(directory)
            assert unchanged == loaded and import_scan(unchanged, password) == (account,)
            assert sorted(p.name for p in directory.iterdir()) == ["scan-only.wsp.enc", "tampered"]
            passed.append(CASES[4])
            from tools.ci_macos_scan_backup_process import exercise_process_recovery
            def authenticate(ciphertext):
                assert import_scan(ciphertext, password) == (account,)
            passed.extend(exercise_process_recovery(root, directory, authenticate))
        if tuple(passed) != CASES:
            raise RuntimeError("MACOS_SCAN_CRYPTO_CASE_COUNT_DENIED")
        return tuple(passed)
    finally:
        sys.setprofile(previous_profile)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True)
    args = parser.parse_args(argv)
    try:
        passed = run(Path(args.source_root))
        for name in passed:
            print("ACTUAL_PINNED_MACOS_SCAN_BACKUP_" + name + "_PASS")
        print("ACTUAL_PINNED_MACOS_SCAN_BACKUP_OK 7/7; public fixtures; NO Core/retained custody/rollback/signing authority")
    except Exception:
        print("MACOS_SCAN_CRYPTO_PROOF_DENIED", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
