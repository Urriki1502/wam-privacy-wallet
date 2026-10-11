"""REAL GnuPG sign/verify gate using EPHEMERAL SYNTHETIC KEY MATERIAL ONLY.

Linux native CI only. No WAM Core execution, real signature, network, wallet,
WAM token, wallet seed or external archive. GnuPG's actual crypto is exercised.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest.mock import patch

from wam_privacy_wallet.node import core_signed_release as release
from wam_privacy_wallet.node.core_signed_release import (
    CoreReleaseSignatureError, verify_wam_signed_distribution,
)

_ARCHIVE = "wam-coin-v0.1.11-x86_64-linux-gnu.tar.gz"
_USER_ID = "WAM Wallet synthetic CI only <no-real-keys@example.invalid>"


def _check_gpg(binary: Path, home: Path, *args: str) -> bytes:
    env = {"GNUPGHOME": str(home), "HOME": str(home), "LC_ALL": "C"}
    if "PATH" in os.environ:
        env["PATH"] = os.environ["PATH"]
    cp = subprocess.run(
        [str(binary), "--homedir", str(home), "--batch", "--no-tty",
         "--no-options", *args],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, cwd=home, env=env,
        timeout=45, check=False,
    )
    if cp.returncode != 0:
        raise AssertionError("CI_REAL_GPG_SETUP_FAILED")
    return cp.stdout


def _export_fingerprint(gpg: Path, home: Path) -> str:
    listing = _check_gpg(gpg, home, "--with-colons", "--fingerprint",
                         "--list-keys", _USER_ID)
    found = []
    last = ""
    for line in listing.decode("ascii", errors="replace").splitlines():
        parts = line.split(":")
        if parts[0] == "pub":
            last = "pub"
        elif parts[0] == "sub":
            last = "sub"
        elif parts[0] == "fpr" and last == "pub" and len(parts) > 9:
            found.append(parts[9])
    if len(found) != 1 or len(found[0]) != 40:
        raise AssertionError("CI_REAL_GPG_FINGERPRINT_UNAVAILABLE")
    return found[0]


def _deny(label: str, expected_code: str, call) -> None:
    try:
        call()
    except CoreReleaseSignatureError as exc:
        if str(exc) != expected_code:
            raise AssertionError("CI_REAL_GPG_WRONG_DENIAL_" + label) from None
    else:
        raise AssertionError("CI_REAL_GPG_UNEXPECTED_ACCEPT_" + label)
    print("CI_REAL_GPG_NEGATIVE_PASS: " + label, flush=True)


def main() -> int:
    resolved = shutil.which("gpg")
    if resolved is None or not Path(resolved).is_absolute():
        raise AssertionError("CI_REAL_GPG_UNAVAILABLE")
    gpg = Path(resolved)
    with tempfile.TemporaryDirectory(prefix="wam-synthetic-crypto-ci-") as root:
        base = Path(root)
        signer = base / "synthetic-private-signing-home"
        signer.mkdir(mode=0o700)
        trusted = base / "verifier-temporary-home"
        trusted.mkdir(mode=0o700)
        _check_gpg(
            gpg, signer, "--yes", "--pinentry-mode", "loopback",
            "--passphrase", "", "--quick-generate-key",
            _USER_ID, "rsa2048", "sign", "0",
        )
        synthetic_fp = _export_fingerprint(gpg, signer)
        public = base / "SYNTHETIC-SIGNING-KEY.asc"
        public.write_bytes(_check_gpg(gpg, signer, "--armor", "--export", synthetic_fp))
        archive = base / _ARCHIVE
        archive.write_bytes(b"NONEXECUTABLE_SYNTHETIC_ARCHIVE_GPG_GATE_" * 128)
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        sha_file = base / "SHA256SUMS"
        sha_file.write_text(checksum + "  " + _ARCHIVE + "\n", encoding="ascii")
        sig_file = base / "SHA256SUMS.asc"
        _check_gpg(gpg, signer, "--yes", "--armor", "--detach-sign",
                   "--output", str(sig_file), str(sha_file))

        def review(*, key=public, sums=sha_file, sig=sig_file, pkg=archive):
            return verify_wam_signed_distribution(
                signing_key=key, sha256sums=sums, detached_signature=sig,
                archive=pkg, archive_name=_ARCHIVE, gpg_executable=gpg,
            )

        # Only testing may swap the pinned fingerprint. Production never
        # accepts key identity via inputs, env or an untrusted manifest.
        with patch.object(release, "WAM_RELEASE_SIGNING_FINGERPRINT", synthetic_fp):
            valid = review()
            if (valid.status != "SIGNED_DISTRIBUTION_ONLY"
                    or valid.core_execution_allowed is not False
                    or valid.mainnet_allowed is not False
                    or valid.real_wallet_allowed is not False
                    or valid.extracted_binary_verified is not False
                    or valid.execution_identity_bound is not False):
                raise AssertionError("CI_REAL_GPG_AUTHORITY_ESCAPE")
            print("CI_REAL_GPG_POSITIVE_PASS: detached signature + archive digest", flush=True)

            sums_tampered = base / "SHA256SUMS-TAMPERED"
            sums_tampered.write_text(
                "0" * 64 + "  " + _ARCHIVE + "\n", encoding="ascii"
            )
            _deny(
                "signed_sums_modified", "CORE_RELEASE_SIGNATURE_DENIED",
                lambda: review(sums=sums_tampered),
            )

            sig_tampered = base / "SHA256SUMS-TAMPERED.asc"
            sig_tampered.write_bytes(sig_file.read_bytes()[:-24] + b"INVALID_TAMPER_BYTES")
            _deny(
                "signature_modified", "CORE_RELEASE_SIGNATURE_DENIED",
                lambda: review(sig=sig_tampered),
            )

            archive_tampered = base / "SYNTHETIC_TAMPERED_ARCHIVE"
            archive_tampered.write_bytes(archive.read_bytes() + b"X")
            _deny(
                "archive_modified", "CORE_RELEASE_ARCHIVE_DENIED",
                lambda: review(pkg=archive_tampered),
            )

        # With no test override, an ephemeral key must NEVER be accepted as
        # the real WAM signing key even with a perfectly valid signature.
        _deny("unapproved_signer", "CORE_RELEASE_SIGNER_DENIED", review)

        # No signing key material leaves TemporaryDirectory at scope exit.
        if not trusted.is_dir():
            raise AssertionError("CI_REAL_GPG_WORKSPACE_MISSING")
    print("CI_REAL_GPG_E2E_PASSED: 1 valid + 4 denied, zero Core execution", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
