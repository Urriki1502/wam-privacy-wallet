"""Inspect unsigned REGTEST desktop preview bytes; do not grant wallet authority."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import stat

PLATFORMS = {"linux-x64", "windows-x64", "macos-x64", "macos-arm64"}
FORBIDDEN = {"wamd", "wamd.exe", "wam-cli", "wam-cli.exe", "wam-tx",
             "wam-tx.exe", "wallet.dat", ".cookie", "seed.txt", "seed.json"}
FORBIDDEN_SUFFIX = {".sqlite", ".sqlite3", ".key", ".pem", ".wallet"}
SOURCE_SHA = re.compile(r"[0-9a-f]{40}\Z")

class PreviewPackageError(ValueError):
    """Fixed-code package refusal; no private file contents or paths."""

def inspect(package_dir: Path, executable: Path, platform: str, commit: str) -> dict:
    if (type(package_dir) is not type(Path()) or type(executable) is not type(Path())
            or type(platform) is not str or platform not in PLATFORMS
            or type(commit) is not str or SOURCE_SHA.fullmatch(commit) is None):
        raise PreviewPackageError("PREVIEW_INPUT_DENIED")
    if not package_dir.is_dir() or package_dir.is_symlink():
        raise PreviewPackageError("PREVIEW_DIR_DENIED")
    root = package_dir.resolve(strict=True)
    if not executable.is_file() or executable.is_symlink():
        raise PreviewPackageError("PREVIEW_EXECUTABLE_DENIED")
    if not executable.resolve(strict=True).is_relative_to(root):
        raise PreviewPackageError("PREVIEW_EXECUTABLE_ESCAPE_DENIED")
    files = size = 0
    for item in package_dir.rglob("*"):
        if (item.name.lower() in FORBIDDEN or item.suffix.lower() in FORBIDDEN_SUFFIX
                or "wam-coin" in (part.lower() for part in item.parts)):
            raise PreviewPackageError("PREVIEW_BUNDLED_CORE_OR_SECRET_DENIED")
        if item.is_symlink():
            # PyInstaller uses internal library symlinks on Unix.
            if not item.resolve(strict=True).is_relative_to(root):
                raise PreviewPackageError("PREVIEW_SYMLINK_ESCAPE_DENIED")
            continue
        if item.is_dir():
            continue
        info = item.stat()
        if not stat.S_ISREG(info.st_mode):
            raise PreviewPackageError("PREVIEW_NONREGULAR_DENIED")
        files += 1
        size += info.st_size
        if files > 20000 or size > 2_000_000_000:
            raise PreviewPackageError("PREVIEW_BOUNDS_DENIED")
    digest = sha256()
    with executable.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "schema": "wam-regtest-desktop-preview/v1",
        "status": "EXPERIMENTAL_REGTEST_GUI_PREVIEW_ONLY",
        "platform": platform, "source_commit": commit,
        "executable_sha256": digest.hexdigest(),
        "total_files": files, "package_bytes": size,
        "core_binary_authenticated": False, "core_e2e_passed": False,
        "scanner_operational": False, "signing_allowed": False,
        "broadcast_allowed": False, "mainnet_allowed": False,
        "production_release_approved": False, "release_signed": False,
        "notarized": False,
    }

def main() -> int:
    cli = argparse.ArgumentParser()
    cli.add_argument("--package-dir", type=Path, required=True)
    cli.add_argument("--executable", type=Path, required=True)
    cli.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    cli.add_argument("--commit", required=True)
    cli.add_argument("--output", type=Path, required=True)
    opts = cli.parse_args()
    try:
        manifest = inspect(opts.package_dir, opts.executable, opts.platform, opts.commit)
        if opts.output.exists() or opts.output.is_symlink():
            raise PreviewPackageError("PREVIEW_MANIFEST_OVERWRITE_DENIED")
        with opts.output.open("x", encoding="utf-8") as dst:
            json.dump(manifest, dst, sort_keys=True, indent=2)
            dst.write("\n")
    except (OSError, ValueError):
        raise SystemExit("PREVIEW_PACKAGE_INSPECTION_DENIED") from None
    print("REGTEST_GUI_PREVIEW_INSPECTION_PASS_NO_CORE_E2E")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
