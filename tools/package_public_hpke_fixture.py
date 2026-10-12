"""Install OWN compiled public research worker. Does NOT authenticate a release.

Only use after `cargo build --locked` of native/hpke_readonly. No upstream source
is copied. A checksum detects accidental changes but does not solve executable
path races, malicious local builds, signer authorization or external review.
"""
from hashlib import sha256
import json
from pathlib import Path
import shutil
import struct
import os
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    # Explicit target required: native build output only, never arbitrary paths.
    if len(sys.argv) != 2 or sys.argv[1] not in (
        "native", "x86_64-pc-windows-msvc", "i686-pc-windows-msvc",
        "x86_64-unknown-linux-gnu", "aarch64-apple-darwin", "x86_64-apple-darwin"):
        raise SystemExit("HPKE_PACKAGE_TARGET_DENIED")
    target = sys.argv[1]
    name = "wam-wallet-hpke-readonly" + (".exe" if sys.platform == "win32" else "")
    parent = ROOT / "native" / "hpke_readonly" / "target"
    source = parent / "release" / name if target == "native" else parent / target / "release" / name
    destination = ROOT / "src" / "wam_privacy_wallet" / "integrations" / "_native"
    if destination.is_symlink() or source.is_symlink(): raise SystemExit("HPKE_PACKAGE_PATH_DENIED")
    destination.mkdir(exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination, delete=False) as stream:
        staged = Path(stream.name)
    try:
        shutil.copyfile(source, staged)
        staged.chmod(0o700)
        os.replace(staged, destination / name)
    finally:
        staged.unlink(missing_ok=True)
    manifest = {
        "source_commit": "db3d2dcaa540f1129d540101813b761167d33174",
        "worker_sha256": sha256(source.read_bytes()).hexdigest(),
        "pointer_bits": struct.calcsize("P") * 8,
        "platform": sys.platform, "release_allowed": False,
    }
    with tempfile.NamedTemporaryFile(dir=destination, delete=False) as stream:
        staged = Path(stream.name)
        stream.write(json.dumps(manifest, sort_keys=True).encode("utf-8"))
    try:
        os.replace(staged, destination / "hpke-public-fixture-build.json")
    finally:
        staged.unlink(missing_ok=True)
    print("PUBLIC_HPKE_WORKER_INSTALLED; UNAUTHENTICATED_LOCAL_BUILD; external review/sign/send blocked")


if __name__ == "__main__": main()
