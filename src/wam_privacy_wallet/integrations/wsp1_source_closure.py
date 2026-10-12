"""Fail-closed whole-Python-package source closure for pinned WSP-1 CI.

The previous four-blob WSP API review is necessary but insufficient: Python
imports from keystore/core/store/watcher and other transitive modules. Verify
EVERY tracked package blob against the exact upstream Git commit before any
native WSP module is imported. No import, Core launch, keys or wallet creation.
This is a CI qualification, NOT an operational production loader.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tomllib

from .wsp1_source_review import PINNED_COMMIT, _git_blob_sha

_REQUIRED_PY = frozenset({
    "src/wam_sp/__init__.py", "src/wam_sp/api.py",
    "src/wam_sp/scanner.py", "src/wam_sp/core.py",
    "src/wam_sp/store.py", "src/wam_sp/keystore.py",
    "src/wam_sp/watcher.py", "src/wam_sp/limits.py",
})
_REQUIRED_DEPS = frozenset({
    "coincurve==21.0.0", "cryptography==50.0.0",
    "pycryptodome==3.23.0",
})
_TREE_HASH = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_MAX_TREE_BYTES = 1_000_000
_MAX_PACKAGE_FILES = 160
_MAX_SINGLE_FILE = 512_000


class WspFullSourceError(ValueError):
    """Stable denial: never expose repository paths or file contents."""


def _deny() -> None:
    raise WspFullSourceError("WSP1_FULL_SOURCE_CLOSURE_DENIED")


def _git(root: Path, *args: str) -> bytes:
    try:
        run = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(root), *args],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, timeout=8, check=False,
        )
        if run.returncode != 0 or len(run.stdout) > _MAX_TREE_BYTES:
            _deny()
        return run.stdout
    except (OSError, subprocess.SubprocessError):
        _deny()


def verify_wsp1_full_source_closure(root: Path) -> dict[str, object]:
    """Verify all Python source bytes of a pinned, clean checkout, not 4 files."""
    if (type(root) is not type(Path()) or not root.is_absolute()
            or root.is_symlink() or not root.is_dir()):
        _deny()
    package = root / "src" / "wam_sp"
    if (not package.is_dir() or package.is_symlink()
            or (root / "src").is_symlink()):
        _deny()
    commit = _git(root, "rev-parse", "--verify", "HEAD").strip()
    if commit.decode("ascii", "replace") != PINNED_COMMIT:
        _deny()
    toplevel = _git(root, "rev-parse", "--show-toplevel").strip()
    try:
        # Git uses slash paths on Windows; compare filesystem identities while
        # preserving exact raw-byte verification of every source blob below.
        same_root = Path(toplevel.decode("utf-8")).resolve(strict=True) == root.resolve(strict=True)
    except (OSError, UnicodeError, ValueError):
        _deny()
    if not same_root:
        _deny()

    tree = _git(root, "ls-tree", "-r", "-z", "HEAD", "--",
                "src/wam_sp", "pyproject.toml")
    entries = tree.split(b"\0")
    if not tree.endswith(b"\0") or entries[-1] != b"":
        _deny()
    expected: dict[str, str] = {}
    if len(entries) - 1 > _MAX_PACKAGE_FILES:
        _deny()
    for item in entries[:-1]:
        try:
            header, raw_path = item.split(b"\t", 1)
            mode, kind, raw_hash = header.split(b" ")
            rel = raw_path.decode("utf-8")
            pp = PurePosixPath(rel)
            digest = raw_hash.decode("ascii")
        except (ValueError, UnicodeDecodeError):
            _deny()
        if (mode not in (b"100644", b"100755")
                or kind != b"blob" or _TREE_HASH.fullmatch(digest) is None
                or rel in expected or pp.is_absolute()
                or ".." in pp.parts or "\\" in rel
                or (rel != "pyproject.toml"
                    and (pp.parts[:2] != ("src", "wam_sp")))):
            _deny()
        expected[rel] = digest
    if not _REQUIRED_PY <= set(expected) or "pyproject.toml" not in expected:
        _deny()

    # Compare all committed source/metadata bytes (not just four API files).
    for rel, digest in expected.items():
        entry = root / rel
        current = root
        for component in PurePosixPath(rel).parts:
            current = current / component
            if current.is_symlink():
                _deny()
        try:
            info = entry.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or not 1 <= info.st_size <= _MAX_SINGLE_FILE):
                _deny()
            raw = entry.read_bytes()
        except OSError:
            _deny()
        if len(raw) != info.st_size or _git_blob_sha(raw) != digest:
            _deny()

    # Untracked Python files can be imported via an editable checkout even
    # when all four pinned API blobs still match; never tolerate them.
    disk_py = {str(p.relative_to(root)).replace(os.sep, "/")
               for p in package.rglob("*.py")}
    committed_py = {p for p in expected if p.endswith(".py")}
    if disk_py != committed_py:
        _deny()
    for directory, subdirs, names in os.walk(package, followlinks=False):
        if any((Path(directory) / child).is_symlink() for child in subdirs):
            _deny()
        if any(name.endswith((".so", ".pyd", ".dll", ".pth", ".zip"))
               for name in names):
            _deny()

    # Pin WSP's declared runtime dependencies as well as imported Python.
    try:
        project = tomllib.loads((root / "pyproject.toml").read_text("utf-8"))
        dependencies = project["project"]["dependencies"]
    except (OSError, ValueError, KeyError, TypeError):
        _deny()
    if type(dependencies) is not list or frozenset(dependencies) != _REQUIRED_DEPS:
        _deny()

    return {
        "status": "WSP1_FULL_SOURCE_CLOSURE_VERIFIED_NO_AUTHORITY",
        "pinned_commit": PINNED_COMMIT,
        "git_blobs_verified": len(expected),
        "python_modules_verified": len(committed_py),
        "scanner_enabled": False,
        "signer_enabled": False,
        "broadcast_allowed": False,
        "mainnet_allowed": False,
        "core_execution_allowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Full WSP-1 source closure, read-only")
    parser.add_argument("--source-root", required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_wsp1_full_source_closure(Path(args.source_root))
    except (WspFullSourceError, ValueError, OSError, TypeError):
        print("WSP1_FULL_SOURCE_CLOSURE_DENIED", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
