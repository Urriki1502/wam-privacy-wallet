"""Read-only WSP-1 source/API check. Does NOT import, execute or enable WSP-1.

The upstream source tree is independently supplied from immutable commit
ac55f13423620252bdbf848c7e8a280c3b84721e. Git blob byte hashes below are
pinned to that commit. No downloader, scanner, wallet, signer, network, keys or
external code execution is provided by this module.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import stat
import sys

PINNED_COMMIT = "ac55f13423620252bdbf848c7e8a280c3b84721e"
# Four reviewed WSP-1 source *blobs*; no third-party code is vendored/imported.
_PINNED = {
    "src/wam_sp/api.py": "3c5a285c721982540b8aa9242ac8d882c7981a53",
    "src/wam_sp/scanner.py": "6565efc474e7798e7231bf2ef4df771ac1f24a22",
    "src/wam_sp/offline_signer.py": "45100e327abafd9758f6ba0d00efb78e65f0e241",
    "src/wam_sp/backup.py": "60a1938b0ea612d9ef7423e7e494e09a7afe0fa1",
}
_REQUIRED_METHODS = {
    "api": ("SilentWallet", frozenset({
        "get_silent_address", "scan", "export_signing_request",
        "backup", "restore", "broadcast", "close",
    })),
    "scanner": ("Scanner", frozenset({"sync", "sync_mempool", "close"})),
}
_EXPECTED_SCAN_CALLS = frozenset({
    "getbestblockhash", "getblockcount", "getblockhash", "getblock",
    "getrawmempool", "getrawtransaction",
})
_MAX_FILE = 256_000


class WspSourceReviewError(ValueError):
    """Stable denial; no caller path, source text or private data is returned."""


def _deny() -> None:
    raise WspSourceReviewError("WSP1_SOURCE_REVIEW_DENIED")


def _git_blob_sha(raw: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    ).hexdigest()


def _inspect_one(raw: bytes, *, blob_sha: str, role: str) -> tuple[ast.Module, set[str]]:
    """Pure static AST validation; tests may supply synthetic bytes/pins.

    A successful synthetic test NEVER represents pinned real WSP-1 qualification.
    """
    if (type(raw) is not bytes or not 1 <= len(raw) <= _MAX_FILE
            or type(blob_sha) is not str or len(blob_sha) != 40
            or any(ch not in "0123456789abcdef" for ch in blob_sha)
            or type(role) is not str or role not in ("api","scanner","signer","backup")
            or _git_blob_sha(raw) != blob_sha):
        _deny()
    try:
        tree = ast.parse(raw.decode("utf-8"), mode="exec")
    except (UnicodeError, SyntaxError, ValueError, MemoryError, RecursionError):
        _deny()
    defined: set[str] = set()
    if role in _REQUIRED_METHODS:
        class_name, methods = _REQUIRED_METHODS[role]
        classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name]
        if len(classes) != 1:
            _deny()
        defined = {
            n.name for n in classes[0].body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if not methods <= defined:
            _deny()
    if role == "signer" and not any(
        isinstance(n, ast.FunctionDef) and n.name == "main" for n in tree.body
    ):
        _deny()
    if role == "backup" and not {"create", "restore"} <= {
        n.name for n in tree.body if isinstance(n, ast.FunctionDef)
    }:
        _deny()
    return tree, defined


def verify_pinned_wsp1_sources(root: Path) -> dict[str, object]:
    """Examine only four known files; report scanner bridge gap, never approve it."""
    if type(root) is not type(Path()) or not root.is_absolute() or root.is_symlink():
        _deny()
    trees: dict[str, ast.Module] = {}
    for path, pinned_sha in _PINNED.items():
        item = root / path
        try:
            meta = item.lstat()
            if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1
                    or not 1 <= meta.st_size <= _MAX_FILE
                    or item.is_symlink()):
                _deny()
            data = item.read_bytes()
            if len(data) != meta.st_size:
                _deny()
            role = path.rsplit("/",1)[-1].replace("offline_signer","signer").replace(".py","")
            tree, _ = _inspect_one(data, blob_sha=pinned_sha, role=role)
        except OSError:
            _deny()
        trees[path] = tree
    scanner = trees["src/wam_sp/scanner.py"]
    calls = {
        n.args[0].value for n in ast.walk(scanner)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "call"
        and n.args and isinstance(n.args[0], ast.Constant)
        and type(n.args[0].value) is str
    }
    attest_count = sum(
        1 for n in ast.walk(scanner)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "attest"
    )
    if calls != _EXPECTED_SCAN_CALLS or attest_count < 1:
        _deny()
    # Wallet RPC is trusted only as a local *read-only* module; never
    # instantiate it or pass it to WSP scanner/signer code.
    from wam_privacy_wallet.node.read_rpc import _READ_METHODS
    missing = sorted(calls - _READ_METHODS)
    if missing != ["getblock", "getrawmempool", "getrawtransaction"]:
        _deny()
    return {
        "status": "WSP1_PINNED_SOURCE_INSPECTED_NO_INTEGRATION",
        "upstream_commit_sha": PINNED_COMMIT,
        "source_files_verified": len(_PINNED),
        "scanner_rpc_calls": sorted(calls),
        "wallet_read_rpc_missing": missing,
        "scanner_attest_contract_unqualified": True,
        "scanner_enabled": False,
        "signer_enabled": False,
        "broadcast_allowed": False,
        "mainnet_allowed": False,
        "core_execution_allowed": False,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(description="Static WSP-1 API source qualification; NEVER import wallet code")
    p.add_argument("--source-root", required=True)
    args = p.parse_args(argv)
    try:
        result = verify_pinned_wsp1_sources(Path(args.source_root))
    except (WspSourceReviewError, OSError, ValueError, TypeError):
        print("WSP1_SOURCE_REVIEW_DENIED", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",",":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
