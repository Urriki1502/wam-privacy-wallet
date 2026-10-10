"""Offline-only source provenance gate; never imports or executes upstream code.

The manifest is a review inventory, not an authorization to use dependencies.
Do not use this module to accept binary provenance or attest a real WAM node.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_SHA = re.compile(r"[0-9a-f]{40}\\Z")
_REPOS = frozenset(("Urriki1502/wam-silent-payments", "Urriki1502/wam-silent-wallet"))
_IDS = frozenset((
    "wsp-api", "wsp-scanner", "wsp-store", "wsp-signer",
    "wsp-backup", "wsp-rpc", "silentwallet-session", "silentwallet-node",
))
_FIELDS = frozenset(("id", "repository", "commit_sha", "source_path", "blob_sha", "status", "blocker"))


class ReuseManifestError(ValueError):
    """Public constant code only; never echo untrusted manifest data."""


def validate_manifest(data: object) -> None:
    """Fail closed on unpinned or spuriously approved third-party imports."""
    if type(data) is not dict or set(data) != {
        "schema", "state", "node_network", "integration_allowed",
        "upstream_repositories_not_modified", "candidates"
    }:
        raise ReuseManifestError("REUSE_MANIFEST_FORMAT")
    if (
        data["schema"] != "wam-wallet-reuse-gate/v1"
        or data["state"] != "RESEARCH_ONLY"
        or data["node_network"] != "regtest"
        or data["integration_allowed"] is not False
        or data["upstream_repositories_not_modified"] is not True
    ):
        raise ReuseManifestError("REUSE_MANIFEST_AUTHORITY_DENIED")
    candidates = data["candidates"]
    if type(candidates) is not list or len(candidates) != len(_IDS):
        raise ReuseManifestError("REUSE_MANIFEST_CANDIDATES")
    seen = set()
    for row in candidates:
        if type(row) is not dict or set(row) != _FIELDS:
            raise ReuseManifestError("REUSE_MANIFEST_ROW")
        if type(row["id"]) is not str or row["id"] not in _IDS or row["id"] in seen:
            raise ReuseManifestError("REUSE_MANIFEST_ID")
        seen.add(row["id"])
        if (
            type(row["repository"]) is not str or row["repository"] not in _REPOS
            or type(row["source_path"]) is not str
            or not row["source_path"].startswith("src/")
            or ".." in Path(row["source_path"]).parts
            or "\\\\" in row["source_path"]
            or type(row["commit_sha"]) is not str or not _SHA.fullmatch(row["commit_sha"])
            or type(row["blob_sha"]) is not str or not _SHA.fullmatch(row["blob_sha"])
        ):
            raise ReuseManifestError("REUSE_MANIFEST_UNPINNED")
        if row["status"] not in ("BLOCKED", "REVIEW_GATED"):
            raise ReuseManifestError("REUSE_MANIFEST_STATUS_DENIED")
        if type(row["blocker"]) is not str or not 12 <= len(row["blocker"]) <= 320:
            raise ReuseManifestError("REUSE_MANIFEST_BLOCKER")
    if seen != _IDS:
        raise ReuseManifestError("REUSE_MANIFEST_MISSING")


def main() -> int:
    path = Path(__file__).resolve().parents[1] / "compat" / "reuse_candidates.json"
    try:
        validate_manifest(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, RecursionError):
        print("REUSE_MANIFEST_REJECTED")
        return 1
    print("REUSE_MANIFEST_SHAPE_PASS_REVIEW_REQUIRED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
