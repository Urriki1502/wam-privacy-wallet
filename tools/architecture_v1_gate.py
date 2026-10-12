"""Fail-closed V1 diagram-to-repository traceability gate; never operational."""
from __future__ import annotations

import json
from pathlib import Path

_FILE = Path(__file__).resolve().parents[1] / "docs" / "ARCHITECTURE_V1_TRACEABILITY.json"
_DENIAL = "ARCHITECTURE_V1_TRACEABILITY_DENIED"
_WALLET = "Urriki1502/wam-privacy-wallet"
_WSP = "Urriki1502/wam-silent-payments"
_PRIVACY = "Urriki1502/wam-privacy"
_SECURITY = "Urriki1502/wam-security"

# This is an independent review baseline, not a copy of the supplied manifest.
_REQUIRED = {
    "user": ("EXTERNAL_ACTOR", _WALLET, "docs/ARCHITECTURE.md"),
    "ui": ("MERGED_SCAFFOLD", _WALLET, "src/wam_privacy_wallet/gui/main_window.py"),
    "application": ("MERGED_SCAFFOLD", _WALLET, "src/wam_privacy_wallet/application/privacy_readiness.py"),
    "wsp1": ("EXTERNAL_REVIEW_GATED", _WSP, "src/wam_sp/api.py"),
    "scanner": ("EXTERNAL_REVIEW_GATED", _WSP, "src/wam_sp/scanner.py"),
    "signer": ("EXTERNAL_REVIEW_GATED", _WSP, "src/wam_sp/offline_signer.py"),
    "recovery": ("EXTERNAL_REVIEW_GATED", _WSP, "src/wam_sp/backup.py"),
    "payjoin": ("MODEL_ONLY", _PRIVACY, "prototypes/payjoin_safety/validator.py"),
    "disclosure": ("NOT_INTEGRATED", _WALLET, "docs/ARCHITECTURE.md"),
    "network": ("MODEL_ONLY", _PRIVACY, "prototypes/network_privacy/policy.py"),
    "rpc": ("MERGED_READ_ONLY", _WALLET, "src/wam_privacy_wallet/node/read_rpc.py"),
    "core": ("BLOCKED_OFFICIAL_CORE", _WALLET, "tools/verify_official_regtest_readiness.py"),
    "assurance": ("EXTERNAL_REVIEW_GATED", _SECURITY, "README.md"),
    "ci": ("MERGED_CI_ONLY", _WALLET, "tools/ci_contract_gate.py"),
}
_EDGES = frozenset({
    ("user", "ui"), ("ui", "application"),
    ("application", "wsp1"), ("application", "payjoin"),
    ("application", "disclosure"), ("application", "network"),
    ("application", "rpc"), ("wsp1", "scanner"),
    ("wsp1", "signer"), ("wsp1", "recovery"),
    ("scanner", "rpc"), ("signer", "rpc"), ("recovery", "rpc"),
    ("network", "rpc"), ("rpc", "core"), ("assurance", "wsp1"),
    ("assurance", "application"), ("ci", "application"), ("ci", "rpc"),
})
_BLOCKERS = frozenset({("CORE-PROCESS", 36), ("CORE-GNU-STACK", 86),
                      ("CORE-ELF-HOLD", 84), ("CORE-REAL-TWO-NODE", 9),
                      ("WSP-QUALIFICATION", 3)})


class ArchitectureV1Error(ValueError):
    """Fixed denial, never content from caller manifests."""


def _deny() -> None:
    raise ArchitectureV1Error(_DENIAL)


def audit_v1_traceability(data: object) -> dict[str, object]:
    """Validate review-state graph; never issue wallet or Core authority."""
    if type(data) is not dict or set(data) != {
        "schema", "network_scope", "operational_wallet_enabled",
        "mainnet_allowed", "signed_core_launch_allowed",
        "upstream_repositories_unchanged", "diagram_source",
        "nodes", "edges", "blockers",
    }:
        _deny()
    if (type(data["schema"]) is not str
            or data["schema"] != "wam-privacy-wallet-v1-architecture/v1"
            or type(data["network_scope"]) is not str
            or data["network_scope"] != "REGTEST_ONLY"
            or data["operational_wallet_enabled"] is not False
            or data["mainnet_allowed"] is not False
            or data["signed_core_launch_allowed"] is not False
            or data["upstream_repositories_unchanged"] is not True
            or type(data["diagram_source"]) is not str
            or data["diagram_source"] != (
                "User-approved WAM Privacy Wallet V1 architecture diagram (2026-10-12)"
            )):
        _deny()
    nodes = data["nodes"]
    if type(nodes) is not list or len(nodes) != len(_REQUIRED):
        _deny()
    found: set[str] = set()
    for node in nodes:
        if type(node) is not dict or set(node) != {
            "id", "label", "status", "repository", "path",
        }:
            _deny()
        name = node["id"]
        if type(name) is not str or name not in _REQUIRED or name in found:
            _deny()
        found.add(name)
        status, repo, path = _REQUIRED[name]
        if (type(node["label"]) is not str
                or not 3 <= len(node["label"]) <= 96
                or any(type(node[k]) is not str for k in ("status","repository","path"))
                or (node["status"], node["repository"], node["path"]) != (status,repo,path)):
            _deny()
    if found != set(_REQUIRED):
        _deny()
    edges = data["edges"]
    if type(edges) is not list or len(edges) != len(_EDGES):
        _deny()
    seen: set[tuple[str,str]] = set()
    for edge in edges:
        if type(edge) is not dict or set(edge) != {"from", "to"}:
            _deny()
        a,b = edge["from"],edge["to"]
        if type(a) is not str or type(b) is not str or (a,b) not in _EDGES or (a,b) in seen:
            _deny()
        seen.add((a,b))
    if seen != _EDGES:
        _deny()
    blockers = data["blockers"]
    if type(blockers) is not list or len(blockers) != len(_BLOCKERS):
        _deny()
    seen_blockers: set[tuple[str,int]] = set()
    for b in blockers:
        if type(b) is not dict or set(b) not in ({"id","issue"},{"id","pr"}):
            _deny()
        num = b.get("issue", b.get("pr"))
        if type(b["id"]) is not str or type(num) is not int:
            _deny()
        if (b["id"] in {"CORE-ELF-HOLD", "WSP-QUALIFICATION"}) != ("pr" in b):
            _deny()
        item = (b["id"], num)
        if item not in _BLOCKERS or item in seen_blockers:
            _deny()
        seen_blockers.add(item)
    if seen_blockers != _BLOCKERS:
        _deny()

    # Fixed status, never caller-derived approvals or executable grant.
    return {
        "status": "ARCHITECTURE_V1_REVIEW_ONLY",
        "nodes": len(_REQUIRED),
        "edges": len(_EDGES),
        "operational_wallet_enabled": False,
        "core_execution_allowed": False,
        "mainnet_allowed": False,
        "release_qualified": False,
    }


def audit_checked_in_v1() -> dict[str, object]:
    try:
        return audit_v1_traceability(json.loads(_FILE.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, RecursionError):
        _deny()
