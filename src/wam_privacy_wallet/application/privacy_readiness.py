"""Offline research-readiness projection; never enables wallet capabilities.

This package-level adapter consumes only explicitly supplied manifests. It does
NOT import WSP, scanner, signer, PayJoin or network modules and performs no I/O.
A recorded source pin is not proof of source authentication or code safety.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal

_WSP_PIN = "ac55f13423620252bdbf848c7e8a280c3b84721e"
_SILENT_WALLET_PIN = "44e749a5c8fde82f672d0bc9d11e43af4e52c673"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_CANDIDATES = {
    "wsp-api": ("Urriki1502/wam-silent-payments", _WSP_PIN, "src/wam_sp/api.py", "3c5a285c721982540b8aa9242ac8d882c7981a53", "REVIEW_GATED"),
    "wsp-scanner": ("Urriki1502/wam-silent-payments", _WSP_PIN, "src/wam_sp/scanner.py", "6565efc474e7798e7231bf2ef4df771ac1f24a22", "REVIEW_GATED"),
    "wsp-store": ("Urriki1502/wam-silent-payments", _WSP_PIN, "src/wam_sp/store.py", "8d0b6b94afba15519534f057e51b59130bd7cb67", "REVIEW_GATED"),
    "wsp-signer": ("Urriki1502/wam-silent-payments", _WSP_PIN, "src/wam_sp/offline_signer.py", "45100e327abafd9758f6ba0d00efb78e65f0e241", "BLOCKED"),
    "wsp-backup": ("Urriki1502/wam-silent-payments", _WSP_PIN, "src/wam_sp/backup.py", "60a1938b0ea612d9ef7423e7e494e09a7afe0fa1", "REVIEW_GATED"),
    "wsp-rpc": ("Urriki1502/wam-silent-payments", _WSP_PIN, "src/wam_sp/rpc.py", "23624626cd7d04ce6e1915f1a9f5f1bef01b5002", "BLOCKED"),
    "silentwallet-session": ("Urriki1502/wam-silent-wallet", _SILENT_WALLET_PIN, "src/wam_silent_wallet/services/session_service.py", "ecda81a855ca2f981d7026d4d2d11b11baf8832c", "REVIEW_GATED"),
    "silentwallet-node": ("Urriki1502/wam-silent-wallet", _SILENT_WALLET_PIN, "src/wam_silent_wallet/services/node_service.py", "5a55d0b83ba5687cf9e86f7b211e3fa84dda6b56", "BLOCKED"),
}
_GATES = {
    "CORE-REAL-E2E": ("P0", "BLOCKED"),
    "WSP-DEPENDENCY-REVIEW": ("P0", "BLOCKED"),
    "SCANNER-RPC-BRIDGE": ("P0", "BLOCKED"),
    "SCAN-SPEND-SEPARATION": ("P0", "BLOCKED"),
    "WALLET-STATE-RECOVERY": ("P0", "BLOCKED"),
    "SIGNER-APPROVAL": ("P0", "BLOCKED"),
    "WIN32-RELEASE-QUALIFICATION": ("P1", "BLOCKED"),
    "PR-BRANCH-GOVERNANCE": ("P1", "REVIEW_REQUIRED"),
    "DEPENDENCY-RELEASE-SUPPLYCHAIN": ("P1", "BLOCKED"),
    "PRIVACY-POLICY-REVIEW": ("P1", "BLOCKED"),
}
_MANIFEST_FIELDS = {"schema", "state", "node_network", "integration_allowed",
                    "upstream_repositories_not_modified", "candidates"}
_CANDIDATE_FIELDS = {"id", "repository", "commit_sha", "source_path",
                     "blob_sha", "status", "blocker"}
_LEDGER_FIELDS = {"schema", "scope", "release_allowed", "mainnet_allowed",
                  "operational_wallet_enabled", "gates"}
_GATE_FIELDS = {"id", "priority", "status", "requirement", "evidence"}


class PrivacyReadinessError(ValueError):
    """Fixed, non-sensitive failure identifier."""


@dataclass(frozen=True, slots=True)
class PrivacyResearchSnapshot:
    """Display-only; no grants, handles, secrets, callbacks or transactions."""

    research_state: Literal["RESEARCH_ONLY"]
    wsp_source: Literal["PIN_RECORDED_UNATTESTED"]
    wallet_privacy: Literal["MODEL_ONLY"]
    payjoin: Literal["MODEL_ONLY"]
    network_privacy: Literal["MODEL_ONLY"]
    selective_disclosure: Literal["NOT_INTEGRATED"]
    scan: Literal["BLOCKED"]
    sign: Literal["BLOCKED"]
    send: Literal["BLOCKED"]


def _non_authorizing_snapshot() -> PrivacyResearchSnapshot:
    # Construct a fresh value; never share a globally mutable object even
    # though this dataclass rejects ordinary attribute assignment.
    return PrivacyResearchSnapshot(
        "RESEARCH_ONLY", "PIN_RECORDED_UNATTESTED",
        "MODEL_ONLY", "MODEL_ONLY", "MODEL_ONLY", "NOT_INTEGRATED",
        "BLOCKED", "BLOCKED", "BLOCKED",
    )


def _deny() -> None:
    raise PrivacyReadinessError("APP_PRIVACY_EVIDENCE_DENIED")


def research_readiness(manifest: object, ledger: object) -> PrivacyResearchSnapshot:
    """Derive an always-disabled UI snapshot from *injected* review evidence.

    This duplicates only the safety-critical shape/version/pin checks at the
    application presentation seam; the authoritative offline CLI validators
    and their regression floors are unchanged. No source bytes are fetched
    or attested; the output never grants any operational wallet capability.
    """
    if type(manifest) is not dict or set(manifest) != _MANIFEST_FIELDS:
        _deny()
    if (
        manifest["schema"] != "wam-wallet-reuse-gate/v1"
        or manifest["state"] != "RESEARCH_ONLY"
        or manifest["node_network"] != "regtest"
        or manifest["integration_allowed"] is not False
        or manifest["upstream_repositories_not_modified"] is not True
    ):
        _deny()
    rows = manifest["candidates"]
    if type(rows) is not list or len(rows) != len(_CANDIDATES):
        _deny()
    seen = set()
    for row in rows:
        if type(row) is not dict or set(row) != _CANDIDATE_FIELDS:
            _deny()
        name = row["id"]
        if type(name) is not str or name not in _CANDIDATES or name in seen:
            _deny()
        seen.add(name)
        expected_repo, expected_pin, expected_path, expected_blob, expected_status = _CANDIDATES[name]
        if (
            type(row["repository"]) is not str or row["repository"] != expected_repo
            or type(row["commit_sha"]) is not str or row["commit_sha"] != expected_pin
            or type(row["source_path"]) is not str or row["source_path"] != expected_path
            or type(row["blob_sha"]) is not str or _SHA.fullmatch(row["blob_sha"]) is None
            or row["blob_sha"] != expected_blob
            or type(row["status"]) is not str or row["status"] != expected_status
            or type(row["blocker"]) is not str or not 12 <= len(row["blocker"]) <= 320
        ):
            _deny()
    if seen != set(_CANDIDATES):
        _deny()

    if type(ledger) is not dict or set(ledger) != _LEDGER_FIELDS:
        _deny()
    if (
        ledger["schema"] != "wam-wallet-security-gates/v1"
        or ledger["scope"] != "G0_B4_REVIEW_ONLY"
        or ledger["release_allowed"] is not False
        or ledger["mainnet_allowed"] is not False
        or ledger["operational_wallet_enabled"] is not False
    ):
        _deny()
    gates = ledger["gates"]
    if type(gates) is not list or len(gates) != len(_GATES):
        _deny()
    seen_gates = set()
    for gate in gates:
        if type(gate) is not dict or set(gate) != _GATE_FIELDS:
            _deny()
        name = gate["id"]
        if type(name) is not str or name not in _GATES or name in seen_gates:
            _deny()
        seen_gates.add(name)
        expected_priority, expected_status = _GATES[name]
        if (
            type(gate["priority"]) is not str or gate["priority"] != expected_priority
            or type(gate["status"]) is not str or gate["status"] != expected_status
            or type(gate["requirement"]) is not str or not 30 <= len(gate["requirement"]) <= 280
            or type(gate["evidence"]) is not str or not gate["evidence"]
        ):
            _deny()
    if seen_gates != set(_GATES):
        _deny()
    return _non_authorizing_snapshot()
