"""Structural review ledger: blocked conditions cannot be silently promoted.

No network, secrets, wallet, WSP dependency or production authorization.
Passing this test verifies ledger consistency only, never security readiness.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_GATE_ROWS = {
    "CORE-REAL-E2E": "P0",
    "WSP-DEPENDENCY-REVIEW": "P0",
    "SCANNER-RPC-BRIDGE": "P0",
    "SCAN-SPEND-SEPARATION": "P0",
    "WALLET-STATE-RECOVERY": "P0",
    "SIGNER-APPROVAL": "P0",
    "WIN32-RELEASE-QUALIFICATION": "P1",
    "PR-BRANCH-GOVERNANCE": "P1",
    "DEPENDENCY-RELEASE-SUPPLYCHAIN": "P1",
    "PRIVACY-POLICY-REVIEW": "P1",
}
_HARD_BLOCKED = frozenset(k for k in _GATE_ROWS if k != "PR-BRANCH-GOVERNANCE")
_GATE_FIELDS = frozenset(("id", "priority", "status", "requirement", "evidence"))
_ROOT_FIELDS = frozenset(("schema", "scope", "release_allowed", "mainnet_allowed", "operational_wallet_enabled", "gates"))
_LINK = re.compile(r"https://github[.]com/Urriki1502/wam-privacy-wallet/(issues|pull)/[1-9][0-9]*\Z")


class SecurityGateLedgerError(ValueError):
    """Constant public error strings; never echo untrusted input."""


def validate_security_gates(data: object) -> None:
    if type(data) is not dict or set(data) != _ROOT_FIELDS:
        raise SecurityGateLedgerError("G0_GATE_SCHEMA_DENIED")
    if (data["schema"] != "wam-wallet-security-gates/v1"
        or data["scope"] != "G0_B4_REVIEW_ONLY"
        or data["release_allowed"] is not False
        or data["mainnet_allowed"] is not False
        or data["operational_wallet_enabled"] is not False):
        raise SecurityGateLedgerError("G0_GATE_AUTHORITY_DENIED")
    gates = data["gates"]
    if type(gates) is not list or len(gates) != len(_GATE_ROWS):
        raise SecurityGateLedgerError("G0_GATE_INVENTORY_DENIED")
    seen = set()
    for gate in gates:
        if type(gate) is not dict or set(gate) != _GATE_FIELDS:
            raise SecurityGateLedgerError("G0_GATE_FORMAT_DENIED")
        identifier = gate["id"]
        if type(identifier) is not str or identifier not in _GATE_ROWS or identifier in seen:
            raise SecurityGateLedgerError("G0_GATE_ID_DENIED")
        seen.add(identifier)
        if gate["priority"] != _GATE_ROWS[identifier]:
            raise SecurityGateLedgerError("G0_GATE_PRIORITY_DENIED")
        if gate["status"] not in ("BLOCKED", "REVIEW_REQUIRED"):
            raise SecurityGateLedgerError("G0_GATE_STATUS_DENIED")
        if identifier in _HARD_BLOCKED and gate["status"] != "BLOCKED":
            raise SecurityGateLedgerError("G0_GATE_NO_EVIDENCE_DENIED")
        requirement, evidence = gate["requirement"], gate["evidence"]
        if type(requirement) is not str or not 30 <= len(requirement) <= 280:
            raise SecurityGateLedgerError("G0_GATE_REQUIREMENT_DENIED")
        if type(evidence) is not str or not (
            _LINK.fullmatch(evidence)
            or evidence in ("docs/THREAT_MODEL.md", "docs/RELEASE_POLICY.md", "docs/OPEN_SOURCE_CHECKLIST.md")
        ):
            raise SecurityGateLedgerError("G0_GATE_EVIDENCE_DENIED")
    if seen != set(_GATE_ROWS):
        raise SecurityGateLedgerError("G0_GATE_INVENTORY_DENIED")


def main() -> int:
    path = Path(__file__).resolve().parents[1] / "compat" / "g0_security_gate_ledger.json"
    try:
        validate_security_gates(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        print("G0_SECURITY_GATE_LEDGER_REJECTED")
        return 1
    print("G0_SECURITY_GATE_LEDGER_VALID_REVIEW_ONLY_NOT_RELEASE_AUTHORITY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
