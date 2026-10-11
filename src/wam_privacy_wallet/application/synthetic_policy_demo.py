"""Explicit, fixed-fixture offline execution of pinned pure privacy research models.

This module is NOT imported by the GUI or wallet startup. A caller may only
request a static mock demonstration, never supply real PSBTs, endpoints, keys,
RPC credentials, node handles or a signer. The resulting model PASS is NEVER
transaction authorization or proof that WAM's real network was checked.
"""
from __future__ import annotations

from hashlib import sha1
from pathlib import Path

from .policy_evidence import (
    PolicyEvidenceError, SyntheticPolicyReport, inspect_synthetic_policy_evidence,
)

# Require exact byte-identical copies of the reviewed, MIT-licensed upstream
# wam-privacy commit db3d2dcaa540f1129d540101813b761167d33174.
# Git blob IDs prove local content match, NOT publisher authenticity.
_SOURCE_ROOT = Path(__file__).resolve().parents[1]
_PINNED_FILES = {
    "research_models/network_privacy/model.py": "efba5aa0f4cd7d57615dfde47206e7e0dde8d865",
    "research_models/network_privacy/policy.py": "3d24c9a9a010220503e6c81251da7c42309a63a0",
    "research_models/payjoin_safety/model.py": "8e3e8be096a66fc960f75a56f1ac34daa9306017",
    "research_models/payjoin_safety/validator.py": "598596a8bde118204b3baf69bb53a884c6dad21a",
}


class SyntheticDemoError(ValueError):
    """Fixed failure code; never leak raw errors or model input."""


def _verify_source_bytes() -> None:
    """Verify vendor source bytes before importing any research package."""
    try:
        for path, expected in _PINNED_FILES.items():
            content = (_SOURCE_ROOT / path).read_bytes()
            digest = sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()
            if digest != expected:
                raise SyntheticDemoError("APP_SYNTHETIC_MODEL_PIN_DENIED")
    except (OSError, UnicodeError, ValueError):
        raise SyntheticDemoError("APP_SYNTHETIC_MODEL_PIN_DENIED") from None


def run_fixed_synthetic_privacy_demo() -> SyntheticPolicyReport:
    """Run two actual pure-model research validators with fixed fake values.

    No arguments are accepted by design. The code does NOT use DNS, sockets,
    real WAM Core, a WSP scanner, a signer, actual wallet state or private keys.
    All amounts, fake txids, endpoints and domains are hard-coded placeholders.
    """
    _verify_source_bytes()
    try:
        # Delayed imports are intentional: no demo code runs at app startup.
        from ..research_models.network_privacy.model import Endpoint, NetworkPlan, NetworkPolicy
        from ..research_models.network_privacy.policy import (
            validate_network_plan, redacted_network_event,
        )
        from ..research_models.payjoin_safety.model import (
            PayjoinContext, Transaction, TxInput, TxOutput,
        )
        from ..research_models.payjoin_safety.validator import (
            validate_proposal, redacted_payjoin_event,
        )

        plan = NetworkPlan((
            Endpoint("chain_scan", "127.0.0.1", 1, "local",
                     authenticated_transport=True),
            Endpoint("tx_broadcast", "example.invalid", 1, "tor",
                     encrypted_transport=True),
        ))
        network = redacted_network_event(
            validate_network_plan(plan, NetworkPolicy())
        )

        sender = TxInput(f"{1:064x}", 0, 100_000, "sender")
        receiver = TxInput(f"{9:064x}", 0, 20_000, "receiver", finalized=True)
        original = Transaction(
            2, 0, (sender,),
            (TxOutput("synthetic-receiver", 50_000, "receiver"),
             TxOutput("synthetic-change", 49_000, "sender")),
        )
        proposal = Transaction(
            2, 0, (sender, receiver),
            (TxOutput("synthetic-receiver", 69_000, "receiver"),
             TxOutput("synthetic-change", 49_000, "sender")),
        )
        payjoin = redacted_payjoin_event(
            validate_proposal(original, proposal, PayjoinContext(payment_output_index=0))
        )
        return inspect_synthetic_policy_evidence(network, payjoin)
    except Exception:
        # Upstream policy exceptions and Python errors are all redacted.
        raise SyntheticDemoError("APP_SYNTHETIC_MODEL_EXECUTION_DENIED") from None
