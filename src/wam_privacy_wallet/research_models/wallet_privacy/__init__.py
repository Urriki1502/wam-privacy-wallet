"""Reference privacy-aware wallet policy for WAM.

This package is a deterministic research prototype. It does not sign, broadcast,
scan, or modify WAM consensus state.
"""

from .model import Coin, Intent, Policy, Selection
from .policy import PolicyError, select_coins, redacted_event

__all__ = [
    "Coin",
    "Intent",
    "Policy",
    "Selection",
    "PolicyError",
    "select_coins",
    "redacted_event",
]
