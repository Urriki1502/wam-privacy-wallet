"""GUI-owned application lifecycle; no node, account or spend authority.

Mode selection and local readiness inspection are implemented application
operations. They are not genuine Core acceptance or a wallet connection.
Work tickets prevent cancelled/previous-session completions from reaching UI.
This controller has no plug-in backend, mock fallback, credential or key input.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from wam_privacy_wallet.node.two_node_readiness import TwoNodeReadiness

BLOCKERS = (9, 82, 86, 153, 148, 151)


class RegtestLifecycleError(ValueError):
    """Redacted application refusal, never a backend exception."""


@dataclass(frozen=True, slots=True)
class ReadinessInspection:
    blockers: tuple[int, ...] = BLOCKERS
    status: str = "BLOCKED_EXTERNAL_APPROVAL"
    core_authenticated: bool = False
    wallet_operational: bool = False
    signing_allowed: bool = False
    broadcast_allowed: bool = False
    mainnet_allowed: bool = False


def inspect_local_readiness(cancelled) -> ReadinessInspection:
    """Inspect the existing non-authorizing policy, without network or Core I/O.

    No HTTP/GPG/artifact verification occurs here. The receipt deliberately
    says BLOCKED, even if a caller supplies successful evidence elsewhere.
    """
    if cancelled() is not False:
        raise RegtestLifecycleError("APP_REGTEST_CANCELLED")
    receipt = TwoNodeReadiness().receipt()
    if (receipt["status"] != "BLOCKED_REQUIRES_GENUINE_CORE_REVIEW"
            or any(receipt[name] is not False for name in (
                "evidence_complete", "real_two_node_regtest_qualified",
                "core_execution_allowed", "scanner_enabled", "wallet_ready",
                "signing_allowed", "broadcast_allowed", "mainnet_allowed"))):
        raise RegtestLifecycleError("APP_REGTEST_READINESS_DENIED")
    if cancelled() is not False:
        raise RegtestLifecycleError("APP_REGTEST_CANCELLED")
    return ReadinessInspection()


@dataclass(frozen=True, slots=True)
class WorkTicket:
    revision: int
    operation: str


@dataclass(frozen=True, slots=True)
class RegtestApplicationState:
    revision: int = 0
    phase: str = "MODE_REQUIRED"
    mode: str = "UNSELECTED"
    readiness: str = "NOT_INSPECTED"
    failure: str = ""
    core_authenticated: bool = field(default=False, init=False)
    wallet_operational: bool = field(default=False, init=False)
    signing_allowed: bool = field(default=False, init=False)
    broadcast_allowed: bool = field(default=False, init=False)
    mainnet_allowed: bool = field(default=False, init=False)


class RegtestLifecycle:
    """Single GUI-thread writer. Only an owned active ticket can complete work."""

    def __init__(self):
        self._state = RegtestApplicationState()
        self._ticket = None

    @property
    def state(self):
        return self._state

    def _set(self, phase, *, mode=None, readiness=None, failure=""):
        old = self._state
        self._state = RegtestApplicationState(
            old.revision + 1, phase, old.mode if mode is None else mode,
            old.readiness if readiness is None else readiness, failure,
        )
        return self._state

    def select_mode(self, mode):
        if (self._state.phase == "CLOSED" or self._ticket is not None
                or type(mode) is not str or mode != "regtest"):
            raise RegtestLifecycleError("APP_REGTEST_MODE_DENIED")
        return self._set("REGTEST_SELECTED", mode="REGTEST", readiness="NOT_INSPECTED")

    def begin_readiness(self, *, consent):
        if (consent is not True or self._state.mode != "REGTEST"
                or self._state.phase == "CLOSED" or self._ticket is not None):
            raise RegtestLifecycleError("APP_REGTEST_CONSENT_OR_STATE_DENIED")
        state = self._set("CHECKING", readiness="NOT_INSPECTED")
        self._ticket = WorkTicket(state.revision, "READINESS")
        return self._ticket

    def _owns(self, ticket):
        # Identity, not a forgeable matching revision, grants completion rights.
        return type(ticket) is WorkTicket and ticket is self._ticket

    def finish_readiness(self, ticket, receipt):
        if not self._owns(ticket):
            return False
        self._ticket = None
        if not valid_readiness(receipt):
            self._set("FAILED", readiness="NOT_INSPECTED", failure="APP_REGTEST_RESULT_DENIED")
            raise RegtestLifecycleError("APP_REGTEST_RESULT_DENIED")
        self._set("BLOCKED", readiness="BLOCKED_EXTERNAL_APPROVAL")
        return True

    def fail(self, ticket):
        if not self._owns(ticket):
            return False
        self._ticket = None
        self._set("FAILED", readiness="NOT_INSPECTED", failure="APP_REGTEST_WORK_DENIED")
        return True

    def cancel(self):
        if self._state.phase == "CLOSED":
            return self._state
        self._ticket = None
        return self._set("CANCELLED", readiness="NOT_INSPECTED")

    def close(self):
        self._ticket = None
        if self._state.phase != "CLOSED":
            self._set("CLOSED", readiness="NOT_INSPECTED")
        return self._state

    def require_operational_wallet(self):
        # No receipt, click, endpoint, password, environment variable or caller
        # booleans can replace Core/WSP/security approval. No backend is touched.
        raise RegtestLifecycleError("APP_REGTEST_OPERATIONAL_GATES_BLOCKED")


def valid_readiness(value):
    return (type(value) is ReadinessInspection
            and type(value.blockers) is tuple
            and len(value.blockers) == len(BLOCKERS)
            and all(type(item) is int for item in value.blockers)
            and value.blockers == BLOCKERS
            and type(value.status) is str and value.status == "BLOCKED_EXTERNAL_APPROVAL"
            and all(getattr(value, name) is False for name in (
                "core_authenticated", "wallet_operational", "signing_allowed",
                "broadcast_allowed", "mainnet_allowed")))
