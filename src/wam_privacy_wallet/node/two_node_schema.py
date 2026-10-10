"""G1-03: versioned, non-executing two-node config representation.

Legacy G1-01 remains the canonical, unchanged source of truth. This module
parses that exact preview into immutable typed data and requires lossless
serialization plus exact policy parity. It never executes a node or grants
network, scanner, signer, wallet or release authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .two_node_policy import TwoNodePolicyError, audit_two_node_policy
from .two_node_topology import TwoNodePlan

SCHEMA_VERSION = 1
# Bitcoin-derived options scoped to the selected network, not global defaults.
# Keep fail-closed independently of the upstream equality/parity audit.
_NETWORK_ONLY_KEYS = frozenset(("bind", "rpcbind", "rpcport", "port", "connect"))
_DENIED = "G1_SCHEMA_INVALID"


class TwoNodeSchemaError(ValueError):
    """Stable, redacted error; do not include untrusted values."""


@dataclass(frozen=True, slots=True)
class ConfigOptionV1:
    section: Literal["global", "regtest"]
    key: str
    value: str


@dataclass(frozen=True, slots=True)
class StructuredNodeV1:
    label: Literal["node-a", "node-b"]
    rpc_host: str
    rpc_port: int
    p2p_host: str
    p2p_port: int
    peer_p2p_port: int
    options: tuple[ConfigOptionV1, ...]


@dataclass(frozen=True, slots=True)
class StructuredTwoNodeV1:
    schema_version: int
    nodes: tuple[StructuredNodeV1, StructuredNodeV1]
    status: Literal["BLOCKED_UNVERIFIED_CORE"]
    real_regtest_qualified: bool
    publisher_identity_verified: bool
    scanner_enabled: bool
    signing_enabled: bool
    release_allowed: bool


@dataclass(frozen=True, slots=True)
class SchemaParityEvidence:
    status: Literal["OFFLINE_PARITY_ONLY"] = "OFFLINE_PARITY_ONLY"
    schema_version: int = SCHEMA_VERSION
    legacy_config_unchanged: bool = True
    core_runtime_qualified: bool = False
    execution_allowed: bool = False
    release_allowed: bool = False


def _parse_legacy(preview: str) -> tuple[ConfigOptionV1, ...]:
    """Strictly parse the existing proposal; never reinterpret a duplicate."""
    if type(preview) is not str or not preview.endswith("\n") or len(preview) > 4096:
        raise TwoNodeSchemaError(_DENIED)
    section = "global"
    seen_section = False
    seen: set[tuple[str, str]] = set()
    options: list[ConfigOptionV1] = []
    for line in preview.splitlines():
        if line == "[regtest]" and not seen_section:
            section = "regtest"
            seen_section = True
            continue
        if not line or line.startswith("[") or "=" not in line:
            raise TwoNodeSchemaError(_DENIED)
        key, value = line.split("=", 1)
        if (not key.isascii() or not key.isalnum() or key != key.lower()
                or not value or len(value) > 128 or value.strip() != value
                or "\r" in value or (section, key) in seen
                or (key in _NETWORK_ONLY_KEYS and section != "regtest")):
            raise TwoNodeSchemaError(_DENIED)
        seen.add((section, key))
        options.append(ConfigOptionV1(section, key, value))
    if not seen_section or not options or options[0].section != "global":
        raise TwoNodeSchemaError(_DENIED)
    return tuple(options)


def _exact_node_types(node: object) -> bool:
    if type(node) is not StructuredNodeV1:
        return False
    try:
        if type(node.label) is not str or node.label not in ("node-a", "node-b"):
            return False
        if type(node.rpc_host) is not str or type(node.p2p_host) is not str:
            return False
        if any(type(getattr(node, field)) is not int
               for field in ("rpc_port", "p2p_port", "peer_p2p_port")):
            return False
        if type(node.options) is not tuple or not 1 <= len(node.options) <= 32:
            return False
        for option in node.options:
            if type(option) is not ConfigOptionV1:
                return False
            if (type(option.section) is not str
                    or type(option.key) is not str or type(option.value) is not str):
                return False
    except AttributeError:
        return False
    return True


def serialize_legacy_preview(node: object) -> str:
    """Lossless legacy serializer; serialized output is NOT a runnable config."""
    if not _exact_node_types(node):
        raise TwoNodeSchemaError(_DENIED)
    assert isinstance(node, StructuredNodeV1)
    seen: set[tuple[str, str]] = set()
    lines: list[str] = []
    in_regtest = False
    for option in node.options:
        if option.section not in ("global", "regtest"):
            raise TwoNodeSchemaError(_DENIED)
        if option.section == "global" and in_regtest:
            raise TwoNodeSchemaError(_DENIED)
        if option.section == "regtest" and not in_regtest:
            lines.append("[regtest]")
            in_regtest = True
        if (not option.key.isascii() or not option.key.isalnum()
                or option.key != option.key.lower()
                or not option.value or len(option.value) > 128
                or option.value.strip() != option.value
                or any(ch in option.value for ch in "\r\n")
                or (option.section, option.key) in seen
                or (option.key in _NETWORK_ONLY_KEYS
                    and option.section != "regtest")):
            raise TwoNodeSchemaError(_DENIED)
        seen.add((option.section, option.key))
        lines.append(f"{option.key}={option.value}")
    if not in_regtest or not lines or lines[0].startswith("["):
        raise TwoNodeSchemaError(_DENIED)
    return "\n".join(lines) + "\n"


def build_structured_two_node_v1(plan: object) -> StructuredTwoNodeV1:
    """Derive schema v1 solely from an independently audited canonical plan."""
    try:
        audit_two_node_policy(plan)
    except TwoNodePolicyError:
        raise TwoNodeSchemaError(_DENIED) from None
    assert isinstance(plan, TwoNodePlan)
    nodes = tuple(
        StructuredNodeV1(
            label=node.label,
            rpc_host=node.rpc_host,
            rpc_port=node.rpc_port,
            p2p_host=node.p2p_host,
            p2p_port=node.p2p_port,
            peer_p2p_port=node.peer_p2p_port,
            options=_parse_legacy(node.config_preview),
        )
        for node in plan.nodes
    )
    result = StructuredTwoNodeV1(
        schema_version=SCHEMA_VERSION,
        nodes=(nodes[0], nodes[1]),
        status=plan.status,
        real_regtest_qualified=plan.real_regtest_qualified,
        publisher_identity_verified=plan.publisher_identity_verified,
        scanner_enabled=plan.scanner_enabled,
        signing_enabled=plan.signing_enabled,
        release_allowed=plan.release_allowed,
    )
    if any(serialize_legacy_preview(node) != legacy.config_preview
           for node, legacy in zip(result.nodes, plan.nodes)):
        raise TwoNodeSchemaError(_DENIED)
    return result


def _exact_schema_types(schema: object) -> bool:
    if type(schema) is not StructuredTwoNodeV1:
        return False
    try:
        if type(schema.schema_version) is not int or schema.schema_version != SCHEMA_VERSION:
            return False
        if type(schema.status) is not str:
            return False
        for flag in ("real_regtest_qualified", "publisher_identity_verified",
                     "scanner_enabled", "signing_enabled", "release_allowed"):
            if type(getattr(schema, flag)) is not bool:
                return False
        if type(schema.nodes) is not tuple or len(schema.nodes) != 2:
            return False
        return all(_exact_node_types(node) for node in schema.nodes)
    except AttributeError:
        return False


def audit_parallel_two_node_v1(legacy_plan: object, candidate: object) -> SchemaParityEvidence:
    """Fail closed on any schema/legacy mismatch, including equal-valued aliases."""
    if not _exact_schema_types(candidate):
        raise TwoNodeSchemaError(_DENIED)
    try:
        canonical = build_structured_two_node_v1(legacy_plan)
        if candidate != canonical:
            raise TwoNodeSchemaError(_DENIED)
        assert isinstance(candidate, StructuredTwoNodeV1)
        assert isinstance(legacy_plan, TwoNodePlan)
        for node, legacy in zip(candidate.nodes, legacy_plan.nodes):
            if serialize_legacy_preview(node) != legacy.config_preview:
                raise TwoNodeSchemaError(_DENIED)
    except (TwoNodePolicyError, TwoNodeSchemaError):
        raise TwoNodeSchemaError(_DENIED) from None
    return SchemaParityEvidence()
