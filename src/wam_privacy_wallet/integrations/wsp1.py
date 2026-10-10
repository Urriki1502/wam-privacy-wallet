"""Fail-closed WSP-1 package provenance and API probe.

This module NEVER constructs a wallet, creates keys, opens a database,
connects to RPC, scans blocks, signs, or broadcasts. Runtime version metadata
is checked before the pinned engine is imported. The pinned code is still
research software, and import-time checks are not an independent audit.
"""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from importlib import metadata

WSP1_REPOSITORY = "https://github.com/Urriki1502/wam-silent-payments"
WSP1_COMMIT = "dcf1aecc00a64bfad3151fa202c3e07d47d83e69"
WSP1_DISTRIBUTION = "wam-silent-payments"
WSP1_VERSION = "1.0.0.dev0"
WSP1_API_VERSION = 1
WSP1_PROFILE = "WSP-1"
WSP1_CORE_VERSION = "0.1.11"
WSP1_CORE_COMMIT = "8a3f4fe4f1d804c378f795d4cc281ec5125f75f3"
WSP1_REGTEST_GENESIS = "b88f3d262f285e38e184f50bf3eea1c8e615486ae67d3d9eaf0976fbd6d3d30d"


class WSP1ContractError(RuntimeError):
    """Known qualification failure with a stable, non-sensitive code."""


@dataclass(frozen=True, slots=True)
class WSP1Qualification:
    """Read-only evidence; no live-node or wallet connection is implied."""

    version: str
    commit: str
    api_version: int
    profile: str
    regtest_genesis: str
    mainnet_enabled: bool


def _verify_installed_provenance() -> None:
    """Require an installed distribution from the exact reviewed Git commit."""
    try:
        dist = metadata.distribution(WSP1_DISTRIBUTION)
    except metadata.PackageNotFoundError as exc:
        raise WSP1ContractError("WSP1_NOT_INSTALLED") from exc
    if dist.version != WSP1_VERSION:
        raise WSP1ContractError("WSP1_VERSION_MISMATCH")
    try:
        raw = dist.read_text("direct_url.json")
        provenance = json.loads(raw) if raw is not None else None
    except (ValueError, TypeError) as exc:
        raise WSP1ContractError("WSP1_INVALID_PROVENANCE") from exc
    if not isinstance(provenance, dict):
        raise WSP1ContractError("WSP1_PROVENANCE_MISSING")
    url = provenance.get("url")
    vcs = provenance.get("vcs_info")
    if not isinstance(url, str) or not isinstance(vcs, dict):
        raise WSP1ContractError("WSP1_INVALID_PROVENANCE")
    # Accept Git's canonical .git suffix, but no alternate repository owner,
    # host, scheme, path, query, or unreviewed ref.
    normalized_url = url.removesuffix(".git")
    if normalized_url != WSP1_REPOSITORY or vcs.get("vcs") != "git":
        raise WSP1ContractError("WSP1_SOURCE_MISMATCH")
    if vcs.get("commit_id") != WSP1_COMMIT:
        raise WSP1ContractError("WSP1_COMMIT_MISMATCH")


def probe_pinned_wsp1() -> WSP1Qualification:
    """Check the pinned package and its read-only protocol metadata.

    This is only a compatibility signal for a future regtest-only adapter.
    It grants no permission to process addresses, private keys or funds.
    """
    _verify_installed_provenance()
    try:
        engine = importlib.import_module("wam_sp")
        profile = importlib.import_module("wam_sp.profile")
    except (ImportError, OSError) as exc:
        raise WSP1ContractError("WSP1_IMPORT_FAILURE") from exc

    if getattr(engine, "__version__", None) != WSP1_VERSION:
        raise WSP1ContractError("WSP1_RUNTIME_VERSION_MISMATCH")
    if getattr(profile, "API_VERSION", None) != WSP1_API_VERSION:
        raise WSP1ContractError("WSP1_API_MISMATCH")
    if getattr(profile, "PROFILE", None) != WSP1_PROFILE:
        raise WSP1ContractError("WSP1_PROFILE_MISMATCH")
    if getattr(profile, "CORE_VERSION", None) != WSP1_CORE_VERSION:
        raise WSP1ContractError("WSP1_CORE_VERSION_MISMATCH")
    if getattr(profile, "CORE_COMMIT", None) != WSP1_CORE_COMMIT:
        raise WSP1ContractError("WSP1_CORE_COMMIT_MISMATCH")
    if getattr(profile, "REGTEST_GENESIS", None) != WSP1_REGTEST_GENESIS:
        raise WSP1ContractError("WSP1_GENESIS_MISMATCH")
    if getattr(profile, "MAINNET_ENABLED", None) is not False:
        raise WSP1ContractError("WSP1_MAINNET_UNAPPROVED")

    wallet_cls = getattr(engine, "SilentWallet", None)
    factory = getattr(engine, "create_silent_wallet", None)
    if (
        not isinstance(wallet_cls, type)
        or getattr(wallet_cls, "api_version", None) != WSP1_API_VERSION
        or getattr(wallet_cls, "profile", None) != WSP1_PROFILE
        or not callable(factory)
    ):
        raise WSP1ContractError("WSP1_PUBLIC_API_MISMATCH")

    return WSP1Qualification(
        version=WSP1_VERSION,
        commit=WSP1_COMMIT,
        api_version=WSP1_API_VERSION,
        profile=WSP1_PROFILE,
        regtest_genesis=WSP1_REGTEST_GENESIS,
        mainnet_enabled=False,
    )
