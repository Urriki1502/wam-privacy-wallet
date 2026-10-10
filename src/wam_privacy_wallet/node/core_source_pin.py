"""Fail-closed read-only WAM Core source compatibility contract.

No Core source is copied into the wallet build. Only exact Git blob IDs,
network constants and regtest genesis are checked against trusted, pinned
upstream source bytes. Neither this module nor CI compiles or changes Core.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Mapping

from .attestation import WAM_REGTEST_GENESIS

_PINNED_PATHS = (
    "src/wam/wam-params.h",
    "src/wam/chainparams.cpp",
    "scripts/patch_upstream.py",
)
_HEX40 = re.compile(r"[0-9a-f]{40}\\Z", re.ASCII)
_HEX64 = re.compile(r"[0-9a-f]{64}\\Z", re.ASCII)
_PORT_RE = re.compile(
    r"static\\s+constexpr\\s+int\\s+WAM_(MAINNET|TESTNET|REGTEST)_(P2P|RPC)_PORT\\s*=\\s*(\\d+)\\s*;"
)
_GENESIS_RE = re.compile(
    r'assert\\(consensus\\.hashGenesisBlock\\s*==\\s*uint256S\\("0x([0-9a-f]{64})"\\)\\);'
)
_REGTEST_RPC_PATCH = 'replacement=\'return std::make_unique<CBaseChainParams>("regtest", 29554);\''


class CoreSourceContractError(RuntimeError):
    """Non-sensitive contract status: no upstream source text is ever included."""


def git_blob_sha1(raw: bytes) -> str:
    if type(raw) is not bytes:
        raise CoreSourceContractError("CORE_SOURCE_INVALID_BYTES")
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\\0" + raw).hexdigest()


def load_core_manifest(path: Path) -> dict:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise CoreSourceContractError("CORE_MANIFEST_INVALID") from None
    if not isinstance(manifest, dict) or type(manifest.get("schema")) is not int or manifest["schema"] != 1:
        raise CoreSourceContractError("CORE_MANIFEST_INVALID")
    if manifest.get("repository") != "wamcoin-core-dev/wam-coin":
        raise CoreSourceContractError("CORE_MANIFEST_WRONG_SOURCE")
    for key in ("inspected_commit", "wsp1_reference_core_commit"):
        value = manifest.get(key)
        if type(value) is not str or _HEX40.fullmatch(value) is None:
            raise CoreSourceContractError("CORE_MANIFEST_INVALID")
    blobs = manifest.get("source_blobs")
    if type(blobs) is not dict or set(blobs) != set(_PINNED_PATHS):
        raise CoreSourceContractError("CORE_MANIFEST_INVALID")
    if any(type(v) is not str or _HEX40.fullmatch(v) is None for v in blobs.values()):
        raise CoreSourceContractError("CORE_MANIFEST_INVALID")
    if manifest.get("regtest_genesis") != WAM_REGTEST_GENESIS:
        raise CoreSourceContractError("CORE_MANIFEST_GENESIS_MISMATCH")
    if type(manifest.get("network_ports")) is not dict:
        raise CoreSourceContractError("CORE_MANIFEST_INVALID")
    ports = manifest["network_ports"]
    if set(ports) != {"mainnet", "testnet", "regtest"}:
        raise CoreSourceContractError("CORE_MANIFEST_INVALID")
    for spec in ports.values():
        if type(spec) is not dict or set(spec) != {"p2p", "rpc"}:
            raise CoreSourceContractError("CORE_MANIFEST_INVALID")
        if (type(spec["p2p"]) is not int or type(spec["rpc"]) is not int
                or not 1 <= spec["rpc"] < 65536 or spec["rpc"] != spec["p2p"] - 1):
            raise CoreSourceContractError("CORE_MANIFEST_PORT_INVALID")
    if ports["regtest"] != {"p2p": 29555, "rpc": 29554}:
        raise CoreSourceContractError("CORE_MANIFEST_PORT_INVALID")
    return manifest


def _strict_text(raw: bytes) -> str:
    if len(raw) > 500_000:
        raise CoreSourceContractError("CORE_SOURCE_TOO_LARGE")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CoreSourceContractError("CORE_SOURCE_INVALID_UTF8") from None


def verify_core_source(manifest: dict, files: Mapping[str, bytes]) -> dict:
    """Check exact raw pinned Core source content and critical source semantics."""
    if type(manifest) is not dict or type(files) is not dict or set(files) != set(_PINNED_PATHS):
        raise CoreSourceContractError("CORE_SOURCE_FILE_SET_INVALID")
    for path in _PINNED_PATHS:
        raw = files[path]
        if git_blob_sha1(raw) != manifest["source_blobs"][path]:
            raise CoreSourceContractError("CORE_SOURCE_BLOB_MISMATCH")

    params = _strict_text(files[_PINNED_PATHS[0]])
    chains = _strict_text(files[_PINNED_PATHS[1]])
    patch = _strict_text(files[_PINNED_PATHS[2]])
    records = _PORT_RE.findall(params)
    if len(records) != 6 or len({(n, kind) for n, kind, _ in records}) != 6:
        raise CoreSourceContractError("CORE_SOURCE_PORTS_UNRECOGNIZED")
    found = {n.lower(): {} for n in ("MAINNET", "TESTNET", "REGTEST")}
    for network, kind, number in records:
        found[network.lower()][kind.lower()] = int(number)
    if found != manifest["network_ports"]:
        raise CoreSourceContractError("CORE_SOURCE_PORT_DRIFT")

    if chains.count("class CRegTestParams") != 1:
        raise CoreSourceContractError("CORE_SOURCE_REGTEST_UNRECOGNIZED")
    regtest = chains.split("class CRegTestParams", 1)[1]
    hashes = _GENESIS_RE.findall(regtest)
    if len(hashes) != 1 or hashes[0] != manifest["regtest_genesis"]:
        raise CoreSourceContractError("CORE_SOURCE_GENESIS_DRIFT")
    if patch.count(_REGTEST_RPC_PATCH) != 1:
        raise CoreSourceContractError("CORE_SOURCE_RPC_PATCH_DRIFT")
    return {
        "network_ports": found,
        "regtest_genesis": hashes[0],
        "source_commit": manifest["inspected_commit"],
        "source_blobs": dict(manifest["source_blobs"]),
    }
