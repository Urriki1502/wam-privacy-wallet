"""Regtest index/filter/descriptor observations with a separate READ boundary.

DEV v0.1.11 compatibility observations motivate this seam; only private-host
logs can qualify it against Core. Never starts Core, loads keys or broadens the
WSP scanner RPC. No filter observation is a permission to skip scanner blocks.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from .basic_block_filter import (
    BasicFilterError, ParsedBasicFilter, parse_basic_filter, validate_filter_header,
)
from .core_profile import VerifiedCoreProfile
from .endpoint import LocalRegtestEndpoint
from .read_rpc import ExplicitRpcAuth, LocalReadOnlyRpc, _post_json_rpc
from .regtest_gateway import LocalRegtestIdentityGateway

_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SCRIPT = re.compile(r"(?:[0-9a-f]{2}){1,520}\Z", re.ASCII)
_INDEXES = ("txindex", "basic block filter index", "coinstatsindex")


class CoreReadinessError(ValueError):
    """Fixed-code refusal; never interpolate node responses or scan scripts."""


@dataclass(frozen=True, slots=True)
class CoreReadinessObservation:
    height: int
    block_hash: str
    filter_elements: int
    filter_bytes: int
    filter_header: str

    def receipt(self) -> dict[str, object]:
        return {
            "status": "REPORTED_REGTEST_INDEX_FILTER_CONSISTENCY_ONLY",
            "height": self.height,
            "indexes": list(_INDEXES),
            "filter_elements": self.filter_elements,
            "filter_bytes": self.filter_bytes,
            "core_binary_authenticated": False,
            "real_regtest_accepted": False,
            "filter_can_skip_wsp_blocks": False,
            "signing_allowed": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
        }


class CoreRegtestReadinessRpc:
    """Explicit loopback/auth only; shared bounded transport, zero retries.

    The public methods are the entire RPC capability surface. A fresh strict
    network/genesis/profile check brackets each operation. Failure returns no
    receipt and does not modify checkpoints, scanner DB or local authority.
    """

    __slots__ = ("_endpoint", "_auth", "_timeout", "_identity", "_gateway")

    def __init__(self, endpoint: LocalRegtestEndpoint, auth: ExplicitRpcAuth,
                 *, timeout: float = 3) -> None:
        # Reuse exactly the existing typed endpoint/auth/timeout policy.
        self._identity = LocalReadOnlyRpc(endpoint, auth, timeout=timeout)
        self._gateway = LocalRegtestIdentityGateway(endpoint, auth, timeout=timeout)
        self._endpoint, self._auth, self._timeout = endpoint, auth, timeout

    def _request(self, method: str, params: list[object]) -> object:
        # Call sites below supply closed parameters. No public arbitrary call().
        if method not in ("getindexinfo", "getblockfilter", "scanblocks"):
            raise CoreReadinessError("CORE_READINESS_METHOD_DENIED")
        return _post_json_rpc(self._endpoint, self._auth, self._timeout,
                              method, params, 2_200_000)

    def _profile(self) -> VerifiedCoreProfile:
        profile = self._gateway.probe_core_profile()
        if profile.headers != profile.identity.height:
            raise CoreReadinessError("CORE_READINESS_HEADERS_PENDING")
        return profile

    def _indexes(self, height: int) -> None:
        result = self._request("getindexinfo", [])
        if type(result) is not dict:
            raise CoreReadinessError("CORE_READINESS_INDEX_DENIED")
        for name in _INDEXES:
            item = result.get(name)
            if (type(item) is not dict or item.get("synced") is not True
                    or type(item.get("best_block_height")) is not int
                    or item["best_block_height"] != height):
                raise CoreReadinessError("CORE_READINESS_INDEX_DENIED")

    def _filter(self, block_hash: str) -> tuple[ParsedBasicFilter, dict]:
        result = self._request("getblockfilter", [block_hash, "basic"])
        if (type(result) is not dict or type(result.get("header")) is not str
                or _HASH.fullmatch(result["header"]) is None):
            raise CoreReadinessError("CORE_READINESS_FILTER_DENIED")
        parsed = parse_basic_filter(result.get("filter"))
        return parsed, result

    def observe(self) -> CoreReadinessObservation:
        """Observe required indexes and the best filter's parent-header link."""
        try:
            before = self._profile()
            identity = before.identity
            self._indexes(identity.height)
            parsed, current = self._filter(identity.best_block_hash)
            previous = "0" * 64
            parent = None
            if identity.height > 0:
                parent = self._identity.call("getblockhash", [identity.height - 1])
                if type(parent) is not str or _HASH.fullmatch(parent) is None:
                    raise CoreReadinessError("CORE_READINESS_FILTER_DENIED")
                _, prev_filter = self._filter(parent)
                previous = prev_filter["header"]
            validate_filter_header(current["filter"], current["header"], previous)
            self._indexes(identity.height)
            if (self._profile() != before or (parent is not None and
                    self._identity.call("getblockhash", [identity.height - 1]) != parent)):
                raise CoreReadinessError("CORE_READINESS_CHAIN_DRIFT")
            return CoreReadinessObservation(identity.height, identity.best_block_hash,
                                             parsed.element_count, parsed.byte_count,
                                             current["header"])
        except CoreReadinessError:
            raise
        except BasicFilterError:
            raise CoreReadinessError("CORE_READINESS_FILTER_DENIED") from None
        except Exception:
            raise CoreReadinessError("CORE_READINESS_RPC_DENIED") from None

    def scan_public_scripts(self, scripts: tuple[str, ...], *, start: int,
                            stop: int, user_consented: bool) -> tuple[str, ...]:
        """Bounded scanblocks start for public raw scripts, never key descriptors.

        No status/abort authority or automatic retry: a timeout is a refusal,
        although Core's read job may finish independently. False positives are
        retained and matched blocks are checked against the current chain.
        Results are diagnostics; they cannot replace full WSP Scanner.sync.
        """
        if (user_consented is not True or type(scripts) is not tuple
                or not 1 <= len(scripts) <= 16
                or any(type(s) is not str or _SCRIPT.fullmatch(s) is None for s in scripts)
                or len(set(scripts)) != len(scripts)
                or type(start) is not int or type(stop) is not int
                or not 0 <= start <= stop <= 100_000_000 or stop - start >= 64):
            raise CoreReadinessError("CORE_READINESS_SCAN_SCOPE_DENIED")
        try:
            before = self._profile()
            if stop > before.identity.height:
                raise CoreReadinessError("CORE_READINESS_SCAN_SCOPE_DENIED")
            self._indexes(before.identity.height)
            result = self._request("scanblocks", ["start", [f"raw({s})" for s in scripts],
                                                   start, stop, "basic"])
            if (type(result) is not dict or result.get("completed") is not True
                    or type(result.get("from_height")) is not int
                    or type(result.get("to_height")) is not int
                    or result["from_height"] != start or result["to_height"] != stop
                    or type(result.get("relevant_blocks")) is not list):
                raise CoreReadinessError("CORE_READINESS_SCAN_REPLY_DENIED")
            hashes = result["relevant_blocks"]
            if (len(hashes) > stop - start + 1
                    or any(type(h) is not str or _HASH.fullmatch(h) is None for h in hashes)
                    or len(set(hashes)) != len(hashes)):
                raise CoreReadinessError("CORE_READINESS_SCAN_REPLY_DENIED")
            last_height = start - 1
            for block_hash in hashes:
                header = self._identity.call("getblockheader", [block_hash, True])
                if (type(header) is not dict or header.get("hash") != block_hash
                        or type(header.get("height")) is not int
                        or not last_height < header["height"] <= stop
                        or self._identity.call("getblockhash", [header["height"]]) != block_hash):
                    raise CoreReadinessError("CORE_READINESS_SCAN_REPLY_DENIED")
                last_height = header["height"]
            self._indexes(before.identity.height)
            if self._profile() != before:
                raise CoreReadinessError("CORE_READINESS_CHAIN_DRIFT")
            return tuple(hashes)
        except CoreReadinessError:
            raise
        except Exception:
            raise CoreReadinessError("CORE_READINESS_RPC_DENIED") from None
