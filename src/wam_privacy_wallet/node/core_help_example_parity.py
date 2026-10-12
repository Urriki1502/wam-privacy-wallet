"""Read-only WAM daemon help/example text parity preflight.

This module does NOT execute wamd, authenticate publisher signatures, or
claim that independently supplied help text came from any released binary.
The DEV build/release runner must first prove that the captured --help output
belongs to the SAME qualified image as the example. Even a perfect local
option-name match is only untrusted text-inventory consistency.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

_HELP = re.compile(r"^[ \t]{1,8}--?([a-z][a-z0-9-]{0,63})(?=[= \t]|$)", re.I)
_EXAMPLE = re.compile(
    r"^[ \t]*[#;][ \t]*(?:--?)?([a-z][a-z0-9-]{0,63})[ \t]*=[ \t]*(.*)$",
    re.I,
)
_PLACEHOLDER = re.compile(r"<[a-z][a-z0-9_ .:/-]{0,63}>", re.I)
_NETWORK = frozenset(("main", "mainnet", "test", "testnet", "regtest", "signet"))
_CREDENTIAL = frozenset((
    "rpcpassword", "rpcauth", "rpcuser", "walletpassphrase",
    "rpcwalletpassphrase", "proxyuser", "proxypass",
))
_LOOPBACK = frozenset(("127.0.0.1", "localhost", "::1", "[::1]"))
_ALLOWIP = _LOOPBACK | frozenset(("127.0.0.1/8", "::1/128", "[::1]/128"))
_MAX_HELP_BYTES = 512 * 1024
_MAX_EXAMPLE_BYTES = 256 * 1024


class CoreHelpExampleError(ValueError):
    """Refusal codes only; never echo potentially sensitive input lines."""


@dataclass(frozen=True, slots=True)
class CoreHelpExampleObservation:
    option_count: int
    option_names_sha256: str
    help_text_sha256: str
    example_text_sha256: str
    text_option_inventory_matches: bool = True
    status: str = "UNTRUSTED_CORE_HELP_EXAMPLE_TEXT_PARITY_ONLY"
    signed_provenance_verified: bool = False
    same_executed_image_proven: bool = False
    help_parity_verified: bool = False
    safe_defaults_verified: bool = False
    real_regtest_qualified: bool = False
    core_execution_allowed: bool = False
    signer_enabled: bool = False
    broadcast_allowed: bool = False
    mainnet_allowed: bool = False


def _text(payload: bytes, limit: int, error: str) -> str:
    if type(payload) is not bytes or not 1 <= len(payload) <= limit:
        raise CoreHelpExampleError(error)
    try:
        decoded = payload.decode("utf-8", "strict")
        if (not decoded.strip()
                or "\x00" in decoded
                or "\ufeff" in decoded
                or any(ord(ch) < 32 and ch not in "\t\r\n" for ch in decoded)
                or any(ch in decoded for ch in ("\u2028", "\u2029"))):
            raise ValueError("unsafe content")
        return decoded
    except (UnicodeError, ValueError):
        raise CoreHelpExampleError(error) from None


def _help_options(body: str) -> frozenset[str]:
    options: set[str] = set()
    for line in body.splitlines():
        match = _HELP.match(line)
        if match is None:
            continue
        name = match.group(1).lower()
        if name in options:
            raise CoreHelpExampleError("CORE_CONFIG_HELP_DUPLICATE_DENIED")
        options.add(name)
    if not options:
        raise CoreHelpExampleError("CORE_CONFIG_HELP_OPTIONS_MISSING")
    return frozenset(options)


def _example_options(body: str) -> frozenset[str]:
    options: set[str] = set()
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("[") or not stripped.startswith(("#", ";")):
            raise CoreHelpExampleError("CORE_CONFIG_ACTIVE_DIRECTIVE_DENIED")
        match = _EXAMPLE.match(line)
        if match is None:
            continue
        name = match.group(1).lower()
        if name in options:
            raise CoreHelpExampleError("CORE_CONFIG_EXAMPLE_DUPLICATE_DENIED")
        options.add(name)
        value = match.group(2).strip()
        # Published sample must not contain real credentials or a ready-to-use
        # public RPC/P2P binding, even if currently commented out.
        if name in _CREDENTIAL and value and not _PLACEHOLDER.fullmatch(value):
            raise CoreHelpExampleError("CORE_CONFIG_EXAMPLE_CREDENTIAL_DENIED")
        if name in ("rpcbind", "bind", "whitebind") and value and value not in _LOOPBACK:
            raise CoreHelpExampleError("CORE_CONFIG_EXAMPLE_BIND_DENIED")
        if name == "rpcallowip" and value and value not in _ALLOWIP:
            raise CoreHelpExampleError("CORE_CONFIG_EXAMPLE_BIND_DENIED")
        if name in _NETWORK and value and value not in ("0", "1", "<0|1>"):
            raise CoreHelpExampleError("CORE_CONFIG_EXAMPLE_NETWORK_DENIED")
    if not options:
        raise CoreHelpExampleError("CORE_CONFIG_EXAMPLE_OPTIONS_MISSING")
    return frozenset(options)


def inspect_help_example_text(
    daemon_help: bytes,
    example_conf: bytes,
) -> CoreHelpExampleObservation:
    """Compare strict text option inventories; never claim same-binary origin.

    Real signed archive provenance and the DEV-controlled generation step
    cannot be inferred from a caller-controlled help capture or file path.
    This function never invokes subprocess, reads secrets, or changes config.
    """
    help_text = _text(
        daemon_help, _MAX_HELP_BYTES, "CORE_CONFIG_HELP_TEXT_DENIED"
    )
    example_text = _text(
        example_conf, _MAX_EXAMPLE_BYTES, "CORE_CONFIG_EXAMPLE_TEXT_DENIED"
    )
    options = _help_options(help_text)
    example = _example_options(example_text)
    if options != example:
        raise CoreHelpExampleError("CORE_CONFIG_OPTION_INVENTORY_MISMATCH")
    digest = hashlib.sha256("\n".join(sorted(options)).encode("ascii")).hexdigest()
    return CoreHelpExampleObservation(
        option_count=len(options),
        option_names_sha256=digest,
        help_text_sha256=hashlib.sha256(daemon_help).hexdigest(),
        example_text_sha256=hashlib.sha256(example_conf).hexdigest(),
    )
