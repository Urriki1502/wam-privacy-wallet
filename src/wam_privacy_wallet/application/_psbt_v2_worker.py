"""Fixed internal unsigned-fixture parser; no arbitrary command/provider inputs."""
from __future__ import annotations

from dataclasses import asdict
import importlib.metadata
import importlib.util
import json
import os
import struct
from pathlib import Path
import sys

from ..integrations.wsp1_source_closure import verify_wsp1_full_source_closure
from .psbt_v2_review import PsbtV2Review

_GLOBAL = frozenset((b"\xfb", b"\x02", b"\x03", b"\x04", b"\x05", b"\x06"))
_INPUT = frozenset((b"\x01", b"\x0e", b"\x0f", b"\x10"))
_OUTPUT = frozenset((b"\x03", b"\x04"))
_DEPS = {"coincurve": "21.0.0", "cryptography": "50.0.0", "pycryptodome": "3.23.0"}
_FORBIDDEN = frozenset(("sign", "sign_schnorr", "sign_spend", "signed_single_input",
    "finalize", "finalized", "broadcast", "prepare", "export_signing_request",
    "create_silent_wallet", "spending_key", "send"))


def _deny() -> None:
    raise ValueError("APP_PSBT_V2_WORKER_DENIED")


def _audit_read_only(event, args):
    """Denial instrumentation; never a claim of OS/native hostile-code sandboxing."""
    if (event.startswith("socket.") or event in (
            "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn")):
        _deny()
    if event == "open" and len(args) >= 3:
        flags = args[2]
        if type(flags) is int and flags & (os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_RDWR | os.O_APPEND):
            _deny()


def _profile_no_sign(frame, event, arg):
    if event != "call":
        return
    module = frame.f_globals.get("__name__", "")
    if type(module) is str and module.startswith(("wam_sp", "coincurve")):
        name = frame.f_code.co_name
        if name in _FORBIDDEN:
            _deny()
        if name == "__init__" and type(frame.f_locals.get("self")).__name__ in (
                "Signer", "Wallet", "SilentWallet", "Keyring", "KeyRing"):
            _deny()


def qualify_read_only_source(root: Path) -> None:
    """Shared one-shot worker gate; installs the existing denial instrumentation."""
    if struct.calcsize("P") != 8 or sys.platform not in ("linux", "darwin", "win32"):
        _deny()
    if any(name == "wam_sp" or name.startswith("wam_sp.") for name in sys.modules):
        _deny()
    verify_wsp1_full_source_closure(root)
    # A fresh worker must not select unverified, pre-existing cached bytecode.
    if any((root / "src/wam_sp").rglob("*.pyc")):
        _deny()
    if any(importlib.metadata.version(name) != version for name, version in _DEPS.items()):
        _deny()
    spec = importlib.util.find_spec("wam_sp")
    if (spec is None or spec.origin is None
            or Path(spec.origin).resolve() != (root / "src/wam_sp/__init__.py").resolve()):
        _deny()
    sys.addaudithook(_audit_read_only)
    sys.setprofile(_profile_no_sign)


def parse_pinned_unsigned_fixture(raw: bytes, root: Path) -> PsbtV2Review:
    """Internal one-shot function; imports only after exact source qualification."""
    if type(raw) is not bytes or not 5 <= len(raw) <= 1_000_000:
        _deny()
    qualify_read_only_source(root)
    try:
        # Actual unchanged pinned parser primitives, not a copied wire parser.
        from wam_sp.psbt import PSBT, Reader, _read_map, _count

        reader = Reader(raw)
        if reader.take(5) != b"psbt\xff":
            _deny()
        global_map = _read_map(reader)
        if (not set(global_map) <= _GLOBAL
                or global_map.get(b"\xfb") != b"\x02\x00\x00\x00"
                or global_map.get(b"\x06", b"\x00") != b"\x00"
                or b"\x04" not in global_map or b"\x05" not in global_map):
            _deny()
        ni = _count(global_map[b"\x04"], 128)
        no = _count(global_map[b"\x05"], 256)
        for _ in range(ni):
            if not set(_read_map(reader)) <= _INPUT:
                _deny()
        for _ in range(no):
            if not set(_read_map(reader)) <= _OUTPUT:
                _deny()
        reader.finish()
        parsed = PSBT.decode(raw)
        if (parsed.version != 2 or any(sig is not None for sig in parsed.signatures)
                or sum(value for value, _ in parsed.utxos) < sum(value for value, _ in parsed.tx.outputs)):
            _deny()
        return PsbtV2Review(len(parsed.tx.inputs), len(parsed.tx.outputs))
    finally:
        sys.setprofile(None)


def main() -> int:
    try:
        if len(sys.argv) != 3 or sys.argv[1] != "--source-root":
            _deny()
        root = Path(sys.argv[2])
        raw = sys.stdin.buffer.read(1_000_001)
        receipt = parse_pinned_unsigned_fixture(raw, root)
        print(json.dumps(asdict(receipt), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:
        # No traceback, path, PSBT, script, amount or underlying import error.
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
