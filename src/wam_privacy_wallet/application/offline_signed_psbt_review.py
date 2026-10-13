"""Receive a separately signed WSP-1 PSBT for STRICT offline review, never spend.

No signer instantiation, Core process, RPC, broadcast, secret access, wallet
authority or mock backend. POSIX private input, exact-source upstream parser,
cryptographic signature verification and intent matching, all review-only.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import importlib.metadata
import importlib.util
import os
from pathlib import Path
import stat
import sys

from wam_privacy_wallet.integrations.wsp1_source_closure import verify_wsp1_full_source_closure
from wam_privacy_wallet.integrations.wsp1_source_review import PINNED_COMMIT

_MAX_SIGNED_B64 = 1_400_000
_MAX_CIPHERTEXT = 1_000_052


class SignedPsbtReviewError(ValueError):
    """Never expose sensitive bytes or private file paths in exceptions."""


def _read_private_file(path: Path, *, lower: int, upper: int) -> bytes:
    if (type(path) is not type(Path()) or not path.is_absolute()
            or path.is_symlink() or not 1 <= lower <= upper
            or sys.platform != "linux" or os.name != "posix"):
        raise SignedPsbtReviewError("SIGNED_PSBT_PRIVATE_FILE_DENIED")
    directory = file_fd = None
    try:
        if path.resolve(strict=True) != path:
            raise ValueError
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY
                            | os.O_NOFOLLOW | os.O_CLOEXEC)
        d = os.fstat(directory)
        if (not stat.S_ISDIR(d.st_mode)
                or stat.S_IMODE(d.st_mode) != 0o700
                or d.st_uid != os.geteuid()):
            raise ValueError
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW
                          | os.O_CLOEXEC, dir_fd=directory)
        before = os.fstat(file_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != os.geteuid()
                or not lower <= before.st_size <= upper):
            raise ValueError
        data = bytearray()
        while len(data) < before.st_size:
            part = os.read(file_fd, min(65536, before.st_size - len(data)))
            if not part:
                raise ValueError
            data.extend(part)
        after = os.fstat(file_fd)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise ValueError
        return bytes(data)
    except (OSError, ValueError):
        raise SignedPsbtReviewError("SIGNED_PSBT_PRIVATE_FILE_DENIED") from None
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory is not None:
            os.close(directory)


def review_signed_regtest_psbt(
    source_root: Path, encrypted_request: Path, signed_psbt: Path,
    intent_password: bytes, *, expected_request_sha256: str,
    user_consented: bool,
) -> dict[str, object]:
    """Review real offline signer output with original pinned WSP verification.

    The encrypted intent contains no spend secret; the signed PSBT arrives
    from a separate operator-managed offline signer. This function NEVER
    executes the signer or Core and does not authorize broadcast.
    """
    if (user_consented is not True or type(source_root) is not type(Path())
            or not source_root.is_absolute()
            or type(encrypted_request) is not type(Path())
            or type(signed_psbt) is not type(Path())
            or encrypted_request == signed_psbt
            or type(intent_password) is not bytes
            or not 12 <= len(intent_password) <= 1024
            or type(expected_request_sha256) is not str
            or len(expected_request_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_request_sha256)):
        raise SignedPsbtReviewError("SIGNED_PSBT_SCOPE_DENIED")
    try:
        proof = verify_wsp1_full_source_closure(source_root)
        if (proof.get("pinned_commit") != PINNED_COMMIT
                or proof.get("status") != "WSP1_FULL_SOURCE_CLOSURE_VERIFIED_NO_AUTHORITY"
                or proof.get("signer_enabled") is not False
                or proof.get("broadcast_allowed") is not False):
            raise ValueError
        required = (("coincurve", "21.0.0"),
                    ("cryptography", "50.0.0"),
                    ("pycryptodome", "3.23.0"))
        if any(importlib.metadata.version(pkg) != version for pkg,version in required):
            raise ValueError
        spec = importlib.util.find_spec("wam_sp")
        if (spec is None or spec.origin is None
                or Path(spec.origin).resolve() !=
                    source_root / "src/wam_sp/__init__.py"):
            raise ValueError
    except Exception:
        raise SignedPsbtReviewError("SIGNED_PSBT_SOURCE_DENIED") from None
    request_bytes = _read_private_file(
        encrypted_request, lower=52, upper=_MAX_CIPHERTEXT)
    if (not request_bytes.startswith(b"WAMSP02\x00")
            or sha256(request_bytes).hexdigest() != expected_request_sha256):
        raise SignedPsbtReviewError("SIGNED_PSBT_REQUEST_DENIED")
    signed_data = _read_private_file(signed_psbt, lower=16, upper=_MAX_SIGNED_B64)
    try:
        # These are actual upstream parser/crypto methods, not code copies.
        from wam_sp.wallet import decode_request
        from wam_sp.psbt import PSBT
        from wam_sp.core import decode_address
        proposal = decode_request(request_bytes, intent_password)
        ascii_psbt = signed_data.decode("ascii")
        if ascii_psbt != ascii_psbt.strip() or any(ch.isspace() for ch in ascii_psbt):
            raise ValueError
        psbt = PSBT.from_base64(ascii_psbt)
        if psbt.version != 2 or len(psbt.tx.inputs) != len(proposal.coins):
            raise ValueError
        # Reverify every Taproot signature + BIP352 sender proof in upstream
        # before trusting any recipient/fee projection. NO broadcast.
        psbt.finalize()
        for outpoint, utxo, coin in zip(psbt.tx.inputs, psbt.utxos, proposal.coins):
            if (outpoint != (coin["txid"], coin["vout"])
                    or utxo[0] != coin["atoms"]
                    or utxo[1] != b"\x51\x20" + bytes.fromhex(coin["public_key"])):
                raise ValueError
        fee = sum(v for v, _ in psbt.utxos) - sum(v for v, _ in psbt.tx.outputs)
        if fee != proposal.fee or not 1 <= fee <= 1_000_000:
            raise ValueError
        output_metadata = psbt.output_extra or tuple({} for _ in psbt.tx.outputs)
        observed = Counter()
        for (atoms, _), metadata in zip(psbt.tx.outputs, output_metadata):
            pair = metadata.get(b"\x09")
            if type(pair) is not bytes or len(pair) != 66:
                raise ValueError
            observed[(atoms, pair)] += 1
        for intent in proposal.intents:
            scan, spend = decode_address(intent.code, hrp="wamrtsp")
            entry = (intent.atoms, scan.format() + spend.format())
            if observed[entry] < 1:
                raise ValueError
            observed[entry] -= 1
        extras = [(amount, count) for (amount, _), count in observed.items() if count]
        if (sum(count for _, count in extras) > 1
                or any(amount < 330 for amount, count in extras)):
            raise ValueError
        return {
            "status": "SEPARATE_SIGNER_PSBT_CRYPTO_VERIFIED_REVIEW_ONLY",
            "wsp_source_commit": PINNED_COMMIT,
            "encrypted_request_sha256": expected_request_sha256,
            "signed_psbt_sha256": sha256(signed_data).hexdigest(),
            "input_count": len(psbt.tx.inputs),
            "recipient_count": len(proposal.intents),
            "fee_atoms": fee,
            "change_output_present_unqualified": bool(extras),
            "core_binary_authenticated": False,
            "signature_verified_by_upstream_parser": True,
            "signer_executed_by_wallet": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
            "wallet_operational": False,
            "real_regtest_e2e_passed": False,
        }
    except Exception:
        raise SignedPsbtReviewError("SIGNED_PSBT_REVIEW_DENIED") from None
