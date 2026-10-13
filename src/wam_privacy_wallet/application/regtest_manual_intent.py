"""Disposable REAL REGTEST WSP-1 UTXO → encrypted offline-signer intent.

This is a send-COORDINATOR role, never the separate signer process. It imports
the source-pinned upstream Wallet only after Scanner and source verification.
No spend seed, Keyring, raw signer, network mutation or synthetic runtime.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import re
import secrets
import stat
import sys

from wam_privacy_wallet.application.qualified_scan_session import SourceQualifiedScanRuntime
from wam_privacy_wallet.integrations.wsp1_scanner_only_rpc import Wsp1ScannerOnlyRpc
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
from wam_privacy_wallet.node.regtest_gateway import LocalRegtestIdentityGateway

_NAME = "wsp-intent-v1.enc"
_CODE = re.compile(r"wamrtsp1[023456789acdefghjklmnpqrstuvwxyz]{100,130}\Z", re.ASCII)
_MAGIC = b"WAMSP02\x00"
_MAX_CIPHERTEXT = 1_000_052


class ManualIntentError(ValueError):
    """Fixed codes only; never account, recipient, RPC, path or PSBT metadata."""


def _store_encrypted_intent(folder: Path, ciphertext: bytes) -> str:
    """Create-once Linux dirfd atomic publish; ciphertext is opaque to app."""
    if (sys.platform != "linux" or os.name != "posix"
            or type(folder) is not type(Path()) or not folder.is_absolute()
            or folder.is_symlink() or type(ciphertext) is not bytes
            or not 52 <= len(ciphertext) <= _MAX_CIPHERTEXT
            or not ciphertext.startswith(_MAGIC)):
        raise ManualIntentError("INTENT_STORE_SCOPE_DENIED")
    dir_fd = None
    fd = None
    staged = False
    error = False
    stage = ".wsp-intent-stage-" + secrets.token_hex(16)
    digest = sha256(ciphertext).hexdigest()
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        dir_fd = os.open(folder, flags)
        meta = os.fstat(dir_fd)
        if (not stat.S_ISDIR(meta.st_mode) or stat.S_IMODE(meta.st_mode) != 0o700
                or meta.st_uid != os.geteuid() or meta.st_nlink < 2):
            raise ValueError
        fd = os.open(
            stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dir_fd,
        )
        staged = True
        offset = 0
        while offset < len(ciphertext):
            written = os.write(fd, ciphertext[offset:])
            if written <= 0:
                raise OSError
            offset += written
        os.fsync(fd)
        os.close(fd)
        fd = None
        # Hardlink publication is atomic; existing canonical file stays intact.
        os.link(stage, _NAME, src_dir_fd=dir_fd, dst_dir_fd=dir_fd,
                follow_symlinks=False)
    except Exception:
        error = True
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                error = True
        if dir_fd is not None:
            if staged:
                try:
                    os.unlink(stage, dir_fd=dir_fd)
                except OSError:
                    error = True
            try:
                os.fsync(dir_fd)
            except OSError:
                error = True
            try:
                os.close(dir_fd)
            except OSError:
                error = True
    if error:
        raise ManualIntentError("INTENT_STORE_DENIED") from None
    return digest


def create_manual_regtest_intent(
    source_root: Path, private_dir: Path, output_dir: Path,
    scan_password: bytes, intent_password: bytes, *,
    endpoint: LocalRegtestEndpoint, rpc_auth: ExplicitRpcAuth,
    recipient_code: str, recipient_atoms: int, fee_atoms: int,
    user_consented: bool, acknowledge_unverified_binary: bool,
    max_blocks: int = 16,
) -> dict[str, object]:
    """Use genuine current scan-UTXOs, reserve inputs, export AES-GCM sidecar.

    No automatic cancellation/retry after sidecar publication: a partially
    successful operation can leave a conservatively reserved UTXO.
    """
    if (user_consented is not True or acknowledge_unverified_binary is not True
            or type(endpoint) is not LocalRegtestEndpoint
            or endpoint.host != "127.0.0.1"
            or type(rpc_auth) is not ExplicitRpcAuth
            or type(source_root) is not type(Path()) or not source_root.is_absolute()
            or type(private_dir) is not type(Path()) or not private_dir.is_absolute()
            or type(output_dir) is not type(Path()) or not output_dir.is_absolute()
            or type(scan_password) is not bytes
            or type(intent_password) is not bytes
            or not 12 <= len(scan_password) <= 1024
            or not 12 <= len(intent_password) <= 1024
            or type(recipient_code) is not str or _CODE.fullmatch(recipient_code) is None
            or type(recipient_atoms) is not int
            or not 330 <= recipient_atoms <= 22_000_000 * 100_000_000
            or type(fee_atoms) is not int or not 1 <= fee_atoms <= 1_000_000
            or type(max_blocks) is not int or not 1 <= max_blocks <= 16):
        raise ManualIntentError("INTENT_PREPARE_SCOPE_DENIED")
    session = None
    try:
        gw = LocalRegtestIdentityGateway(endpoint, rpc_auth, timeout=3)
        before = gw.probe_core_profile()
        runtime = SourceQualifiedScanRuntime(source_root, user_consented=True)
        session = runtime.open(private_dir, scan_password, user_consented=True)
        rpc = Wsp1ScannerOnlyRpc(endpoint, rpc_auth, timeout=3)
        snap = session.scan(rpc, user_consented=True, max_blocks=max_blocks)
        if not snap.chain_current:
            raise ManualIntentError("INTENT_PREPARE_PARTIAL_SCAN_DENIED")
        # Every WSP module including wallet.py and crypto dependencies is
        # verified by exact tracked Git blob before first upstream import.
        from wam_sp.wallet import Wallet, Intent, encode_request
        scanner = session._scanner
        with scanner._lease():
            if gw.probe_core_profile() != before:
                raise ManualIntentError("INTENT_PREPARE_MOVED_DENIED")
            scanner.assert_current()
            wallet = Wallet(scanner)  # No Keyring or signer role.
            proposal = wallet.propose(
                (Intent(recipient_code, recipient_atoms),),
                fee_atoms, min_confirmations=1, allow_cluster_merge=False,
            )
            # Upstream encrypts intent for the separate TTY-only offline signer.
            # The reservation remains LOCKED after this point if anything fails
            # ambiguously: never retry the same UTXOs automatically.
            try:
                ciphertext = encode_request(proposal, intent_password)
            except Exception:
                # No ciphertext was exposed, so a DRAFT reservation may
                # safely be rolled back. Never release a published request.
                wallet.release_draft(proposal.token)
                raise
            digest = _store_encrypted_intent(output_dir, ciphertext)
            wallet.mark_signed(proposal.token)
            scanner.assert_current()
        if gw.probe_core_profile() != before:
            raise ManualIntentError("INTENT_PREPARE_MOVED_DENIED")
        return {
            "status": "ENCRYPTED_WSP_INTENT_READY_FOR_SEPARATE_OFFLINE_SIGNER",
            "source_commit": snap.source_commit,
            "encrypted_request_sha256": digest,
            "input_count": len(proposal.coins),
            "fee_atoms": fee_atoms,
            "core_binary_authenticated": False,
            "real_regtest_e2e_passed": False,
            "wallet_operational": False,
            "signer_executed": False,
            "signing_allowed": False,
            "broadcast_allowed": False,
            "mainnet_allowed": False,
        }
    except ManualIntentError:
        raise
    except Exception:
        raise ManualIntentError("INTENT_PREPARE_DENIED") from None
    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                raise ManualIntentError("INTENT_PREPARE_CLOSE_DENIED") from None
