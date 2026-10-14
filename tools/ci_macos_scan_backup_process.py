"""Actual macOS envelope publisher race/termination with public WSP fixtures.

Called only from the separately qualified native crypto proof. No production
backup, automatic orphan cleanup, Core, scanner or runtime authority.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import queue
import stat
import subprocess
import sys
import threading

from tools.ci_macos_scan_backup_native import _platform
from tools.ci_wsp1_scanner_process_lock import _qualify
from tools.ci_wsp1_scanner_native_only import _no_signer
from wam_privacy_wallet.application import macos_encrypted_scan_backup as storage

ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 20


def _child(root, directory, role):
    _platform()
    _qualify(root)
    if (not directory.is_absolute() or directory.name not in ('concurrent', 'interrupted')
            or not directory.parent.name.startswith('public-macos-scan-crypto-')
            or directory.is_symlink() or directory.parent.is_symlink()):
        raise RuntimeError('MACOS_ENVELOPE_FIXTURE_DIRECTORY_DENIED')
    info = directory.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError('MACOS_ENVELOPE_FIXTURE_DIRECTORY_DENIED')
    previous = sys.getprofile()
    sys.setprofile(_no_signer)
    try:
        from wam_sp.core import pub
        from wam_sp.keystore import ScanAccount, export_scan
        encrypted = export_scan((ScanAccount(0, 1, pub(2), birthday=1),),
                                b'PUBLIC_DISPOSABLE_REGTEST_TEST_PASSWORD')
        print('READY', flush=True)
        if sys.stdin.readline(32) != 'PUBLISH\n':
            raise RuntimeError('MACOS_ENVELOPE_PROTOCOL_DENIED')
        if role == 'flush-and-wait':
            flush = storage._full_flush
            def hold(fd):
                flush(fd)
                print('FLUSHED', flush=True)
                if sys.stdin.readline(32) != 'RELEASE\n':
                    raise RuntimeError('MACOS_ENVELOPE_PROTOCOL_DENIED')
            storage._full_flush = hold
        try:
            storage.provision_macos_encrypted_scan_backup(directory, encrypted)
        except storage.MacosEncryptedScanBackupError as error:
            if str(error) != 'MACOS_SCAN_BACKUP_STORE_DENIED':
                raise RuntimeError('MACOS_ENVELOPE_WRONG_DENIAL') from None
            print('DENIED', flush=True)
        else:
            print('CREATED', flush=True)
    finally:
        sys.setprofile(previous)


class _Process:
    def __init__(self, root, directory, role):
        env = {k: os.environ[k] for k in ('PATH', 'TMPDIR') if k in os.environ}
        env.update(PYTHONPATH=str(ROOT / 'src'), PYTHONDONTWRITEBYTECODE='1')
        self.process = subprocess.Popen(
            [sys.executable, '-B', '-m', 'tools.ci_macos_scan_backup_process',
             '--source-root', str(root), '--directory', str(directory), '--role', role],
            cwd=ROOT, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, close_fds=True,
        )
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        try:
            while line := self.process.stdout.readline(80):
                if line not in ('READY\n', 'FLUSHED\n', 'CREATED\n', 'DENIED\n'):
                    self.lines.put('INVALID_PROTOCOL')
                    return
                self.lines.put(line.strip())
        finally:
            self.lines.put(None)

    def receive(self):
        try:
            return self.lines.get(timeout=TIMEOUT)
        except queue.Empty:
            raise RuntimeError('MACOS_ENVELOPE_PROTOCOL_TIMEOUT') from None

    def expect(self, value):
        if self.receive() != value:
            raise RuntimeError('MACOS_ENVELOPE_PROTOCOL_DENIED')

    def publish(self):
        self.process.stdin.write('PUBLISH\n')
        self.process.stdin.flush()

    def finish(self):
        if self.process.wait(timeout=TIMEOUT) != 0:
            raise RuntimeError('MACOS_ENVELOPE_CHILD_DENIED')
        self.expect(None)

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=TIMEOUT)
        self.reader.join(timeout=TIMEOUT)
        for pipe in (self.process.stdin, self.process.stdout):
            pipe.close()
        if self.reader.is_alive():
            raise RuntimeError('MACOS_ENVELOPE_READER_CLEANUP_DENIED')


def exercise_process_recovery(root, parent, authenticate):
    """Use the caller's already source-qualified authentication assertion."""
    _platform()
    concurrent = parent / 'concurrent'
    concurrent.mkdir(mode=0o700)
    children = []
    try:
        for _ in range(2):
            child = _Process(root, concurrent, 'publish')
            children.append(child)
            child.expect('READY')
        for child in children:
            child.publish()
        outcomes = [child.receive() for child in children]
        if sorted(outcomes) != ['CREATED', 'DENIED']:
            raise RuntimeError('MACOS_ENVELOPE_CONCURRENT_PUBLICATION_DENIED')
        for child in children:
            child.finish()
        authenticate(storage.load_macos_encrypted_scan_backup(concurrent))
        assert sorted(p.name for p in concurrent.iterdir()) == ['scan-only.wsp.enc']
    finally:
        for child in children:
            child.close()

    interrupted = parent / 'interrupted'
    interrupted.mkdir(mode=0o700)
    holder = _Process(root, interrupted, 'flush-and-wait')
    try:
        holder.expect('READY')
        holder.publish()
        holder.expect('FLUSHED')
        assert not (interrupted / 'scan-only.wsp.enc').exists()
        holder.process.terminate()
        assert holder.process.wait(timeout=TIMEOUT) != 0
        holder.expect(None)
    finally:
        holder.close()
    stages = tuple(interrupted.glob('.macos-scan-stage-*'))
    assert len(stages) == 1
    orphan = stages[0]
    identity = orphan.stat()
    assert stat.S_IMODE(identity.st_mode) == 0o600 and identity.st_nlink == 1
    authenticate(orphan.read_bytes())
    restarted = _Process(root, interrupted, 'publish')
    try:
        restarted.expect('READY')
        restarted.publish()
        restarted.expect('CREATED')
        restarted.finish()
    finally:
        restarted.close()
    authenticate(storage.load_macos_encrypted_scan_backup(interrupted))
    assert orphan.stat().st_ino == identity.st_ino
    assert sorted(p.name for p in interrupted.iterdir()) == sorted([orphan.name, 'scan-only.wsp.enc'])
    return ('ACTUAL_INTERPROCESS_CREATE_ONCE', 'ACTUAL_FLUSHED_OWNER_TERMINATION_RESTART')


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--directory', required=True)
    parser.add_argument('--role', choices=('publish', 'flush-and-wait'), required=True)
    args = parser.parse_args(argv)
    try:
        _child(Path(args.source_root), Path(args.directory), args.role)
    except Exception:
        print('MACOS_ENVELOPE_PROCESS_PROOF_DENIED', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
