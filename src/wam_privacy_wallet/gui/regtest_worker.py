"""Cooperative Qt readiness worker, with owned completion and clean shutdown.

Fixed local policy inspection only. No backend injection, node connection,
credential, account, signer, thread termination or synthetic wallet fallback.
"""
from __future__ import annotations

from threading import Event
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Qt, Signal, Slot

from wam_privacy_wallet.application.regtest_lifecycle import (
    RegtestLifecycle, RegtestLifecycleError, inspect_local_readiness,
)
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
from wam_privacy_wallet.node.gui_two_node_readonly import inspect_existing_two_nodes
from wam_privacy_wallet.application.qt_native_wsp_bridge import run_existing_two_node_scan
from wam_privacy_wallet.application.qt_native_private_workflow import run_private_wsp_workflow


class _ReadinessWorker(QObject):
    result = Signal(object, object)
    failed = Signal(object)
    done = Signal()

    def __init__(self, ticket, cancelled):
        super().__init__()
        self._ticket = ticket
        self._cancelled = cancelled

    @Slot()
    def run(self):
        try:
            receipt = inspect_local_readiness(self._cancelled.is_set)
            if not self._cancelled.is_set():
                self.result.emit(self._ticket, receipt)
        except Exception:
            self.failed.emit(self._ticket)
        finally:
            self.done.emit()


class _NodeProbeWorker(QObject):
    result = Signal(object, object)
    failed = Signal(object)
    done = Signal()

    def __init__(self, revision, cancelled, kwargs):
        super().__init__()
        self._revision = revision
        self._cancelled = cancelled
        self._kwargs = kwargs

    @Slot()
    def run(self):
        kwargs = self._kwargs
        self._kwargs = None
        try:
            if self._cancelled.is_set():
                return
            proof = inspect_existing_two_nodes(**kwargs, cancelled=self._cancelled)
            if not self._cancelled.is_set():
                self.result.emit(self._revision, proof)
        except Exception:
            if not self._cancelled.is_set():
                self.failed.emit(self._revision)
        finally:
            # Do not retain operator RPC passwords after the probe ends.
            kwargs.clear()
            self.done.emit()


class _NativeScanWorker(QObject):
    result = Signal(object, object)
    failed = Signal(object)
    done = Signal()

    def __init__(self, revision, cancelled, kwargs):
        super().__init__()
        self._revision = revision
        self._cancelled = cancelled
        self._kwargs = kwargs

    @Slot()
    def run(self):
        kwargs = self._kwargs
        self._kwargs = None
        try:
            if self._cancelled.is_set():
                return
            proof = run_existing_two_node_scan(**kwargs, cancelled=self._cancelled)
            if not self._cancelled.is_set():
                self.result.emit(self._revision, proof)
        except Exception:
            if not self._cancelled.is_set():
                self.failed.emit(self._revision)
        finally:
            kwargs.clear()
            self.done.emit()


class _PrivateWorkflowWorker(QObject):
    result = Signal(object, object)
    failed = Signal(object)
    done = Signal()

    def __init__(self, revision, cancelled, kwargs):
        super().__init__()
        self._revision = revision
        self._cancelled = cancelled
        self._kwargs = kwargs

    @Slot()
    def run(self):
        kwargs = self._kwargs
        self._kwargs = None
        try:
            if self._cancelled.is_set():
                return
            proof = run_private_wsp_workflow(**kwargs, cancelled=self._cancelled)
            if not self._cancelled.is_set():
                self.result.emit(self._revision, proof)
        except Exception:
            if not self._cancelled.is_set():
                self.failed.emit(self._revision)
        finally:
            kwargs.clear()
            self.done.emit()


class RegtestWorkerController(QObject):
    state_changed = Signal(object)
    idle = Signal()
    node_probe_completed = Signal(object, object)
    node_probe_failed = Signal(object)
    scan_completed = Signal(object, object)
    scan_failed = Signal(object)
    private_completed = Signal(object, object)
    private_failed = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.lifecycle = RegtestLifecycle()
        self._thread = None
        self._worker = None
        self._cancelled = None

    @property
    def busy(self):
        # Even a finished thread remains owned until its queued cleanup runs.
        return self._thread is not None

    def _notify(self):
        self.state_changed.emit(self.lifecycle.state)

    def select_regtest(self):
        if self.busy:
            raise RegtestLifecycleError("APP_REGTEST_WORKER_BUSY")
        self.lifecycle.select_mode("regtest")
        self._notify()

    def inspect(self, *, consent):
        if self.busy:
            raise RegtestLifecycleError("APP_REGTEST_WORKER_BUSY")
        ticket = self.lifecycle.begin_readiness(consent=consent)
        cancelled = Event()
        thread = QThread(self)
        worker = _ReadinessWorker(ticket, cancelled)
        worker.moveToThread(thread)
        self._thread, self._worker, self._cancelled = thread, worker, cancelled
        thread.started.connect(worker.run)
        worker.result.connect(self._result)
        worker.failed.connect(self._failed)
        worker.done.connect(worker.deleteLater)
        # quit must not wait for GUI-thread queued events during shutdown wait.
        worker.done.connect(thread.quit, Qt.ConnectionType.DirectConnection)
        thread.finished.connect(self._cleanup)
        self._notify()
        thread.start()

    def inspect_nodes(self, *, node_a_rpc: int, node_a_p2p: int,
                      node_a_user: str, node_a_password: str,
                      node_b_rpc: int, node_b_p2p: int,
                      node_b_user: str, node_b_password: str,
                      consent: bool, unverified_core_ack: bool,
                      check_index_filters: bool = False):
        state = self.lifecycle.state
        if (self.busy or state.mode != "REGTEST" or state.phase == "CLOSED"
                or consent is not True or unverified_core_ack is not True
                or type(check_index_filters) is not bool):
            raise RegtestLifecycleError("APP_REGTEST_NODE_CONSENT_DENIED")
        try:
            kwargs = {
                "a": LocalRegtestEndpoint("127.0.0.1", node_a_rpc),
                "aa": ExplicitRpcAuth(node_a_user, node_a_password),
                "b": LocalRegtestEndpoint("127.0.0.1", node_b_rpc),
                "bb": ExplicitRpcAuth(node_b_user, node_b_password),
                "p2p_a": node_a_p2p, "p2p_b": node_b_p2p,
                "user_consented": True,
                "acknowledged_unverified_core": True,
                "check_index_filters": check_index_filters,
            }
            if len({node_a_rpc, node_a_p2p, node_b_rpc, node_b_p2p}) != 4:
                raise ValueError
        except ValueError:
            raise RegtestLifecycleError("APP_REGTEST_NODE_INPUT_DENIED") from None
        thread = QThread(self)
        cancelled = Event()
        worker = _NodeProbeWorker(state.revision, cancelled, kwargs)
        worker.moveToThread(thread)
        self._thread, self._worker, self._cancelled = thread, worker, cancelled
        thread.started.connect(worker.run)
        worker.result.connect(self._node_result)
        worker.failed.connect(self._node_failed)
        worker.done.connect(worker.deleteLater)
        worker.done.connect(thread.quit, Qt.ConnectionType.DirectConnection)
        thread.finished.connect(self._cleanup)
        self._notify()
        thread.start()

    def scan_existing(self, *, source_root: str, private_dir: str,
                      scan_password: str,
                      node_a_rpc: int, node_a_p2p: int,
                      node_a_user: str, node_a_password: str,
                      node_b_rpc: int, node_b_p2p: int,
                      node_b_user: str, node_b_password: str,
                      consent: bool, unverified_core_ack: bool):
        state = self.lifecycle.state
        if (self.busy or state.mode != "REGTEST" or
                state.phase in ("CLOSED", "CANCELLED") or
                consent is not True or unverified_core_ack is not True):
            raise RegtestLifecycleError("APP_REGTEST_SCAN_CONSENT_DENIED")
        try:
            kwargs = dict(
                source_root=Path(source_root), private_dir=Path(private_dir),
                passphrase=scan_password.encode("utf-8"),
                a=LocalRegtestEndpoint("127.0.0.1", node_a_rpc),
                aa=ExplicitRpcAuth(node_a_user, node_a_password),
                b=LocalRegtestEndpoint("127.0.0.1", node_b_rpc),
                bb=ExplicitRpcAuth(node_b_user, node_b_password),
                p2p_a=node_a_p2p, p2p_b=node_b_p2p,
                user_consented=True, unverified_core_ack=True,
            )
            if (not kwargs["source_root"].is_absolute() or
                    not kwargs["private_dir"].is_absolute() or
                    not 12 <= len(kwargs["passphrase"]) <= 1024 or
                    len({node_a_rpc,node_b_rpc,node_a_p2p,node_b_p2p}) != 4):
                raise ValueError
        except (TypeError, ValueError, UnicodeError):
            raise RegtestLifecycleError("APP_REGTEST_SCAN_INPUT_DENIED") from None
        thread = QThread(self)
        cancelled = Event()
        worker = _NativeScanWorker(state.revision, cancelled, kwargs)
        worker.moveToThread(thread)
        self._thread, self._worker, self._cancelled = thread, worker, cancelled
        thread.started.connect(worker.run)
        worker.result.connect(self._scan_result)
        worker.failed.connect(self._scan_failure)
        worker.done.connect(worker.deleteLater)
        worker.done.connect(thread.quit, Qt.ConnectionType.DirectConnection)
        thread.finished.connect(self._cleanup)
        self._notify()
        thread.start()


    def private_workflow(self, *, operation: str, source_root: str,
                         private_dir: str, scan_password: str,
                         node_a_rpc: int, node_a_p2p: int,
                         node_a_user: str, node_a_password: str,
                         node_b_rpc: int, node_b_p2p: int,
                         node_b_user: str, node_b_password: str,
                         consent: bool, unverified_core_ack: bool,
                         private_display_ack: bool):
        state = self.lifecycle.state
        if (self.busy or state.mode != "REGTEST" or
                state.phase in ("CLOSED", "CANCELLED") or
                consent is not True or unverified_core_ack is not True or
                private_display_ack is not True or
                type(operation) is not str or
                operation not in ("history", "checkpoint", "restore", "receive", "balance")):
            raise RegtestLifecycleError("APP_REGTEST_PRIVATE_SCOPE_DENIED")
        try:
            kwargs = dict(
                operation=operation,
                source_root=Path(source_root), private_dir=Path(private_dir),
                passphrase=scan_password.encode("utf-8"),
                a=LocalRegtestEndpoint("127.0.0.1", node_a_rpc),
                aa=ExplicitRpcAuth(node_a_user, node_a_password),
                b=LocalRegtestEndpoint("127.0.0.1", node_b_rpc),
                bb=ExplicitRpcAuth(node_b_user, node_b_password),
                p2p_a=node_a_p2p, p2p_b=node_b_p2p,
                user_consented=True, unverified_core_ack=True,
                private_display_ack=True,
            )
            if (not kwargs["source_root"].is_absolute()
                    or not kwargs["private_dir"].is_absolute()
                    or not 12 <= len(kwargs["passphrase"]) <= 1024
                    or len({node_a_rpc,node_b_rpc,node_a_p2p,node_b_p2p}) != 4):
                raise ValueError
        except (TypeError, ValueError, UnicodeError):
            raise RegtestLifecycleError("APP_REGTEST_PRIVATE_INPUT_DENIED") from None
        thread = QThread(self)
        cancelled = Event()
        op = _PrivateWorkflowWorker(state.revision, cancelled, kwargs)
        op.moveToThread(thread)
        self._thread, self._worker, self._cancelled = thread, op, cancelled
        thread.started.connect(op.run)
        op.result.connect(self._private_result)
        op.failed.connect(self._private_failure)
        op.done.connect(op.deleteLater)
        op.done.connect(thread.quit, Qt.ConnectionType.DirectConnection)
        thread.finished.connect(self._cleanup)
        self._notify()
        thread.start()

    @Slot(object, object)
    def _private_result(self, revision, receipt):
        if (type(revision) is int and revision == self.lifecycle.state.revision
                and self._cancelled is not None and not self._cancelled.is_set()):
            self.private_completed.emit(revision, receipt)

    @Slot(object)
    def _private_failure(self, revision):
        if (type(revision) is int and revision == self.lifecycle.state.revision
                and self._cancelled is not None and not self._cancelled.is_set()):
            self.private_failed.emit(revision)

    @Slot(object, object)
    def _scan_result(self, revision, receipt):
        if (type(revision) is int and revision == self.lifecycle.state.revision
                and self._cancelled is not None and not self._cancelled.is_set()):
            self.scan_completed.emit(revision, receipt)

    @Slot(object)
    def _scan_failure(self, revision):
        if (type(revision) is int and revision == self.lifecycle.state.revision
                and self._cancelled is not None and not self._cancelled.is_set()):
            self.scan_failed.emit(revision)

    @Slot(object, object)
    def _node_result(self, revision, receipt):
        if (type(revision) is int and
                revision == self.lifecycle.state.revision and
                not (self._cancelled is None or self._cancelled.is_set())):
            self.node_probe_completed.emit(revision, receipt)

    @Slot(object)
    def _node_failed(self, revision):
        if type(revision) is int and revision == self.lifecycle.state.revision:
            self.node_probe_failed.emit(revision)

    @Slot(object, object)
    def _result(self, ticket, receipt):
        try:
            changed = self.lifecycle.finish_readiness(ticket, receipt)
        except RegtestLifecycleError:
            changed = True
        if changed:
            self._notify()

    @Slot(object)
    def _failed(self, ticket):
        if self.lifecycle.fail(ticket):
            self._notify()

    @Slot()
    def _cleanup(self):
        thread = self._thread
        self._worker = self._thread = self._cancelled = None
        if thread is not None:
            thread.deleteLater()
        self.idle.emit()

    def cancel(self):
        if self._cancelled is not None:
            self._cancelled.set()
        self.lifecycle.cancel()
        self._notify()

    def shutdown(self, *, wait_ms=0):
        if type(wait_ms) is not int or not 0 <= wait_ms <= 5000:
            raise RegtestLifecycleError("APP_REGTEST_SHUTDOWN_INPUT_DENIED")
        if self._cancelled is not None:
            self._cancelled.set()
        self.lifecycle.close()
        self._notify()
        # Never terminate a thread or delete a live QThread/worker. A caller
        # must defer window destruction until this returns True.
        return self._thread is None or self._thread.wait(wait_ms)
