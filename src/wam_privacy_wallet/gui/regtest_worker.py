"""Cooperative Qt readiness worker, with owned completion and clean shutdown.

Fixed local policy inspection only. No backend injection, node connection,
credential, account, signer, thread termination or synthetic wallet fallback.
"""
from __future__ import annotations

from threading import Event

from PySide6.QtCore import QObject, QThread, Qt, Signal, Slot

from wam_privacy_wallet.application.regtest_lifecycle import (
    RegtestLifecycle, RegtestLifecycleError, inspect_local_readiness,
)
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint
from wam_privacy_wallet.node.read_rpc import ExplicitRpcAuth
from wam_privacy_wallet.node.gui_two_node_readonly import inspect_existing_two_nodes


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


class RegtestWorkerController(QObject):
    state_changed = Signal(object)
    idle = Signal()
    node_probe_completed = Signal(object, object)
    node_probe_failed = Signal(object)

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
                      consent: bool, unverified_core_ack: bool):
        state = self.lifecycle.state
        if (self.busy or state.mode != "REGTEST" or state.phase == "CLOSED"
                or consent is not True or unverified_core_ack is not True):
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
