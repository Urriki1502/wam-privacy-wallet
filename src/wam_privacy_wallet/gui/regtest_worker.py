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


class RegtestWorkerController(QObject):
    state_changed = Signal(object)
    idle = Signal()

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
