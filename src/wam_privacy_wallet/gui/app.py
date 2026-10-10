"""Explicit Qt entry point; importing the package never starts a GUI."""

from __future__ import annotations

import sys
from collections.abc import Sequence

from PySide6.QtWidgets import QApplication

from .main_window import MainWindow


def main(argv: Sequence[str] | None = None) -> int:
    """Start the offline preview, without reading wallet state or network settings."""
    if QApplication.instance() is not None:
        raise RuntimeError("A Qt application already exists in this process")
    app = QApplication(list(sys.argv if argv is None else argv))
    app.setApplicationName("WAM Privacy Wallet")
    window = MainWindow()
    window.show()
    return int(app.exec())
