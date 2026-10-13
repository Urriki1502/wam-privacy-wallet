"""Explicit Qt entry point; importing the package never starts a GUI."""

from __future__ import annotations

import sys
import argparse
from collections.abc import Sequence

from PySide6.QtWidgets import QApplication

from .main_window import MainWindow
from .regtest_window import RegtestWindow


def main(argv: Sequence[str] | None = None) -> int:
    """Start explicit mode selection; preview remains available by --offline-review.

    No command-line argument accepts node credentials, keys or account paths.
    Selecting REGTEST does not approve Core, network or spending capabilities.
    """
    values = list(sys.argv if argv is None else argv)
    parser = argparse.ArgumentParser(prog="wam-privacy-wallet")
    parser.add_argument("--offline-review", action="store_true")
    parser.add_argument("--mode", choices=("regtest",))
    args = parser.parse_args(values[1:])
    if args.offline_review and args.mode is not None:
        parser.error("--offline-review and --mode are mutually exclusive")
    if QApplication.instance() is not None:
        raise RuntimeError("A Qt application already exists in this process")
    app = QApplication(values[:1])
    app.setApplicationName("WAM Privacy Wallet")
    window = MainWindow() if args.offline_review else RegtestWindow()
    if args.mode == "regtest":
        window.controller.select_regtest()
    window.show()
    return int(app.exec())
