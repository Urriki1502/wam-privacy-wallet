"""Explicit Qt entry point; importing the package never starts a GUI."""

from __future__ import annotations

import sys
import argparse
from collections.abc import Sequence

from PySide6.QtCore import QTimer
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
    parser.add_argument("--self-test-ui", action="store_true",
                        help="Run local Qt REGTEST window smoke and exit; NO Core")
    args = parser.parse_args(values[1:])
    if args.offline_review and args.mode is not None:
        parser.error("--offline-review and --mode are mutually exclusive")
    if args.self_test_ui and (args.mode != "regtest" or args.offline_review):
        parser.error("--self-test-ui requires --mode regtest and no --offline-review")
    if QApplication.instance() is not None:
        raise RuntimeError("A Qt application already exists in this process")
    app = QApplication(values[:1])
    app.setApplicationName("WAM Privacy Wallet")
    window = MainWindow() if args.offline_review else RegtestWindow()
    if args.mode == "regtest":
        window.controller.select_regtest()
    window.show()
    if args.self_test_ui:
        # Packaging only: no RPC, Core execution, scanner or wallet authority.
        def inspect_preview() -> None:
            valid = (
                isinstance(window, RegtestWindow)
                and window.isVisible()
                and window.navigation.count() == 9
                and window.controller.lifecycle.state.mode == "REGTEST"
                and window.controller.lifecycle.state.wallet_operational is False
                and "NO WALLET LOADED" in window.authority_status.text()
                and "BLOCKED" in window.authority_status.text()
                and window.controller.busy is False
            )
            if valid:
                print("NATIVE_REGTEST_GUI_EVENT_LOOP_SMOKE_PASS_NO_CORE", flush=True)
            # Exit the event loop first; closing a Qt window from its timer
            # callback can re-enter QObject teardown in frozen Linux/Win builds.
            # Normal QApplication/window destruction occurs after exec returns.
            app.exit(0 if valid else 3)

        QTimer.singleShot(100, inspect_preview)
    return int(app.exec())
