"""Frozen PySide6 REGTEST GUI entrypoint. No mock backend or Core launcher."""
from wam_privacy_wallet.gui.app import main

if __name__ == "__main__":
    raise SystemExit(main())
