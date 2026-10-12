"""Compatibility CLI; source qualification lives in the installed wallet package."""
from wam_privacy_wallet.integrations.wsp1_source_closure import (
    PINNED_COMMIT,
    WspFullSourceError,
    verify_wsp1_full_source_closure,
    main,
    _REQUIRED_PY,
    _REQUIRED_DEPS,
    _git,
    _MAX_TREE_BYTES,
    _MAX_PACKAGE_FILES,
    _MAX_SINGLE_FILE,
)

if __name__ == "__main__":
    raise SystemExit(main())
