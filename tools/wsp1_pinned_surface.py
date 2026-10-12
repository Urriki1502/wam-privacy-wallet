"""Compatibility CLI; source qualification lives in the installed wallet package."""
from wam_privacy_wallet.integrations.wsp1_source_review import (
    PINNED_COMMIT,
    WspSourceReviewError,
    verify_pinned_wsp1_sources,
    main,
    _git_blob_sha,
    _inspect_one,
    _PINNED,
    _EXPECTED_SCAN_CALLS,
    _REQUIRED_METHODS,
    _MAX_FILE,
)

if __name__ == "__main__":
    raise SystemExit(main())
