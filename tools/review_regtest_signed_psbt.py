"""Manual TTY-only review of PSBT output from separate offline WSP signer."""
import argparse
import getpass
import json
from pathlib import Path
import sys
from wam_privacy_wallet.application.offline_signed_psbt_review import (
    review_signed_regtest_psbt, SignedPsbtReviewError,
)

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="REGTEST signed PSBT verification only; NEVER broadcasts")
    parser.add_argument("--wsp-source-root", type=Path, required=True)
    parser.add_argument("--encrypted-request", type=Path, required=True)
    parser.add_argument("--signed-psbt", type=Path, required=True)
    parser.add_argument("--request-sha256", required=True)
    parser.add_argument("--explicit-review", action="store_true")
    opts = parser.parse_args(argv)
    try:
        if not sys.stdin.isatty() or not opts.explicit_review:
            raise SignedPsbtReviewError("SIGNED_PSBT_CONSENT_DENIED")
        pwd = getpass.getpass("Disposable encrypted request passphrase: ").encode()
        receipt = review_signed_regtest_psbt(
            opts.wsp_source_root, opts.encrypted_request, opts.signed_psbt,
            pwd, expected_request_sha256=opts.request_sha256,
            user_consented=True)
    except (ValueError, EOFError, KeyboardInterrupt):
        print("SIGNED_PSBT_REVIEW_DENIED", file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
