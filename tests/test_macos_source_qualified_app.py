"""macOS scanner integration negative contracts; no real keys or Core daemon."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import qualified_scan_session as app
from tools import ci_macos_source_qualified_app as native


class MacosQualifiedAppBoundaryTests(unittest.TestCase):
    def test_non_mac_optional_runtime_cannot_verify_or_import_source(self):
        for platform in ("linux", "win32", "unknown"):
            with (self.subTest(platform=platform),
                  patch.object(app.sys, "platform", platform),
                  patch.object(app, "verify_wsp1_full_source_closure") as source):
                with self.assertRaisesRegex(app.QualifiedScanError,
                                            "^APP_QUALIFIED_SCAN_MACOS_PLATFORM_DENIED$"):
                    app.SourceQualifiedScanRuntime(
                        Path.cwd().resolve(), user_consented=True,
                        macos_disposable=True,
                    )
                source.assert_not_called()

    def test_boolean_sentinel_and_consent_cannot_be_bypassed(self):
        with patch.object(app, "verify_wsp1_full_source_closure") as source:
            for flag in (1, "true", None, object()):
                with self.subTest(flag=type(flag).__name__), self.assertRaisesRegex(
                    app.QualifiedScanError, "^APP_QUALIFIED_SCAN_MACOS_SCOPE_DENIED$"
                ):
                    app.SourceQualifiedScanRuntime(
                        Path.cwd().resolve(), user_consented=True,
                        macos_disposable=flag,
                    )
            with self.assertRaisesRegex(
                    app.QualifiedScanError, "^APP_QUALIFIED_SCAN_SCOPE_DENIED$"):
                app.SourceQualifiedScanRuntime(
                    Path.cwd().resolve(), user_consented=False,
                    macos_disposable=True,
                )
            source.assert_not_called()

    def test_macos_checkpoint_restore_remains_explicitly_denied(self):
        runtime = object.__new__(app.SourceQualifiedScanRuntime)
        runtime._macos_disposable = True
        with self.assertRaisesRegex(app.QualifiedScanError,
                                    "^APP_QUALIFIED_SCAN_MACOS_RESTORE_UNQUALIFIED$"):
            runtime.restore(Path.cwd().resolve(), b"disposable-password", user_consented=True)

    def test_native_positive_requires_real_darwin_arm64_before_source_checks(self):
        with patch.object(native.sys, "platform", "linux"), \
             patch.object(native, "SourceQualifiedScanRuntime") as runtime:
            with self.assertRaisesRegex(RuntimeError,
                                        "^MACOS_APP_NATIVE_PLATFORM_DENIED$"):
                native.run(Path.cwd().resolve())
            runtime.assert_not_called()


if __name__ == "__main__":
    unittest.main()
