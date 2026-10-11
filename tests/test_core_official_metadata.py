"""Fail-closed regression matrix for official HTTPS metadata / signed archive CLI.

Network fakes here test denial and fetch boundaries; they are NOT genuine
publisher evidence. Real operational path uses system-TLS HTTPS + real GnuPG.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from wam_privacy_wallet.node import core_official_metadata as metadata
from wam_privacy_wallet.node.core_signed_release import CoreReleaseSignatureError
from tools import verify_core_release_official as cli

ARCHIVE = str(Path.cwd() / "wam-coin-v0.1.11-arm64-apple-darwin.tar.gz")
GPG = str(Path.cwd() / "verified-system-gnupg")


class _Response:
    def __init__(self, *, status=200, body=b"X", headers=None):
        self.status = status
        self.body = body
        self.headers = headers or {}

    def getheader(self, name):
        return self.headers.get(name)

    def read(self, limit):
        return self.body[:limit]


class _Connection:
    def __init__(self, response):
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, method, path, *, headers):
        self.requests.append((method, path, headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class OfficialMetadataHttpsTests(unittest.TestCase):
    def _http(self, response):
        connection = _Connection(response)
        context = object()
        provider = patch.object(metadata.http.client, "HTTPSConnection",
                                return_value=connection)
        tls = patch.object(metadata.ssl, "create_default_context",
                           return_value=context)
        return connection, context, provider, tls

    def test_genuine_transport_contract_pins_hostname_path_and_tls_context(self):
        conn, context, provider, tls = self._http(_Response(body=b"real-bounded-bytes"))
        with provider as create, tls as mk:
            result = metadata._fetch_fixed_asset("/SIGNING-KEY.asc", 32768)
        self.assertEqual(result, b"real-bounded-bytes")
        self.assertEqual(create.call_args.args, ("wamcoin.org",))
        self.assertIs(create.call_args.kwargs["context"], context)
        self.assertEqual(mk.call_count, 1)
        self.assertEqual(conn.requests[0][0:2], ("GET", "/SIGNING-KEY.asc"))
        self.assertEqual(conn.requests[0][2]["Accept-Encoding"], "identity")
        self.assertTrue(conn.closed)

    def test_arbitrary_url_and_size_override_denied_before_network(self):
        conn, _, provider, tls = self._http(_Response())
        with provider as create, tls:
            for path, maximum in (
                ("https://evil.invalid/SHA256SUMS", 131072),
                ("//evil.invalid/SHA256SUMS", 131072),
                ("/downloads/v0.1.12/SHA256SUMS", 131072),
                ("/SIGNING-KEY.asc", 131072),
            ):
                with self.subTest(path=path), self.assertRaisesRegex(
                    metadata.OfficialMetadataError, "^CORE_OFFICIAL_REQUEST_DENIED$",
                ):
                    metadata._fetch_fixed_asset(path, maximum)
        create.assert_not_called()

    def test_timeout_bool_zero_negative_and_large_denied_without_io(self):
        conn, _, provider, tls = self._http(_Response())
        with provider as create, tls:
            for timeout in (True, 0, -1, 16, float("inf"), float("nan")):
                with self.subTest(timeout=timeout), self.assertRaises(
                    metadata.OfficialMetadataError,
                ):
                    metadata._fetch_fixed_asset("/SIGNING-KEY.asc", 32768, timeout=timeout)
        create.assert_not_called()

    def test_no_http_redirects_or_untrusted_origin_fallback(self):
        for code in (301, 302, 303, 307, 308):
            conn, _, provider, tls = self._http(
                _Response(status=code, headers={"Location": "https://evil.invalid/"})
            )
            with self.subTest(code=code), provider, tls, self.assertRaisesRegex(
                metadata.OfficialMetadataError, "^CORE_OFFICIAL_HTTP_DENIED$",
            ):
                metadata._fetch_fixed_asset("/SIGNING-KEY.asc", 32768)
            self.assertTrue(conn.closed)

    def test_bad_http_status_is_never_treated_as_signed_bytes(self):
        conn, _, provider, tls = self._http(_Response(status=404))
        with provider, tls, self.assertRaisesRegex(
            metadata.OfficialMetadataError, "^CORE_OFFICIAL_HTTP_DENIED$",
        ):
            metadata._fetch_fixed_asset("/SIGNING-KEY.asc", 32768)

    def test_content_length_over_limit_and_malformed_denied(self):
        for header in ("99999999", "1.5", "-5", "1e9", " 30", "9999999999999"):
            conn, _, provider, tls = self._http(
                _Response(body=b"x", headers={"Content-Length": header})
            )
            with self.subTest(header=header), provider, tls, self.assertRaisesRegex(
                metadata.OfficialMetadataError, "^CORE_OFFICIAL_SIZE_DENIED$",
            ):
                metadata._fetch_fixed_asset("/SIGNING-KEY.asc", 32768)

    def test_oversized_stream_without_content_length_rejected(self):
        conn, _, provider, tls = self._http(_Response(body=b"a" * 32769))
        with provider, tls, self.assertRaisesRegex(
            metadata.OfficialMetadataError, "^CORE_OFFICIAL_SIZE_DENIED$",
        ):
            metadata._fetch_fixed_asset("/SIGNING-KEY.asc", 32768)

    def test_short_content_length_payload_denied(self):
        conn, _, provider, tls = self._http(
            _Response(body=b"a", headers={"Content-Length": "2"})
        )
        with provider, tls, self.assertRaisesRegex(
            metadata.OfficialMetadataError, "^CORE_OFFICIAL_SIZE_DENIED$",
        ):
            metadata._fetch_fixed_asset("/SIGNING-KEY.asc", 32768)

    def test_compressed_response_rejected_to_avoid_implicit_decompression(self):
        conn, _, provider, tls = self._http(
            _Response(headers={"Content-Encoding": "gzip"})
        )
        with provider, tls, self.assertRaisesRegex(
            metadata.OfficialMetadataError, "^CORE_OFFICIAL_ENCODING_DENIED$",
        ):
            metadata._fetch_fixed_asset("/SIGNING-KEY.asc", 32768)

    def test_empty_response_denied(self):
        conn, _, provider, tls = self._http(_Response(body=b""))
        with provider, tls, self.assertRaisesRegex(
            metadata.OfficialMetadataError, "^CORE_OFFICIAL_SIZE_DENIED$",
        ):
            metadata._fetch_fixed_asset("/SIGNING-KEY.asc", 32768)

    def test_transport_error_is_redacted_and_no_network_fallback(self):
        with patch.object(metadata.http.client, "HTTPSConnection",
                          side_effect=OSError("secret host or credential")):
            with self.assertRaises(metadata.OfficialMetadataError) as caught:
                metadata._fetch_fixed_asset("/SIGNING-KEY.asc", 32768)
        self.assertEqual(str(caught.exception), "CORE_OFFICIAL_TRANSPORT_DENIED")
        self.assertNotIn("secret", str(caught.exception))

    def test_ephemeral_metadata_three_exact_files_and_cleanup(self):
        fake = {
            "/SIGNING-KEY.asc": b"key",
            "/downloads/v0.1.11/SHA256SUMS": b"sums",
            "/downloads/v0.1.11/SHA256SUMS.asc": b"sig",
        }
        with patch.object(metadata, "_fetch_fixed_asset",
                          side_effect=lambda path, maximum: fake[path]) as fetch:
            with metadata.official_release_metadata() as paths:
                self.assertEqual(set(paths), {"key", "checksums", "signature"})
                for label, content in (("key", b"key"), ("checksums", b"sums"),
                                       ("signature", b"sig")):
                    self.assertEqual(paths[label].read_bytes(), content)
                    if os.name != "nt":
                        self.assertEqual(paths[label].stat().st_mode & 0o777, 0o600)
                root = paths["key"].parent
                self.assertTrue(root.is_dir())
            self.assertFalse(root.exists())
        self.assertEqual(fetch.call_count, 3)

    def test_partial_metadata_fetch_failure_cleans_previous_files(self):
        captured = []
        def fetch(path, maximum):
            if captured:
                raise metadata.OfficialMetadataError("CORE_OFFICIAL_HTTP_DENIED")
            captured.append(path)
            return b"first-key"
        with patch.object(metadata, "_fetch_fixed_asset", side_effect=fetch), \
             self.assertRaisesRegex(metadata.OfficialMetadataError,
                                    "^CORE_OFFICIAL_HTTP_DENIED$"):
            with metadata.official_release_metadata():
                self.fail("must not yield partial metadata")
        self.assertEqual(captured, ["/SIGNING-KEY.asc"])


class OfficialReleaseCliTests(unittest.TestCase):
    def _verified(self):
        return {
            "status": "SIGNED_ARCHIVE_REVIEW_ONLY",
            "archive_sha256": "a" * 64,
            "node_sha256": "b" * 64,
            "real_wallet_allowed": False, "core_execution_allowed": False,
            "mainnet_allowed": False, "real_regtest_qualified": False,
        }

    def test_wrong_or_relative_archive_denied_before_fetch(self):
        with patch.object(cli, "official_release_metadata",
                          side_effect=AssertionError("NO_FETCH")):
            for archive in ("untrusted.tar.gz", "https://evil.invalid/x",
                            str(Path.cwd() / "wallet.dat")):
                with self.subTest(archive=archive), self.assertRaises(
                    CoreReleaseSignatureError,
                ):
                    cli.verify_official_release(archive=archive, gpg=GPG)

    def test_valid_official_path_calls_existing_gpg_verifier_without_core_spawn(self):
        class Context:
            def __enter__(self):
                return {"key": Path("/tmp/key"), "checksums": Path("/tmp/sums"),
                        "signature": Path("/tmp/sig")}
            def __exit__(self, *_args):
                return False
        with patch.object(cli, "official_release_metadata", return_value=Context()), \
             patch.object(cli, "qualify_release", return_value=self._verified()) as qualify, \
             patch.object(subprocess, "Popen", side_effect=AssertionError("NO_WAMD")):
            receipt = cli.verify_official_release(archive=ARCHIVE, gpg=GPG)
        self.assertEqual(qualify.call_args.kwargs["gpg"], GPG)
        self.assertEqual(qualify.call_args.kwargs["archive"], ARCHIVE)
        self.assertEqual(receipt["metadata_origin"], "PINNED_WAM_HTTPS_V0_1_11")
        self.assertIs(receipt["core_execution_allowed"], False)
        self.assertIs(receipt["real_regtest_qualified"], False)

    def test_fake_gpg_success_claim_cannot_enable_core_execution(self):
        forged = dict(self._verified(), core_execution_allowed=True)
        with patch.object(cli, "qualify_release", return_value=forged), \
             patch.object(cli, "official_release_metadata") as ctx:
            with self.assertRaisesRegex(
                CoreReleaseSignatureError, "^CORE_RECEIPT_AUTHORITY_DENIED$",
            ):
                cli.verify_official_release(archive=ARCHIVE, gpg=GPG)
        self.assertEqual(ctx.call_count, 1)

    def test_cli_fail_closed_with_fixed_redacted_code_and_no_json(self):
        with patch.object(cli, "official_release_metadata",
                          side_effect=metadata.OfficialMetadataError(
                              "CORE_OFFICIAL_TRANSPORT_DENIED")):
            err, out = io.StringIO(), io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
                status = cli.main(["--archive", ARCHIVE, "--gpg", GPG])
        self.assertEqual(status, 2)
        self.assertEqual(err.getvalue().strip(), "CORE_OFFICIAL_TRANSPORT_DENIED")
        self.assertEqual(out.getvalue(), "")

    def test_cli_success_is_redacted_nonexecuting_json(self):
        with patch.object(cli, "verify_official_release", return_value=self._verified()):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                status = cli.main(["--archive", ARCHIVE, "--gpg", GPG])
        self.assertEqual(status, 0)
        receipt = json.loads(out.getvalue())
        self.assertIs(receipt["mainnet_allowed"], False)
        self.assertNotIn(GPG, out.getvalue())
        self.assertNotIn(ARCHIVE, out.getvalue())


if __name__ == "__main__":
    unittest.main()
