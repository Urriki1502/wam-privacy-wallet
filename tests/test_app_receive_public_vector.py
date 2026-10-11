"""Public-only WSP-1 Receive reference tests; never derive a wallet address."""
from __future__ import annotations

import dataclasses
from hashlib import sha1, sha256
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from wam_privacy_wallet.application import receive_vector as rv


class OfflinePublicReceiveVectorTests(unittest.TestCase):
    def deny(self, sample, **options):
        with self.assertRaisesRegex(
            rv.ReceiveVectorError, "^APP_RECEIVE_PUBLIC_VECTOR_DENIED$"
        ):
            rv.inspect_pinned_public_vector(sample, **options)

    def test_pinned_public_example_yields_a_no_authority_preview(self):
        item = rv.inspect_pinned_public_vector()
        self.assertEqual(
            item,
            rv.ReceiveVectorPreview(
                "WSP-1", "regtest", "PIN_RECORDED_UNATTESTED",
                "PUBLIC_SYNTHETIC_FIXTURE",
                rv._FIXED_FINGERPRINT, "BLOCKED", "BLOCKED", "BLOCKED",
            ),
        )
        self.assertEqual(len(item.fingerprint), 16)
        self.assertEqual(item.fingerprint,
                         sha256(rv._PUBLIC_ONLY_VECTOR.encode("ascii")).hexdigest()[:16])

    def test_preview_is_immutable_with_no_address_or_key_capabilities(self):
        item = rv.inspect_pinned_public_vector()
        self.assertFalse(hasattr(item, "__dict__"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            item.receive = "READY"
        for name in (
            "address", "qr", "copy", "wallet", "account", "seed", "scan_private",
            "spend_private", "rpc", "client", "sign", "broadcast", "payments",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(item, name))
        self.assertNotIn(rv._PUBLIC_ONLY_VECTOR, repr(item))

    def test_source_identity_pins_and_vendored_codec_are_exact(self):
        self.assertEqual(rv.UPSTREAM_REPOSITORY, "Urriki1502/wam-silent-payments")
        self.assertEqual(rv.UPSTREAM_COMMIT_SHA,
                         "ac55f13423620252bdbf848c7e8a280c3b84721e")
        self.assertEqual(rv.UPSTREAM_VECTOR_PATH, "tests/vectors/wsp1-wallet.json")
        self.assertEqual(rv.UPSTREAM_VECTOR_BLOB_SHA,
                         "67c77f1c60ed574d81e20147689d9fafc8797991")
        self.assertEqual(rv.UPSTREAM_CODEC_PATH, "src/wam_sp/codec.py")
        self.assertEqual(rv.UPSTREAM_CODEC_BLOB_SHA,
                         "ec28511113f055ce587f3bfabcd97608a3dfed56")
        raw = rv._CODEC_FILE.read_bytes()
        self.assertEqual(
            sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest(),
            rv.UPSTREAM_CODEC_BLOB_SHA,
        )

    def test_research_codec_is_lf_pinned_for_cross_platform_checkout(self):
        root = Path(__file__).resolve().parents[1]
        attrs = (root / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn(
            "src/wam_privacy_wallet/research_models/wsp_public/codec.py text eol=lf",
            attrs.splitlines(),
        )
        self.assertEqual(rv._CODEC_FILE.read_bytes().count(b"\r\n"), 0)

    def test_wrong_network_or_unapproved_source_version_is_denied(self):
        sample = rv._PUBLIC_ONLY_VECTOR
        for value in ("mainnet", "testnet", "REGTEST", "wamrtsp", "", None, True, 1):
            with self.subTest(network=value):
                self.deny(sample, network=value)
        for value in ("0" * 40, "APPROVED", "", None, True, 42):
            with self.subTest(source=value):
                self.deny(sample, source_commit=value)

    def test_wrong_hrp_and_malformed_syntactic_addresses_are_denied(self):
        sample = rv._PUBLIC_ONLY_VECTOR
        for value in (
            sample.replace("wamrtsp1", "wamsp1", 1),
            "sp" + sample[len("wamrtsp"):],
            "regtest:" + sample, "", "wamrtsp1",
            sample[:16], sample + "x", " " + sample,
            sample.upper(), sample[:9].upper() + sample[9:],
        ):
            with self.subTest(value=str(value)[:24]):
                self.deny(value)

    def test_checksum_mutation_and_arbitrary_long_text_denied(self):
        sample = rv._PUBLIC_ONLY_VECTOR
        for value in (sample[:-1] + ("q" if sample[-1] != "q" else "p"),
                      sample[:-2] + "00",
                      "wamrtsp1" + "q" * 2048):
            self.deny(value)

    def test_nonstring_inputs_and_str_subclasses_denied(self):
        class PseudoAddress(str):
            pass

        for value in (None, {}, [], (), True, 123,
                      bytearray(b"wamrtsp"), object(),
                      PseudoAddress(rv._PUBLIC_ONLY_VECTOR)):
            with self.subTest(kind=type(value).__name__):
                self.deny(value)

    def test_missing_codec_bytes_fails_closed_before_import(self):
        with tempfile.TemporaryDirectory(prefix="wsp-vector-") as tmp:
            missing = Path(tmp) / "absent.py"
            with patch.object(rv, "_CODEC_FILE", missing):
                self.deny(rv._PUBLIC_ONLY_VECTOR)

    def test_changed_codec_bytes_fail_closed_without_execution(self):
        with tempfile.TemporaryDirectory(prefix="wsp-vector-") as tmp:
            counterfeit = Path(tmp) / "codec.py"
            counterfeit.write_text("raise RuntimeError('SHOULD_NOT_EXECUTE')\n",
                                   encoding="utf-8")
            with patch.object(rv, "_CODEC_FILE", counterfeit):
                self.deny(rv._PUBLIC_ONLY_VECTOR)

    def test_bad_decoded_payload_shape_denied(self):
        from wam_privacy_wallet.research_models.wsp_public import codec
        bad_payloads = (
            b"", b"\x02" * 65, b"\x04" + b"\x02" * 65,
            b"\x02" * 33 + b"\x04" + b"\x02" * 32,
            "not bytes", None,
        )
        for value in bad_payloads:
            with self.subTest(kind=type(value).__name__, size=len(value) if value else 0):
                with patch.object(codec, "decode", return_value=value):
                    self.deny(rv._PUBLIC_ONLY_VECTOR)

    def test_public_example_never_imports_keys_scanner_or_wam_core(self):
        item = rv.inspect_pinned_public_vector()
        self.assertEqual(item.scanner, "BLOCKED")
        self.assertEqual(item.signer, "BLOCKED")
        self.assertEqual(item.receive, "BLOCKED")
        import sys
        for name in ("wam_sp.scanner", "wam_sp.api", "wam_sp.signer",
                     "wam_sp.keystore", "wam_core"):
            self.assertNotIn(name, sys.modules)
        self.assertNotIn("000102030405060708090a0b0c0d0e0f", repr(item))
        self.assertNotIn("private", repr(item).lower())


if __name__ == "__main__":
    unittest.main()
