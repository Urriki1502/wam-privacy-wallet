"""Core source profile pin checks: synthetic fixtures only; no HTTP/daemon."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from wam_privacy_wallet.node.attestation import WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.core_source_pin import (
    CoreSourceContractError, git_blob_sha1, load_core_manifest, verify_core_source,
)

PORTS = {
    "mainnet": {"p2p": 9555, "rpc": 9554},
    "testnet": {"p2p": 19555, "rpc": 19554},
    "regtest": {"p2p": 29555, "rpc": 29554},
}
PATHS = ("src/wam/wam-params.h", "src/wam/chainparams.cpp", "scripts/patch_upstream.py")


def fixtures():
    params = "\n".join(
        f"static constexpr int WAM_{network.upper()}_{kind.upper()}_PORT = {value};"
        for network, spec in PORTS.items() for kind, value in spec.items()
    ).encode("ascii")
    chains = (
        "class CMainParams : public CChainParams {\n"
        "  consensus.enforce_BIP94 = false;\n"
        "};\n"
        "class CTestNetParams : public CChainParams {\n"
        "  consensus.enforce_BIP94 = false;\n"
        "};\n"
        "class CRegTestParams : public CChainParams {\n"
        "  consensus.enforce_BIP94 = true;\n"
        f'  assert(consensus.hashGenesisBlock == uint256S("0x{WAM_REGTEST_GENESIS}"));\n'
        "};\n"
    ).encode("ascii")
    patch = b'''replacement='return std::make_unique<CBaseChainParams>("regtest", 29554);'\n'''
    files = dict(zip(PATHS, (params, chains, patch)))
    manifest = {
        "schema": 2, "repository": "wamcoin-core-dev/wam-coin",
        "inspected_commit": "a" * 40, "wsp1_reference_core_commit": "b" * 40,
        "source_blobs": {key: git_blob_sha1(value) for key, value in files.items()},
        "network_ports": PORTS, "regtest_genesis": WAM_REGTEST_GENESIS,
        "consensus_bip94": {"mainnet": False, "testnet": False, "regtest": True},
    }
    return manifest, files


class CorePinTests(unittest.TestCase):
    def test_git_blob_digest_formula(self):
        data = b"test\n"
        digest = hashlib.sha1(b"blob 5\0" + data).hexdigest()
        self.assertEqual(git_blob_sha1(data), digest)

    def test_contract_accepts_exact_source(self):
        manifest, files = fixtures()
        result = verify_core_source(manifest, files)
        self.assertEqual(result["regtest_genesis"], WAM_REGTEST_GENESIS)
        self.assertEqual(result["network_ports"]["regtest"]["rpc"], 29554)

    def test_mutation_is_denied_before_source_parsing(self):
        manifest, files = fixtures()
        for path in PATHS:
            with self.subTest(path=path):
                changed = {**files, path: files[path] + b" "}
                with self.assertRaisesRegex(CoreSourceContractError, "CORE_SOURCE_BLOB_MISMATCH"):
                    verify_core_source(manifest, changed)

    def test_ports_drift_even_if_manifest_blob_updated(self):
        manifest, files = fixtures()
        modified = files[PATHS[0]].replace(b"29554", b"18443")
        changed = {**files, PATHS[0]: modified}
        manifest["source_blobs"][PATHS[0]] = git_blob_sha1(modified)
        with self.assertRaisesRegex(CoreSourceContractError, "CORE_SOURCE_PORT_DRIFT"):
            verify_core_source(manifest, changed)

    def test_genesis_drift_even_if_blob_updated(self):
        manifest, files = fixtures()
        modified = files[PATHS[1]].replace(WAM_REGTEST_GENESIS.encode(), b"0" * 64)
        changed = {**files, PATHS[1]: modified}
        manifest["source_blobs"][PATHS[1]] = git_blob_sha1(modified)
        with self.assertRaisesRegex(CoreSourceContractError, "CORE_SOURCE_GENESIS_DRIFT"):
            verify_core_source(manifest, changed)

    def test_patch_drift_even_if_blob_updated(self):
        manifest, files = fixtures()
        modified = files[PATHS[2]].replace(b"29554", b"18443")
        changed = {**files, PATHS[2]: modified}
        manifest["source_blobs"][PATHS[2]] = git_blob_sha1(modified)
        with self.assertRaisesRegex(CoreSourceContractError, "CORE_SOURCE_RPC_PATCH_DRIFT"):
            verify_core_source(manifest, changed)

    def test_missing_or_extra_source_is_denied(self):
        manifest, files = fixtures()
        with self.assertRaisesRegex(CoreSourceContractError, "CORE_SOURCE_FILE_SET_INVALID"):
            verify_core_source(manifest, {PATHS[0]: files[PATHS[0]]})
        with self.assertRaisesRegex(CoreSourceContractError, "CORE_SOURCE_FILE_SET_INVALID"):
            verify_core_source(manifest, {**files, "evil": b"x"})

    def test_checked_in_manifest_matches_wallet_genesis_and_ports(self):
        path = Path(__file__).resolve().parents[1] / "compat" / "wam_core_source_pin.json"
        config = load_core_manifest(path)
        self.assertEqual(config["regtest_genesis"], WAM_REGTEST_GENESIS)
        self.assertEqual(config["network_ports"]["regtest"], {"p2p": 29555, "rpc": 29554})
        self.assertEqual(config["inspected_commit"], "87ac8f0786fa5bc0796a5cba21e638911078d475")
        self.assertEqual(config["consensus_bip94"], {"mainnet": False, "testnet": False, "regtest": True})
        self.assertEqual(config["wsp1_reference_core_commit"], "8a3f4fe4f1d804c378f795d4cc281ec5125f75f3")

    def test_manifest_rejects_fake_network_and_boolean_port(self):
        manifest, files = fixtures()
        for mutation, code in [
            ({"repository": "bitcoin/bitcoin"}, "CORE_MANIFEST_WRONG_SOURCE"),
            ({"regtest_genesis": "0" * 64}, "CORE_MANIFEST_GENESIS_MISMATCH"),
            ({"network_ports": {**PORTS, "regtest": {"p2p": 29555, "rpc": True}}}, "CORE_MANIFEST_PORT_INVALID"),
        ]:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as d:
                doc = Path(d) / "manifest.json"
                doc.write_text(json.dumps({**manifest, **mutation}), encoding="utf-8")
                with self.assertRaisesRegex(CoreSourceContractError, code):
                    load_core_manifest(doc)

    def test_bip94_wrong_regtest_even_with_rewritten_blob_pin_is_denied(self):
        manifest, files = fixtures()
        changed_bytes = files[PATHS[1]].replace(
            b"consensus.enforce_BIP94 = true;",
            b"consensus.enforce_BIP94 = false;",
        )
        changed = {**files, PATHS[1]: changed_bytes}
        manifest["source_blobs"][PATHS[1]] = git_blob_sha1(changed_bytes)
        with self.assertRaisesRegex(CoreSourceContractError, "^CORE_SOURCE_BIP94_DRIFT$"):
            verify_core_source(manifest, changed)

    def test_bip94_missing_or_duplicate_assignment_is_denied(self):
        for replacement in (b"", b"consensus.enforce_BIP94 = true;\n  consensus.enforce_BIP94 = true;"):
            with self.subTest(replacement=replacement):
                manifest, files = fixtures()
                changed_bytes = files[PATHS[1]].replace(
                    b"consensus.enforce_BIP94 = true;", replacement,
                )
                manifest["source_blobs"][PATHS[1]] = git_blob_sha1(changed_bytes)
                with self.assertRaisesRegex(CoreSourceContractError, "^CORE_SOURCE_BIP94_DRIFT$"):
                    verify_core_source(manifest, {**files, PATHS[1]: changed_bytes})

    def test_bip94_manifest_forgery_denied(self):
        manifest, files = fixtures()
        for invalid in (
            {"mainnet": False, "testnet": False, "regtest": False},
            {"mainnet": 0, "testnet": 0, "regtest": True},
            {"mainnet": False, "testnet": False},
        ):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as d:
                file = Path(d) / "manifest.json"
                file.write_text(json.dumps({**manifest, "consensus_bip94": invalid}))
                with self.assertRaisesRegex(
                    CoreSourceContractError, "^CORE_MANIFEST_BIP94_INVALID$",
                ):
                    load_core_manifest(file)

    def test_bip94_misplaced_assignment_before_network_class_denied(self):
        manifest, files = fixtures()
        changed_bytes = (
            b"consensus.enforce_BIP94 = true;\n" + files[PATHS[1]]
        )
        manifest["source_blobs"][PATHS[1]] = git_blob_sha1(changed_bytes)
        with self.assertRaisesRegex(
            CoreSourceContractError, "^CORE_SOURCE_BIP94_DRIFT$",
        ):
            verify_core_source(manifest, {**files, PATHS[1]: changed_bytes})

    def test_duplicate_ports_denied_even_if_blob_matches(self):
        manifest, files = fixtures()
        modified = files[PATHS[0]] + b"\nstatic constexpr int WAM_REGTEST_RPC_PORT = 29554;\n"
        changed = {**files, PATHS[0]: modified}
        manifest["source_blobs"][PATHS[0]] = git_blob_sha1(modified)
        with self.assertRaisesRegex(CoreSourceContractError, "CORE_SOURCE_PORTS_UNRECOGNIZED"):
            verify_core_source(manifest, changed)


if __name__ == "__main__":
    unittest.main()
