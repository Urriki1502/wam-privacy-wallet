"""Offline security assertions: UI projections confer no capabilities."""
from __future__ import annotations

import dataclasses
import unittest

from wam_privacy_wallet.application.node_status import (
    DiagnosticBoundaryError,
    NodeOverview,
    node_overview,
)
from wam_privacy_wallet.node.attestation import ChainIdentity, WAM_REGTEST_GENESIS
from wam_privacy_wallet.node.core_profile import VerifiedCoreProfile
from wam_privacy_wallet.node.endpoint import LocalRegtestEndpoint


class ApplicationDiagnosticTests(unittest.TestCase):
    @staticmethod
    def profile(*, genesis=WAM_REGTEST_GENESIS, height=1, headers=1, pruned=False):
        identity = ChainIdentity(
            endpoint=LocalRegtestEndpoint("127.0.0.1", 29554),
            genesis=genesis, height=height, best_block_hash="a" * 64,
        )
        return VerifiedCoreProfile(identity=identity, headers=headers, pruned=pruned)

    def test_projection_cannot_authorize_or_retain_rpc_state(self):
        value = node_overview(self.profile())
        self.assertEqual(
            value,
            NodeOverview("regtest", 1, "READ_ONLY_SNAPSHOT", "EXPERIMENTAL_NO_REAL_FUNDS"),
        )
        self.assertEqual(
            tuple(x.name for x in dataclasses.fields(value)),
            ("network", "height", "status", "notice"),
        )
        for name in ("rpc", "endpoint", "auth", "sign", "scan",
                     "approve", "broadcast", "key", "wallet"):
            self.assertFalse(hasattr(value, name))
        self.assertNotIn("127.0.0.1", repr(value))
        self.assertNotIn("29554", repr(value))

    def test_diagnostic_record_is_immutable(self):
        value = node_overview(self.profile())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            value.height = 99

    def test_malformed_untrusted_profile_fails_closed(self):
        for item in (None, {}, [], True, object(), "regtest", 1):
            with self.subTest(type=type(item).__name__):
                with self.assertRaisesRegex(
                    DiagnosticBoundaryError, "^APP_NODE_PROFILE_REQUIRED$"
                ):
                    node_overview(item)

    def test_wrong_network_or_stale_inconsistent_profile_rejected(self):
        for kwargs in (
            {"genesis": "b" * 64},
            {"height": True}, {"height": -1},
            {"height": 3, "headers": 2}, {"pruned": True},
        ):
            with self.subTest(case=kwargs):
                with self.assertRaisesRegex(
                    DiagnosticBoundaryError, "^APP_NODE_PROFILE_INVALID$"
                ):
                    node_overview(self.profile(**kwargs))

    def test_projection_contains_no_secret_derived_or_network_state(self):
        value = node_overview(self.profile(height=22, headers=23))
        self.assertEqual(value.height, 22)
        self.assertFalse(hasattr(value, "__dict__"))
        self.assertEqual(value.network, "regtest")
        self.assertNotIn(WAM_REGTEST_GENESIS, repr(value))


if __name__ == "__main__":
    unittest.main()
