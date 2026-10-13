"""V1 diagram governance regression (read-only, never wallet authorization)."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from tools.architecture_v1_gate import (
    ArchitectureV1Error, audit_checked_in_v1, audit_v1_traceability,
)

_MANIFEST = Path(__file__).resolve().parents[1] / "docs" / "ARCHITECTURE_V1_TRACEABILITY.json"


class V1ArchitectureTraceabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = json.loads(_MANIFEST.read_text(encoding="utf-8"))

    def denied(self, value):
        with self.assertRaisesRegex(
            ArchitectureV1Error, "^ARCHITECTURE_V1_TRACEABILITY_DENIED$",
        ):
            audit_v1_traceability(value)

    def test_diagram_all_14_boxes_and_19_dependencies_are_pinned(self):
        result = audit_checked_in_v1()
        self.assertEqual(result["status"], "ARCHITECTURE_V1_REVIEW_ONLY")
        self.assertEqual((result["nodes"],result["edges"]), (14,19))
        self.assertEqual(
            {x["id"] for x in self.raw["nodes"]},
            {"user","ui","application","wsp1","scanner","signer",
             "recovery","payjoin","disclosure","network","rpc","core",
             "assurance","ci"},
        )

    def test_no_live_wallet_or_core_execution_authority_even_if_claimed(self):
        checked = audit_checked_in_v1()
        for name in ("operational_wallet_enabled","core_execution_allowed",
                     "mainnet_allowed","release_qualified"):
            self.assertIs(checked[name], False)
        for name in ("operational_wallet_enabled","mainnet_allowed",
                     "signed_core_launch_allowed"):
            fake=deepcopy(self.raw)
            fake[name]=True
            self.denied(fake)

    def test_unmerged_external_modules_never_mislabeled_as_integrated(self):
        for node in self.raw["nodes"]:
            if node["id"] in ("wsp1","scanner","signer","recovery","assurance"):
                self.assertEqual(node["status"],"EXTERNAL_REVIEW_GATED")
            if node["id"] in ("payjoin","network"):
                self.assertEqual(node["status"],"OFFLINE_REVIEW_INTEGRATED")
        for target in ("wsp1","payjoin","network","disclosure","core"):
            fake=deepcopy(self.raw)
            next(x for x in fake["nodes"] if x["id"]==target)["status"]="PRODUCTION_READY"
            self.denied(fake)

    def test_wrong_repository_or_file_cannot_launder_provenance(self):
        repo_root = _MANIFEST.parents[1]
        for item in self.raw["nodes"]:
            if item["repository"] == "Urriki1502/wam-privacy-wallet":
                self.assertTrue((repo_root/item["path"]).is_file(),item["id"])
        for key,value in (("repository","attacker/fork"),
                          ("path","../../home/user/.cookie")):
            fake=deepcopy(self.raw)
            next(x for x in fake["nodes"] if x["id"]=="wsp1")[key]=value
            self.denied(fake)

    def test_dependency_graph_rejects_removed_or_injected_authority_edge(self):
        base=deepcopy(self.raw)
        base["edges"].pop()
        self.denied(base)
        fake=deepcopy(self.raw)
        fake["edges"][0]={"from":"core","to":"signer"}
        self.denied(fake)
        duplicate=deepcopy(self.raw)
        duplicate["edges"][-1]=duplicate["edges"][0]
        self.denied(duplicate)

    def test_blockers_exactly_pin_core_wsp_and_elf_review_gates(self):
        gates={(x["id"],x.get("issue",x.get("pr"))) for x in self.raw["blockers"]}
        self.assertEqual(gates,{
            ("CORE-PROCESS",36),("CORE-GNU-STACK",86),
            ("CORE-ELF-HOLD",84),("CORE-REAL-TWO-NODE",9),
            ("WSP-QUALIFICATION",3),
        })
        fake=deepcopy(self.raw)
        next(x for x in fake["blockers"] if x["id"]=="WSP-QUALIFICATION")["pr"]=999
        self.denied(fake)
        wrong_type=deepcopy(self.raw)
        target=next(x for x in wrong_type["blockers"] if x["id"]=="CORE-ELF-HOLD")
        target["issue"]=target.pop("pr")
        self.denied(wrong_type)

    def test_privacy_review_status_never_becomes_operational_acceptance(self):
        expected={"payjoin":"OFFLINE_REVIEW_INTEGRATED","network":"OFFLINE_REVIEW_INTEGRATED","disclosure":"LOCAL_EXPORT_REVIEW_ONLY"}
        for name,status in expected.items():
            self.assertEqual(next(x for x in self.raw["nodes"] if x["id"]==name)["status"],status)
            fake=deepcopy(self.raw)
            next(x for x in fake["nodes"] if x["id"]==name)["status"]="OPERATIONAL_ACCEPTED"
            self.denied(fake)
        self.assertFalse(audit_checked_in_v1()["operational_wallet_enabled"])

    def test_privacy_targets_pin_application_boundaries_not_shielded_source(self):
        targets={"payjoin":"payjoin_proposal_review.py","network":"network_plan_review.py","disclosure":"selected_history_export.py"}
        for name,path in targets.items():
            node=next(x for x in self.raw["nodes"] if x["id"]==name)
            self.assertEqual(node["repository"],"Urriki1502/wam-privacy-wallet")
            self.assertEqual(node["path"],"src/wam_privacy_wallet/application/"+path)
            fake=deepcopy(self.raw)
            target=next(x for x in fake["nodes"] if x["id"]==name)
            target["repository"]="Urriki1502/wam-privacy"
            target["path"]="prototypes/shielded_notes/viewing.py"
            self.denied(fake)


if __name__ == "__main__":
    unittest.main()
