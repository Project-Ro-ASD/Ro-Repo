import copy
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).parents[1]/"tools"))
from v3_dnf_transaction_inputs import transaction_inputs
from v3_promotion_planner import PlanningError

def item(name):
    return {"name":name,"nevra":f"{name}-0:2.0-1.fc44.x86_64","filename":f"{name}-2.0-1.fc44.x86_64.rpm",
            "arch":"x86_64","epoch":"0","version":"2.0","release":"1.fc44"}

def rpm_probe(path):
    filename=pathlib.Path(path).name
    name=filename.split("-1.0-")[0]
    return [name,"0","1.0","1.fc44","x86_64"]

class DnfInputs(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=pathlib.Path(self.temp.name)
        for name in ("dolphin","dolphin-libs","dolphin-devel"):
            (self.root/f"{name}-1.0-1.fc44.x86_64.rpm").write_bytes(b"fixture")
        self.matrix={"scope":"offline-v3-dnf-matrix-untrusted","publishable":False,"dnf_executed":False,
                     "promotion_group":"ro-kde-dolphin","target_arch":"x86_64",
                     "binary_packages":[item(name) for name in ("dolphin","dolphin-libs","dolphin-devel")]}
    def tearDown(self):
        self.temp.cleanup()
    def run_matrix(self):
        with patch("v3_dnf_transaction_inputs.rpm_header",side_effect=rpm_probe):
            return transaction_inputs(self.matrix,self.root)
    def test_atomic_three_package_group(self):
        result=self.run_matrix()
        self.assertEqual(len(result["candidate_targets"]),3)
        self.assertEqual(len(result["baseline_targets"]),3)
        self.assertFalse(result["publishable"])
        self.assertEqual(result["expected_candidate_evr"]["dolphin"],"0:2.0-1.fc44")
    def test_missing_baseline_rejected(self):
        (self.root/"dolphin-devel-1.0-1.fc44.x86_64.rpm").unlink()
        with self.assertRaisesRegex(PlanningError,"set must match"):
            self.run_matrix()
    def test_extra_baseline_rejected(self):
        (self.root/"rogue-1.0-1.fc44.x86_64.rpm").write_bytes(b"rogue")
        with self.assertRaises(PlanningError):
            self.run_matrix()
    def test_wrong_baseline_group_name_rejected(self):
        original=self.root/"dolphin-libs-1.0-1.fc44.x86_64.rpm"
        original.rename(self.root/"rogue-1.0-1.fc44.x86_64.rpm")
        with self.assertRaisesRegex(PlanningError,"unknown/duplicate"):
            self.run_matrix()
    def test_untrusted_malformed_matrix_rejected(self):
        self.matrix["publishable"]=True
        with self.assertRaises(PlanningError):
            self.run_matrix()
    def test_duplicate_transaction_candidate_rejected(self):
        self.matrix["binary_packages"].append(copy.deepcopy(self.matrix["binary_packages"][0]))
        with self.assertRaisesRegex(PlanningError,"duplicate"):
            self.run_matrix()
    def test_reject_baseline_same_version(self):
        def equal_version(path):
            result=rpm_probe(path)
            if result[0]=="dolphin":
                result[2]="2.0"
            return result
        with patch("v3_dnf_transaction_inputs.rpm_header",side_effect=equal_version):
            with self.assertRaisesRegex(PlanningError,"same version"):
                transaction_inputs(self.matrix,self.root)
if __name__=="__main__":
    unittest.main()
