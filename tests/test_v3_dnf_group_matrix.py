import copy
import pathlib
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).parents[1]/"tools"))
from v3_dnf_group_matrix import matrix
from v3_promotion_planner import PlanningError

def p(name,arch):
    return {"nevra":f"{name}-0:1.2-3.fc44.{arch}","architecture":arch,
            "filename":f"{name}-1.2-3.fc44.{arch}.rpm",
            "producer_artifact_sha256":"a"*64,"producer_manifest_digest":"b"*64,
            "published_signed_artifact_sha256":"c"*64}
REG={"producers":[{"components":[{"component":"dolphin","promotion_group":"ro-kde-dolphin",
     "package_names":["dolphin","dolphin-libs","dolphin-devel"],"architectures":["x86_64"]},
     {"component":"assist","promotion_group":"ro-assist","package_names":["ro-assist"],"architectures":["x86_64","aarch64"]},
     {"component":"branding","promotion_group":"branding","package_names":["branding"],"architectures":["noarch"]}]}]}
def plan(packages,group):
    return {"publishable":False,"promotion_group":group,"candidate_sha256":"a"*64,
            "selected_group_packages":packages,"resulting_stable_packages":packages}
class MatrixTests(unittest.TestCase):
    def test_atomic_dolphin_three_binary_packages(self):
        items=[p(n,"x86_64") for n in ("dolphin","dolphin-libs","dolphin-devel")]
        out=matrix(plan(items,"ro-kde-dolphin"),REG,"x86_64")
        self.assertEqual(len(out["binary_packages"]),3)
        self.assertFalse(out["dnf_executed"])
    def test_missing_subpackage_rejected(self):
        with self.assertRaisesRegex(PlanningError,"incomplete"):
            matrix(plan([p("dolphin","x86_64")],"ro-kde-dolphin"),REG,"x86_64")
    def test_cross_group_rejected(self):
        with self.assertRaisesRegex(PlanningError,"cross-group"):
            matrix(plan([p("ro-assist","x86_64")],"ro-kde-dolphin"),REG,"x86_64")
    def test_noarch_available_to_both_arches(self):
        x=plan([p("branding","noarch")],"branding")
        self.assertEqual(matrix(x,REG,"aarch64")["binary_packages"][0]["arch"],"noarch")
        self.assertEqual(matrix(x,REG,"x86_64")["binary_packages"][0]["arch"],"noarch")
    def test_target_architecture_must_exist(self):
        with self.assertRaisesRegex(PlanningError,"no binary"):
            matrix(plan([p("ro-assist","x86_64")],"ro-assist"),REG,"aarch64")
    def test_selected_not_in_result_rejected(self):
        x=plan([p("ro-assist","x86_64")],"ro-assist")
        x["resulting_stable_packages"]=[]
        with self.assertRaisesRegex(PlanningError,"missing from"):
            matrix(x,REG,"x86_64")
    def test_extraneous_arch_candidate_does_not_hide_missing_target(self):
        x=plan([p("dolphin","aarch64"),p("dolphin","x86_64")],"ro-kde-dolphin")
        with self.assertRaises(PlanningError):
            matrix(x,REG,"x86_64")
if __name__=="__main__":
    unittest.main()
