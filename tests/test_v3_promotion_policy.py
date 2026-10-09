import pathlib
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_promotion_policy import PlanningError, evaluate, first_seen

C = {"promotion_group": "ro-assist", "candidate_sha256": "a" * 64}
D = {"promotion_group": "ro-kde-dolphin", "candidate_sha256": "b" * 64}
def record(run, when, candidate=C):
    return {"publication_run": str(run), "published_at": when,
            "promotion_group": candidate["promotion_group"],
            "candidate_sha256": candidate["candidate_sha256"]}
H = [record(10, "2026-09-21T12:00:00Z"), record(11, "2026-10-09T13:19:15Z"),
     record(12, "2026-10-09T13:19:15Z", D)]

class PolicyTests(unittest.TestCase):
    def test_new_snapshot_does_not_reset_dwell(self):
        answer = evaluate(C, H, "normal-app", "normal", "2026-10-09T17:00:00Z")
        self.assertEqual(answer["first_publication_run"], "10")
        self.assertEqual(answer["earliest_normal_promotion"], "2026-09-28T12:00:00Z")
        self.assertTrue(answer["ready_for_review"])
        self.assertFalse(answer["publishable"])
    def test_unrelated_dolphin_publication_does_not_change_candidate(self):
        self.assertEqual(first_seen(C, H, "2026-10-09T17:00:00Z"),
                         first_seen(C, H[:-1], "2026-10-09T17:00:00Z"))
    def test_critical_system_waits_14_days(self):
        x = evaluate(D, H, "critical-system", "normal", "2026-10-10T13:19:15Z")
        self.assertEqual(x["minimum_beta_days"], 14)
        self.assertFalse(x["ready_for_review"])
    def test_fast_track_skips_only_dwell(self):
        x = evaluate(D, H, "critical-desktop", "fast-track", "2026-10-09T17:00:00Z", reason="  Store E2E  ")
        self.assertTrue(x["ready_for_review"])
        self.assertTrue(x["dwell_exception_requested"])
        self.assertEqual(x["reason"], "Store E2E")
        self.assertFalse(x["approval_granted"])
        self.assertFalse(x["test_evidence_verified"])
        self.assertFalse(x["publishable"])
    def test_fast_track_requires_reason(self):
        with self.assertRaises(PlanningError):
            evaluate(C, H, "normal-app", "fast-track", "2026-10-09T17:00:00Z")
    def test_unknown_candidate_fails_closed(self):
        with self.assertRaises(PlanningError):
            first_seen({"promotion_group":"missing","candidate_sha256":"c"*64},H,"2026-10-09T17:00:00Z")
    def test_future_and_duplicate_publications_rejected(self):
        for records in ([record(1,"2026-11-01T00:00:00Z")], [H[0],H[0]]):
            with self.assertRaises(PlanningError):
                first_seen(C,records,"2026-10-09T17:00:00Z")
    def test_malformed_history_rejected(self):
        bad = dict(H[0])
        bad["candidate_sha256"] = "invalid"
        with self.assertRaises(PlanningError):
            first_seen(C,[bad],"2026-10-09T17:00:00Z")
    def test_same_group_changed_digest_has_independent_clock(self):
        newer = {"promotion_group":"ro-assist","candidate_sha256":"d"*64}
        x = evaluate(newer,H+[record(15,"2026-10-09T16:00:00Z",newer)],
                     "normal-app","normal","2026-10-09T17:00:00Z")
        self.assertFalse(x["dwell_met"])
        self.assertEqual(x["first_publication_run"],"15")

if __name__=="__main__":
    unittest.main()
