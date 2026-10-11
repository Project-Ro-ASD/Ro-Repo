import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_beta_evidence_bridge import verify_evidence, REPOSITORY
from v3_promotion_planner import PlanningError
from test_v3_github_beta_audit import fixture


def collection(records):
    return {
        "scope": "v3-github-beta-api-collection-untrusted",
        "repository": REPOSITORY,
        "total_workflow_runs": len(records),
        "successful_runs": len(records),
        "run_details": [r[1] for r in records],
        "job_details": [r[2] for r in records],
        "api_response_immutability_verified": False,
        "archive_completeness_verified": False,
        "publishable": False,
    }


def bundle(records, *, unrelated=()):
    excluded = set(unrelated)
    return {
        "scope": "v3-signed-beta-archive-bundle-untrusted",
        "promotion_group": "ro-assist",
        "signed_publications": [
            {"publication_run": r[0]["publication_run"],
             "published_at": r[0]["published_at"],
             "snapshot_id": "repo-f44-20261001-001",
             "store_tree_sha256": "f" * 64,
             "candidate_sha256": None if r[0]["publication_run"] in excluded
                                 else r[0]["candidate_sha256"]}
            for r in records
        ],
        "candidate_history": [r[0] for r in records
                              if r[0]["publication_run"] not in excluded],
        "archive_completeness_verified": False,
        "trusted_publication_times_verified": False,
        "publishable": False,
    }


class EvidenceBridgeTests(unittest.TestCase):
    def setUp(self):
        self.records = [
            fixture(10, "01", "a" * 64),
            fixture(11, "08", "a" * 64),
        ]
        self.now = "2026-10-10T12:00:00Z"

    def check(self, coll=None, signed=None):
        coll = collection(self.records) if coll is None else coll
        signed = bundle(self.records, unrelated={"10"}) if signed is None else signed
        with patch("v3_beta_evidence_bridge.signed_archive_bundle", return_value=signed) as loader:
            result = verify_evidence(coll, "/signed", "/snapshots", {"producers": []},
                                     "ro-assist", "public.asc", "f"*64, self.now)
            loader.assert_called_once()
            return result

    def test_full_coverage_separate_from_candidate_history(self):
        result = self.check()
        self.assertEqual(result["signed_publications_checked"], 2)
        self.assertEqual(result["matching_candidate_publications"], 1)
        self.assertEqual(result["candidate_remote_verify_times"][0]["publication_run"], "11")
        self.assertFalse(result["archive_completeness_verified"])
        self.assertFalse(result["metadata_key_pin_independently_authenticated"])
        self.assertFalse(result["publishable"])

    def test_missing_signed_publication_rejected(self):
        signed = bundle(self.records, unrelated={"10"})
        signed["signed_publications"].pop(0)
        with self.assertRaises(PlanningError):
            self.check(signed=signed)

    def test_failed_remote_verification_rejected(self):
        coll = collection(self.records)
        coll["job_details"][0]["jobs"][2]["conclusion"] = "failure"
        with self.assertRaisesRegex(PlanningError, "unsuccessful"):
            self.check(coll=coll)

    def test_wrong_repository_rejected_before_archive_load(self):
        coll = collection(self.records)
        coll["repository"] = "not-trusted/Ro-Repo"
        with self.assertRaisesRegex(PlanningError, "identity"):
            self.check(coll=coll)

    def test_inconsistent_run_counts_rejected(self):
        coll = collection(self.records)
        coll["successful_runs"] = 1
        with self.assertRaisesRegex(PlanningError, "counts"):
            self.check(coll=coll)

    def test_forged_signed_candidate_selection_rejected(self):
        signed = bundle(self.records)
        signed["candidate_history"][0] = dict(signed["candidate_history"][0],
                                              candidate_sha256="e"*64)
        with self.assertRaisesRegex(PlanningError, "selection mismatch"):
            self.check(signed=signed)

    def test_signature_failure_propagates(self):
        with patch("v3_beta_evidence_bridge.signed_archive_bundle",
                   side_effect=PlanningError("metadata signature verification failed")):
            with self.assertRaisesRegex(PlanningError, "signature"):
                verify_evidence(collection(self.records), "/signed", "/snapshots",
                                {}, "ro-assist", "public.asc", "f"*64, self.now)


if __name__ == "__main__":
    unittest.main()
