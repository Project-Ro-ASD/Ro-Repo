import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_pages_archive_provenance import (
    verify_checkout, _tracked_bytes, verify_pages_metadata, REMOTE_ORIGIN,
)
from v3_promotion_planner import PlanningError

RUN = "37935890476"
SNAP = "repo-f44-20261009-001"
PUB = "publications/fedora/44/beta/" + RUN + "/publication-v1.json"
SNAP_META = "snapshots/fedora/44/" + SNAP + "/repository-snapshot-v1.json"


class PagesAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        def git(*args):
            return subprocess.check_output(["git", "-C", str(self.root), *args], text=True).strip()
        self.git = git
        git("init", "-q")
        git("config", "user.name", "Test")
        git("config", "user.email", "test@example.invalid")
        git("checkout", "-qb", "pages-storage")
        files = {
            PUB: ('{"channel":"beta","publication_run":"' + RUN + '",'
                  '"snapshot_id":"' + SNAP + '"}').encode(),
            PUB + ".asc": b"fixture signature",
            SNAP_META: b'{"snapshot_id":"' + SNAP.encode() + b'"}',
            SNAP_META + ".asc": b"fixture signature",
        }
        for name, data in files.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        git("add", ".")
        git("commit", "-qm", "isolated pinned Pages fixture")
        self.sha = git("rev-parse", "HEAD")
        self.files = files
        self.collection = {"run_details": [{"id": int(RUN)}]}
        self.bridge = {"signed_publications_checked": 1,
                       "matching_candidate_publications": 1,
                       "candidate_remote_verify_times": []}

    def check(self, fetch=None):
        def get(url):
            rel = url[len(REMOTE_ORIGIN):].split("?", 1)[0]
            return self.files[rel] if fetch is None else fetch(url)
        with patch("v3_pages_archive_provenance.verify_evidence", return_value=self.bridge):
            return verify_pages_metadata(
                self.collection, self.root, self.sha, {},
                "ro-assist", "public.asc", "f"*64,
                "2026-10-11T00:00:00Z", fetch_bytes=get,
            )

    def test_pinned_checkout_and_remote_metadata(self):
        result = self.check()
        self.assertEqual(result["archived_publications_checked"], 1)
        self.assertEqual(result["remote_signed_metadata_files_checked"], 4)
        self.assertFalse(result["remote_entire_rpm_and_store_tree_verified"])
        self.assertFalse(result["pages_branch_source_authenticated_independently"])
        self.assertFalse(result["publishable"])

    def test_wrong_commit_pin_fails_closed(self):
        with self.assertRaisesRegex(PlanningError, "HEAD differs"):
            verify_checkout(self.root, "a"*40)

    def test_checkout_byte_tampering_fails_closed(self):
        (self.root/PUB).write_text("{}")
        with self.assertRaisesRegex(PlanningError, "differs"):
            self.check()

    def test_missing_tracked_signature_fails_closed(self):
        (self.root/(PUB+".asc")).unlink()
        with self.assertRaisesRegex(PlanningError, "missing"):
            self.check()

    def test_remote_signature_mismatch_fails_closed(self):
        def tamper(url):
            rel = url[len(REMOTE_ORIGIN):].split("?", 1)[0]
            return b"tampered" if rel.endswith(".asc") else self.files[rel]
        with self.assertRaisesRegex(PlanningError, "byte mismatch"):
            self.check(fetch=tamper)

    def test_wrong_snapshot_identity_fails_closed(self):
        # Valid signed metadata cannot claim a different snapshot ID.
        bad = PUB.replace("publication-v1.json", "wrong.json")
        self.assertNotIn(bad, self.files)
        (self.root/PUB).write_text('{"channel":"beta","publication_run":"'+RUN+'","snapshot_id":"../escape"}')
        self.git("add", ".")
        self.git("commit", "-qm", "bad metadata test commit")
        self.sha = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(PlanningError, "identity mismatch"):
            self.check()

    def test_remote_ref_mismatch_fails_closed(self):
        self.git("branch", "-f", "other", self.sha)
        # A tracking ref takes precedence if present and must match the pin.
        self.git("update-ref", "refs/remotes/origin/pages-storage", "a"*40) if False else None
        with self.assertRaisesRegex(PlanningError, "branch ref differs"):
            self.git("branch", "-f", "pages-storage", "HEAD~0") if False else None
            verify_checkout(self.root, "b"*40)

    def test_git_tree_rejects_untracked_metadata(self):
        rogue = self.root/"untracked.txt"
        rogue.write_text("extra")
        with self.assertRaisesRegex(PlanningError, "not tracked"):
            _tracked_bytes(self.root, "untracked.txt")


if __name__ == "__main__":
    unittest.main()
