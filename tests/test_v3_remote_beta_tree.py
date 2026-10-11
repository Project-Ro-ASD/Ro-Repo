import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_remote_beta_tree import verify_tree_bytes, verify_remote_beta, REMOTE_ORIGIN
from v3_promotion_planner import PlanningError


class RemoteBetaTreeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        def git(*args):
            return subprocess.check_output(
                ["git", "-C", str(self.root), *args], text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        self.git = git
        git("init", "-q")
        git("config", "user.name", "Test")
        git("config", "user.email", "test@example.invalid")
        git("checkout", "-qb", "pages-storage")
        self.files = {
            "rpm/fedora/44/beta/x86_64/example.rpm": b"rpm-byte-fixture",
            "rpm/fedora/44/beta/x86_64/repodata/repomd.xml": b"<repomd/>",
            "publications/fedora/44/beta/10/publication-v1.json": b'{"channel":"beta"}',
            "publications/fedora/44/beta/10/store/catalog.json": b'{"assets":[]}',
            "snapshots/fedora/44/repo-f44-20261009-001/repository-snapshot-v1.json": b'{"packages":[]}',
        }
        for rel, data in self.files.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        git("add", ".")
        git("commit", "-qm", "isolated Pages tree")
        self.sha = git("rev-parse", "HEAD")

    def fetch(self, url):
        rel = url[len(REMOTE_ORIGIN):].split("?", 1)[0]
        yield self.files[rel]

    def check(self, fetch=None):
        return verify_tree_bytes(self.root, self.sha, fetch_chunks=fetch or self.fetch)

    def test_all_expected_remote_bytes_and_no_approval(self):
        result = self.check()
        self.assertEqual(result["checked_file_count"], 5)
        self.assertTrue(result["all_expected_remote_files_byte_equal"])
        self.assertFalse(result["remote_unlisted_extra_files_excluded"])
        self.assertFalse(result["publishable"])

    def test_remote_tamper_rejected(self):
        def tamper(url):
            yield b"wrong-bytes"
        with self.assertRaises(PlanningError):
            self.check(fetch=tamper)

    def test_remote_missing_file_rejected(self):
        def missing(_url):
            return iter(())
        with self.assertRaisesRegex(PlanningError, "incomplete"):
            self.check(fetch=missing)

    def test_untracked_local_file_rejected(self):
        (self.root/"rpm/fedora/44/beta/x86_64/surprise.rpm").write_bytes(b"new")
        with self.assertRaisesRegex(PlanningError, "untracked"):
            self.check()

    def test_local_tamper_rejected(self):
        (self.root/"rpm/fedora/44/beta/x86_64/example.rpm").write_bytes(b"tampered")
        with self.assertRaisesRegex(PlanningError, "pinned Git blob"):
            self.check()

    def test_symlink_rejected(self):
        target = self.root/"rpm/fedora/44/beta/link"
        target.symlink_to(self.root/"rpm/fedora/44/beta/x86_64", target_is_directory=True)
        with self.assertRaisesRegex(PlanningError, "symlink"):
            self.check()

    def test_excessive_remote_bytes_rejected(self):
        def oversized(_url):
            yield b"a" * 200
        with self.assertRaises(PlanningError):
            self.check(fetch=oversized)

    def test_wrong_commit_rejected(self):
        with self.assertRaisesRegex(PlanningError, "HEAD differs"):
            verify_tree_bytes(self.root, "a" * 40, fetch_chunks=self.fetch)

    def test_signed_metadata_failure_blocks_bulk_comparison(self):
        with patch("v3_remote_beta_tree.verify_pages_metadata",
                   side_effect=PlanningError("bad signature")):
            with patch("v3_remote_beta_tree.verify_tree_bytes") as bulk:
                with self.assertRaisesRegex(PlanningError, "bad signature"):
                    verify_remote_beta({}, self.root, self.sha, {}, "ro-assist",
                                       "key.asc", "f"*64, "2026-10-11T00:00:00Z")
                bulk.assert_not_called()


if __name__ == "__main__":
    unittest.main()
