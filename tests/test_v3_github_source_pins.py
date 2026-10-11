import base64
import hashlib
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_github_source_pins import (
    REPOSITORY, REPOSITORY_ID, KEY_PATH, verify_source_pins, audit_with_live_pins,
)
from v3_promotion_planner import PlanningError

MAIN = "a" * 40
PAGES = "b" * 40
KEY = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n-----END PGP PUBLIC KEY BLOCK-----\n"
KEY_SHA = hashlib.sha256(KEY).hexdigest()
BLOB = hashlib.sha1(b"blob " + str(len(KEY)).encode() + b"\0" + KEY).hexdigest()


class SourcePinTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = pathlib.Path(self.tmp.name) / "metadata.asc"
        self.key.write_bytes(KEY)
        self.calls = []
        self.moved = False

    def api(self, path, token):
        self.calls.append(path)
        self.assertEqual(token, "fixture-token")
        if path == "/repos/" + REPOSITORY:
            return {"id": REPOSITORY_ID, "full_name": REPOSITORY}
        if path.endswith("/git/ref/heads/main"):
            return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": MAIN}}
        if path.endswith("/git/ref/heads/pages-storage"):
            return {"ref": "refs/heads/pages-storage", "object": {
                "type": "commit", "sha": "c"*40 if self.moved else PAGES}}
        if "/contents/" + KEY_PATH in path:
            self.assertTrue(path.endswith("?ref=" + MAIN))
            return {"path": KEY_PATH, "type": "file", "encoding": "base64",
                    "content": base64.b64encode(KEY).decode(), "size": len(KEY), "sha": BLOB}
        self.fail("unexpected GitHub API URL " + path)

    def pins(self, **overrides):
        values = dict(expected_main_sha=MAIN, expected_pages_sha=PAGES,
                      expected_key_sha256=KEY_SHA, local_key=self.key)
        values.update(overrides)
        return verify_source_pins(self.api, "fixture-token", **values)

    def test_matching_repo_refs_and_public_key_never_grant_authority(self):
        result = self.pins()
        self.assertTrue(result["github_repository_and_refs_match_caller_pins"])
        self.assertFalse(result["pins_independently_authenticated"])
        self.assertFalse(result["publishable"])
        self.assertGreaterEqual(self.calls.count("/repos/" + REPOSITORY + "/git/ref/heads/main"), 2)

    def test_wrong_repo_identity_rejected(self):
        def fake(path, token):
            out = self.api(path, token)
            return dict(out, id=999) if path == "/repos/" + REPOSITORY else out
        with self.assertRaisesRegex(PlanningError, "repository identity"):
            verify_source_pins(fake, "fixture-token", expected_main_sha=MAIN,
                               expected_pages_sha=PAGES, expected_key_sha256=KEY_SHA,
                               local_key=self.key)

    def test_pages_ref_mismatch_rejected(self):
        with self.assertRaisesRegex(PlanningError, "Pages branch differs"):
            self.pins(expected_pages_sha="d"*40)

    def test_changed_local_key_rejected(self):
        self.key.write_bytes(b"substituted")
        with self.assertRaisesRegex(PlanningError, "local metadata public key differs"):
            self.pins()

    def test_wrong_pinned_digest_rejected(self):
        with self.assertRaisesRegex(PlanningError, "does not match pin"):
            self.pins(expected_key_sha256="f"*64)

    def test_bad_remote_key_blob_rejected(self):
        def fake(path, token):
            out = self.api(path, token)
            return dict(out, sha="0"*40) if "/contents/" + KEY_PATH in path else out
        with self.assertRaisesRegex(PlanningError, "Git blob mismatch"):
            verify_source_pins(fake, "fixture-token", expected_main_sha=MAIN,
                               expected_pages_sha=PAGES, expected_key_sha256=KEY_SHA,
                               local_key=self.key)

    def test_missing_token_fails_before_network(self):
        with self.assertRaisesRegex(PlanningError, "token required"):
            verify_source_pins(self.api, "", expected_main_sha=MAIN,
                               expected_pages_sha=PAGES, expected_key_sha256=KEY_SHA,
                               local_key=self.key)
        self.assertEqual(self.calls, [])

    def test_ref_move_during_expensive_audit_rejected(self):
        def audit(*args, **kwargs):
            self.moved = True
            return {"repository": REPOSITORY, "caller_pinned_pages_commit": PAGES,
                    "publishable": False}
        with self.assertRaisesRegex(PlanningError, "Pages branch differs"):
            audit_with_live_pins(
                self.api, "fixture-token", expected_main_sha=MAIN,
                expected_pages_sha=PAGES, expected_key_sha256=KEY_SHA,
                local_key=self.key, pages_checkout="unused", registry={},
                promotion_group="ro-assist", now="2026-10-11T12:00:00Z",
                audit_beta=audit, collect_runs=lambda *args: {"publishable": False},
            )

    def test_audit_cannot_return_publishable_result(self):
        def audit(*args, **kwargs):
            return {"repository": REPOSITORY, "caller_pinned_pages_commit": PAGES,
                    "publishable": True}
        with self.assertRaisesRegex(PlanningError, "invalid read-only"):
            audit_with_live_pins(
                self.api, "fixture-token", expected_main_sha=MAIN,
                expected_pages_sha=PAGES, expected_key_sha256=KEY_SHA,
                local_key=self.key, pages_checkout="unused", registry={},
                promotion_group="ro-assist", now="2026-10-11T12:00:00Z",
                audit_beta=audit, collect_runs=lambda *args: {"publishable": False},
            )


if __name__ == "__main__":
    unittest.main()
