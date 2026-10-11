import base64
import copy
import hashlib
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_github_source_pins import verify_registry_pin
from v3_promotion_planner import PlanningError


class RegistryPinTests(unittest.TestCase):
    def setUp(self):
        self.registry = {"fedora_release": 44, "producers": []}
        self.raw = json.dumps(self.registry).encode()
        self.record = {"path": "config/producers-v2.json", "type": "file", "encoding": "base64",
                       "content": base64.b64encode(self.raw).decode(), "size": len(self.raw),
                       "sha": hashlib.sha1(b"blob " + str(len(self.raw)).encode() + b"\0" + self.raw).hexdigest()}
        self.calls = []

    def api(self, path, token):
        self.calls.append(path)
        return self.record

    def test_registry_bound_to_exact_pinned_commit(self):
        result = verify_registry_pin(self.api, "read-only-fixture", "a" * 40, self.registry)
        self.assertEqual(result["registry_file_sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertTrue(self.calls[0].endswith("?ref=" + "a" * 40))
        self.assertFalse(result["independently_authenticated"])

    def test_divergent_local_policy_rejected(self):
        changed = copy.deepcopy(self.registry)
        changed["fedora_release"] = 45
        with self.assertRaisesRegex(PlanningError, "diverges"):
            verify_registry_pin(self.api, "fixture", "a" * 40, changed)

    def test_forged_api_blob_and_wrong_path_rejected(self):
        for key, value in (("sha", "b" * 40), ("path", "attacker-registry.json"), ("size", 1)):
            original = copy.deepcopy(self.record)
            self.record[key] = value
            with self.subTest(field=key), self.assertRaises(PlanningError):
                verify_registry_pin(self.api, "fixture", "a" * 40, self.registry)
            self.record = original

    def test_mutable_branch_cannot_replace_commit_pin(self):
        with self.assertRaisesRegex(PlanningError, "registry commit"):
            verify_registry_pin(self.api, "fixture", "main", self.registry)


if __name__ == "__main__":
    unittest.main()
