import importlib.util
import pathlib
import sys
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "tools" / "bootstrap-repo.py"
spec = importlib.util.spec_from_file_location("bootstrap_repo", MODULE_PATH)
bootstrap = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bootstrap
assert spec.loader is not None
spec.loader.exec_module(bootstrap)


class BaselinePolicyTests(unittest.TestCase):
    def test_parse_repo(self):
        self.assertEqual(
            bootstrap.parse_repo("Project-Ro-ASD/Ro-Repo"),
            ("Project-Ro-ASD", "Ro-Repo"),
        )
        self.assertEqual(
            bootstrap.parse_repo("https://github.com/Project-Ro-ASD/Ro-Repo.git"),
            ("Project-Ro-ASD", "Ro-Repo"),
        )

    def test_status_checks_are_deduplicated_and_do_not_pin_integration(self):
        rule = bootstrap.status_check_rule(["unit-policy", "unit-policy", "fedora44-e2e"])
        checks = rule["parameters"]["required_status_checks"]
        self.assertEqual(
            checks,
            [{"context": "unit-policy"}, {"context": "fedora44-e2e"}],
        )
        self.assertTrue(rule["parameters"]["strict_required_status_checks_policy"])

    def test_universal_rule_is_single_maintainer_safe(self):
        rules = bootstrap.universal_rules()
        self.assertEqual(
            [rule["type"] for rule in rules],
            ["deletion", "non_fast_forward", "pull_request"],
        )
        pr = rules[-1]["parameters"]
        self.assertEqual(pr["required_approving_review_count"], 0)
        self.assertFalse(pr["dismiss_stale_reviews_on_push"])
        self.assertFalse(pr["require_code_owner_review"])

    def test_ruleset_targets_default_branch(self):
        payload = bootstrap.ruleset_payload("x", bootstrap.universal_rules())
        self.assertEqual(
            payload["conditions"]["ref_name"]["include"],
            ["~DEFAULT_BRANCH"],
        )
        self.assertEqual(payload["bypass_actors"], [])


if __name__ == "__main__":
    unittest.main()
