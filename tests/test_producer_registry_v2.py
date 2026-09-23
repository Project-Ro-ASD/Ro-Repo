import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
import ro_repo


class ProducerRegistryV2Tests(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(__file__).parents[1]
        self.v1 = ro_repo.load_producer_registry(self.root / "config/producers-v1.yaml")
        self.v2 = ro_repo.load_producer_registry(self.root / "config/producers-v2.json")

    def test_v2_release_component_resolves_exact_policy(self):
        policy = ro_repo.resolve_component_policy(
            self.v2,
            "Project-Ro-ASD/Ro-ASD-release",
            "ro-asd-release",
        )
        self.assertEqual(policy["package_names"], ["ro-asd-release"])
        self.assertEqual(policy["architectures"], ["noarch"])
        self.assertEqual(policy["risk_class"], "critical-system")
        self.assertEqual(policy["promotion_group"], "ro-asd-release")

    def test_v2_same_repository_can_hold_independent_components(self):
        config = copy.deepcopy(self.v2)
        producer = next(
            item for item in config["producers"]
            if item["repository"] == "Project-Ro-ASD/Ro-ASD-release"
        )
        producer["components"].append({
            "component": "ro-asd-branding",
            "package_names": ["ro-asd-branding"],
            "architectures": ["noarch"],
            "risk_class": "critical-desktop",
            "promotion_group": "ro-asd-branding",
            "required_tests": ["dependency-solve", "smoke"],
            "srpm_required": True,
            "sbom_required": False,
            "allow_fedora_override": False,
            "trusted_signer_workflow": "Project-Ro-ASD/Ro-ASD-release/.github/workflows/release.yml",
        })
        release = ro_repo.resolve_component_policy(
            config, "Project-Ro-ASD/Ro-ASD-release", "ro-asd-release"
        )
        branding = ro_repo.resolve_component_policy(
            config, "Project-Ro-ASD/Ro-ASD-release", "ro-asd-branding"
        )
        self.assertEqual(release["risk_class"], "critical-system")
        self.assertEqual(branding["risk_class"], "critical-desktop")
        self.assertNotEqual(release["promotion_group"], branding["promotion_group"])

    def test_v2_keyring_component_resolves_independent_policy(self):
        policy = ro_repo.resolve_component_policy(
            self.v2,
            "Project-Ro-ASD/Ro-ASD-release",
            "ro-asd-keyring",
        )
        self.assertEqual(policy["package_names"], ["ro-asd-keyring"])
        self.assertEqual(policy["architectures"], ["noarch"])
        self.assertEqual(policy["risk_class"], "critical-system")
        self.assertEqual(policy["promotion_group"], "ro-asd-keyring")
        self.assertEqual(
            policy["trusted_signer_workflow"],
            "Project-Ro-ASD/Ro-ASD-release/.github/workflows/release-keyring.yml",
        )

    def test_v2_repos_component_resolves_independent_policy(self):
        policy = ro_repo.resolve_component_policy(
            self.v2,
            "Project-Ro-ASD/Ro-ASD-release",
            "ro-asd-repos",
        )
        self.assertEqual(policy["package_names"], ["ro-asd-repos"])
        self.assertEqual(policy["architectures"], ["noarch"])
        self.assertEqual(policy["risk_class"], "critical-system")
        self.assertEqual(policy["promotion_group"], "ro-asd-repos")
        self.assertEqual(
            policy["trusted_signer_workflow"],
            "Project-Ro-ASD/Ro-ASD-release/.github/workflows/release-repos.yml",
        )

    def test_v2_defaults_component_resolves_independent_policy(self):
        policy = ro_repo.resolve_component_policy(
            self.v2,
            "Project-Ro-ASD/Ro-ASD-release",
            "ro-asd-defaults",
        )
        self.assertEqual(policy["package_names"], ["ro-asd-defaults"])
        self.assertEqual(policy["architectures"], ["noarch"])
        self.assertEqual(policy["risk_class"], "critical-system")
        self.assertEqual(policy["promotion_group"], "ro-asd-defaults")
        self.assertEqual(
            policy["trusted_signer_workflow"],
            "Project-Ro-ASD/Ro-ASD-release/.github/workflows/release-defaults.yml",
        )

    def test_v2_branding_component_resolves_independent_policy(self):
        policy = ro_repo.resolve_component_policy(
            self.v2,
            "Project-Ro-ASD/Ro-ASD-release",
            "ro-asd-branding",
        )
        self.assertEqual(policy["package_names"], ["ro-asd-branding"])
        self.assertEqual(policy["architectures"], ["noarch"])
        self.assertEqual(policy["risk_class"], "critical-desktop")
        self.assertEqual(policy["promotion_group"], "ro-asd-branding")
        self.assertEqual(
            policy["trusted_signer_workflow"],
            "Project-Ro-ASD/Ro-ASD-release/.github/workflows/release-branding.yml",
        )

    def test_v2_wrong_component_is_fail_closed(self):
        with self.assertRaisesRegex(ro_repo.ContractError, "component policy missing"):
            ro_repo.resolve_component_policy(
                self.v2, "Project-Ro-ASD/Ro-ASD-release", "not-registered"
            )

    def test_v2_package_policy_resolves_component_owner(self):
        policy = ro_repo.resolve_package_policy(self.v2, "ro-asd-release")
        self.assertEqual(policy["repository"], "Project-Ro-ASD/Ro-ASD-release")
        self.assertEqual(policy["component"], "ro-asd-release")

    def test_v2_collision_policy_exposes_normalized_package_names(self):
        policy = ro_repo.resolve_component_policy(
            self.v2,
            "Project-Ro-ASD/Ro-ASD-release",
            "ro-asd-release",
        )
        fedora_names = {"bash", "ro-asd-release"}
        collision = set(policy["package_names"]) & fedora_names
        self.assertEqual(collision, {"ro-asd-release"})
        self.assertFalse(policy["allow_fedora_override"])

    def test_v1_remains_readable_during_migration(self):
        policy = ro_repo.resolve_component_policy(
            self.v1, "Project-Ro-ASD/ro-Control", "ro-control"
        )
        self.assertEqual(policy["package_names"], ["ro-control"])
        self.assertEqual(policy["risk_class"], "normal-app")


if __name__ == "__main__":
    unittest.main()
