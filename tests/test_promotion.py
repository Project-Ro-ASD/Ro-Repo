import unittest
import pathlib
import json
import datetime as dt
import sys
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))
import tools.ro_repo
from tools import ro_repo

class PromotionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.original_root = tools.ro_repo.ROOT
        self.tmp = pathlib.Path("tests_tmp_promo")
        self.tmp.mkdir(exist_ok=True)
        self.out = self.tmp / "out"

    def tearDown(self):
        tools.ro_repo.ROOT = self.original_root
        import shutil
        if self.tmp.exists():
            shutil.rmtree(self.tmp)

    def setup_env(self, risk_map, packages, beta_age_days):
        pub = self.out/"publication/rpm/fedora/44/beta"
        pub.mkdir(parents=True, exist_ok=True)
        past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=beta_age_days)).isoformat().replace("+00:00", "Z")
        ro_repo.save(pub/"publication-v1.json", {"schema_version":1,"channel":"beta","snapshot_id":"repo-f44-20260908-001","published_at":past,"publication_run":"test"})

        snap = self.out/"snapshots/fedora/44/repo-f44-20260908-001"
        snap.mkdir(parents=True, exist_ok=True)
        sha = "a" * 64
        pkgs = [{"nevra": f"{p}-0:1.0-1.x86_64", "architecture": "x86_64", "filename": f"{p}.rpm", "producer_artifact_sha256": sha, "published_signed_artifact_sha256": sha, "producer_manifest_digest": sha} for p in packages]
        ro_repo.save(snap/"repository-snapshot-v1.json", {"schema_version":1,"snapshot_id":"repo-f44-20260908-001","created_at":"2026-09-08T00:00:00Z","fedora_release":44,"parent_snapshot":None,"packages":pkgs,"repositories":{},"rpm_signing_fingerprint":"A"*40,"metadata_signing_fingerprint":"A"*40,"creation_provenance":{"tool":"ro-repo-v2","run":"local"}})

        # mock component-scoped producer registry v2
        config = {
            "schema_version": 2,
            "fedora_release": 44,
            "fedora_package_names_file": "config/fedora-44-package-names.txt",
            "producers": [],
        }
        for pkg, risk in risk_map.items():
            config["producers"].append({
                "repository": f"test/{pkg}",
                "owner": "test",
                "components": [{
                    "component": pkg,
                    "package_names": [pkg],
                    "architectures": ["x86_64"],
                    "risk_class": risk,
                    "promotion_group": "ro-control",
                    "required_tests": ["dependency-solve", "clean-install", "upgrade", "file-conflict", "rpmlint", "smoke"],
                    "srpm_required": True,
                    "sbom_required": False,
                    "allow_fedora_override": False,
                    "trusted_signer_workflow": f"test/{pkg}/.github/workflows/release.yml",
                }],
            })

        ro_repo.ROOT = self.tmp
        (self.tmp/"config").mkdir(exist_ok=True)
        ro_repo.save(self.tmp/"config/producers-v2.json", config)

        # validate_schema is patched by the promotion tests while ROOT is redirected.
        self.real_load = ro_repo.load

    def build_promo(self, risk="normal-app", emergency=False, reason="", evidence=None, group="ro-control"):
        if evidence is None:
            evidence = [{"name":"smoke","result":"pass","snapshot_id":"repo-f44-20260908-001","timestamp":"2026-09-08T00:00:00Z","reference":"http","digest":"a"*64}]
        return {
            "schema_version":1, "snapshot_id":"repo-f44-20260908-001", "from":"beta", "to":"stable",
            "risk_class":risk, "promotion_groups":group if isinstance(group, list) else [group],
            "beta_started_at":dt.datetime.now(dt.timezone.utc).isoformat(), # fake date
            "evidence": evidence, "approved_by":"maintainer",
            "approved_at":dt.datetime.now(dt.timezone.utc).isoformat(), "emergency":emergency, "reason":reason
        }

    @mock.patch("tools.ro_repo.publish")
    @mock.patch("tools.ro_repo.validate_schema")
    def test_fake_old_beta_started_at_rejected(self, m_schema, m_pub):
        self.setup_env({"ro-control": "normal-app"}, ["ro-control"], beta_age_days=2)
        promo = self.build_promo("normal-app")
        promo["beta_started_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10)).isoformat()
        path = self.tmp / "promo.json"
        ro_repo.save(path, promo)

        with self.assertRaisesRegex(ro_repo.ContractError, "minimum beta duration is 7 days"):
            ro_repo.promote(self.out, path, "test")

    @mock.patch("tools.ro_repo.publish")
    @mock.patch("tools.ro_repo.validate_schema")
    def test_critical_package_normal_app_promotion_rejected(self, m_schema, m_pub):
        self.setup_env({"ro-theme": "critical-desktop"}, ["ro-theme"], beta_age_days=10)
        promo = self.build_promo("normal-app")
        path = self.tmp / "promo.json"
        ro_repo.save(path, promo)

        with self.assertRaisesRegex(ro_repo.ContractError, "spoofed risk_class"):
            ro_repo.promote(self.out, path, "test")

    @mock.patch("tools.ro_repo.publish")
    @mock.patch("tools.ro_repo.validate_schema")
    def test_emergency_empty_reason_rejected(self, m_schema, m_pub):
        self.setup_env({"ro-control": "normal-app"}, ["ro-control"], beta_age_days=2)
        promo = self.build_promo("normal-app", emergency=True, reason="  ")
        path = self.tmp / "promo.json"
        ro_repo.save(path, promo)

        with self.assertRaisesRegex(ro_repo.ContractError, "requires a non-empty reason"):
            ro_repo.promote(self.out, path, "test")

    @mock.patch("tools.ro_repo.publish")
    @mock.patch("tools.ro_repo.validate_schema")
    def test_fake_evidence_rejected(self, m_schema, m_pub):
        self.setup_env({"ro-control": "normal-app"}, ["ro-control"], beta_age_days=8)
        evidence_content = {"snapshot_id": "repo-f44-20260908-001", "name": "smoke", "result": "pass"}
        ev_path = self.out / "evidence/test.json"
        ev_path.parent.mkdir(parents=True, exist_ok=True)
        ro_repo.save(ev_path, evidence_content)
        d = ro_repo.digest(ev_path)
        promo = self.build_promo("normal-app", evidence=[{"name":"smoke","result":"pass","snapshot_id":"repo-f44-20260908-001","timestamp":"2026-09-08T00:00:00Z","reference":"evidence/test.json","digest":d}])
        path = self.tmp / "promo.json"
        ro_repo.save(path, promo)

        with self.assertRaisesRegex(ro_repo.ContractError, "promotion evidence missing"):
            ro_repo.promote(self.out, path, "test")

    @mock.patch("tools.ro_repo.publish")
    @mock.patch("tools.ro_repo.validate_schema")
    def test_evidence_traversal_rejected(self, m_schema, m_pub):
        self.setup_env({"ro-control": "normal-app"}, ["ro-control"], beta_age_days=8)
        evidence_content = {"snapshot_id": "repo-f44-20260908-001", "name": "smoke", "result": "pass"}
        ev_path = self.out / "evidence-evil/test.json"
        ev_path.parent.mkdir(parents=True, exist_ok=True)
        ro_repo.save(ev_path, evidence_content)
        d = ro_repo.digest(ev_path)

        # Test 1: evil prefix
        promo = self.build_promo("normal-app", evidence=[{"name":"smoke","result":"pass","snapshot_id":"repo-f44-20260908-001","timestamp":"2026-09-08T00:00:00Z","reference":"evidence-evil/test.json","digest":d}])
        path = self.tmp / "promo.json"
        ro_repo.save(path, promo)
        with self.assertRaisesRegex(ro_repo.ContractError, "path traversal"):
            ro_repo.promote(self.out, path, "test")

        # Test 2: dot-dot traversal
        promo["evidence"][0]["reference"] = "evidence/../evidence-evil/test.json"
        ro_repo.save(path, promo)
        with self.assertRaisesRegex(ro_repo.ContractError, "path traversal"):
            ro_repo.promote(self.out, path, "test")

        # Test 3: symlink escape
        (self.out / "evidence").mkdir(parents=True, exist_ok=True)
        sym = self.out / "evidence/symlink.json"
        sym.symlink_to(ev_path.resolve())
        promo["evidence"][0]["reference"] = "evidence/symlink.json"
        ro_repo.save(path, promo)
        with self.assertRaisesRegex(ro_repo.ContractError, "path traversal"):
            ro_repo.promote(self.out, path, "test")

    @mock.patch("tools.ro_repo.publish")
    @mock.patch("tools.ro_repo.validate_schema")
    def test_fake_group_rejected(self, m_schema, m_pub):
        self.setup_env({"ro-control": "normal-app"}, ["ro-control"], beta_age_days=8)
        promo = self.build_promo("normal-app", group="fake-group")
        path = self.tmp / "promo.json"
        ro_repo.save(path, promo)

        with self.assertRaisesRegex(ro_repo.ContractError, "spoofed promotion_groups"):
            ro_repo.promote(self.out, path, "test")

    @mock.patch("tools.ro_repo.publish")
    @mock.patch("tools.ro_repo.validate_schema")
    def test_same_repository_components_keep_independent_promotion_policy(self, m_schema, m_pub):
        self.setup_env(
            {"ro-asd-release": "critical-system", "ro-asd-branding": "critical-desktop"},
            ["ro-asd-release", "ro-asd-branding"],
            beta_age_days=15,
        )
        config = ro_repo.load(self.tmp/"config/producers-v2.json")
        config["producers"] = [{
            "repository": "test/ro-asd-monorepo",
            "owner": "test",
            "components": [
                {
                    "component": "ro-asd-release",
                    "package_names": ["ro-asd-release"],
                    "architectures": ["x86_64"],
                    "risk_class": "critical-system",
                    "promotion_group": "release-core",
                    "required_tests": [],
                    "srpm_required": True,
                    "sbom_required": False,
                    "allow_fedora_override": False,
                    "trusted_signer_workflow": "test/ro-asd-monorepo/.github/workflows/release.yml",
                },
                {
                    "component": "ro-asd-branding",
                    "package_names": ["ro-asd-branding"],
                    "architectures": ["x86_64"],
                    "risk_class": "critical-desktop",
                    "promotion_group": "branding",
                    "required_tests": [],
                    "srpm_required": True,
                    "sbom_required": False,
                    "allow_fedora_override": False,
                    "trusted_signer_workflow": "test/ro-asd-monorepo/.github/workflows/release.yml",
                },
            ],
        }]
        ro_repo.save(self.tmp/"config/producers-v2.json", config)

        release_policy = ro_repo.resolve_package_policy(config, "ro-asd-release")
        branding_policy = ro_repo.resolve_package_policy(config, "ro-asd-branding")
        self.assertEqual(release_policy["risk_class"], "critical-system")
        self.assertEqual(branding_policy["risk_class"], "critical-desktop")
        self.assertEqual(release_policy["promotion_group"], "release-core")
        self.assertEqual(branding_policy["promotion_group"], "branding")

    @mock.patch("tools.ro_repo.publish")
    @mock.patch("tools.ro_repo.validate_schema")
    def test_multi_group_rejected_and_accepted(self, m_schema, m_pub):
        # Create an environment where the snapshot has two packages belonging to two DIFFERENT promotion groups
        self.setup_env({"ro-control": "normal-app", "ro-assist": "normal-app"}, ["ro-control", "ro-assist"], beta_age_days=8)

        # Override the mocked v2 config to have multiple promotion groups.
        config = ro_repo.load(self.tmp/"config/producers-v2.json")
        for producer in config["producers"]:
            component = producer["components"][0]
            if component["component"] == "ro-control":
                component["promotion_group"] = "groupA"
            elif component["component"] == "ro-assist":
                component["promotion_group"] = "groupB"
        ro_repo.save(self.tmp/"config/producers-v2.json", config)

        # Build evidence content
        evidence_content = {"snapshot_id": "repo-f44-20260908-001", "name": "smoke", "result": "pass"}
        ev_path = self.out / "evidence/test.json"
        ev_path.parent.mkdir(parents=True, exist_ok=True)
        ro_repo.save(ev_path, evidence_content)
        d = ro_repo.digest(ev_path)
        evidence = [{"name":"smoke","result":"pass","snapshot_id":"repo-f44-20260908-001","timestamp":"2026-09-08T00:00:00Z","reference":"evidence/test.json","digest":d}]

        path = self.tmp / "promo.json"

        # Missing group
        promo = self.build_promo("normal-app", group=["groupA"], evidence=evidence, emergency=True, reason="test")
        ro_repo.save(path, promo)
        with self.assertRaisesRegex(ro_repo.ContractError, "spoofed promotion_groups"):
            ro_repo.promote(self.out, path, "test")

        # Extra group
        promo = self.build_promo("normal-app", group=["groupA", "groupB", "groupC"], evidence=evidence, emergency=True, reason="test")
        ro_repo.save(path, promo)
        with self.assertRaisesRegex(ro_repo.ContractError, "spoofed promotion_groups"):
            ro_repo.promote(self.out, path, "test")

        # Exact groups (ACCEPTED)
        promo = self.build_promo("normal-app", group=["groupB", "groupA"], evidence=evidence, emergency=True, reason="test")
        ro_repo.save(path, promo)
        ro_repo.promote(self.out, path, "test")
        self.assertTrue(m_pub.called)

if __name__ == '__main__':
    unittest.main()
