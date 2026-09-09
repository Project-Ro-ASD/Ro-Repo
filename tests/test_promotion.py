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

        # mock producers config
        config = {"producers": []}
        for pkg, risk in risk_map.items():
            config["producers"].append({"repository": f"test/{pkg}", "allowed_package_names": [pkg], "risk_class": risk, "promotion_group": "ro-control"})

        ro_repo.ROOT = self.tmp
        (self.tmp/"config").mkdir(exist_ok=True)
        ro_repo.save(self.tmp/"config/producers-v1.yaml", config)

        # mock schema loading since ROOT changed
        # We'll just patch load to intercept schemas
        self.real_load = ro_repo.load

    def build_promo(self, risk="normal-app", emergency=False, reason="", evidence=None, group="ro-control"):
        if evidence is None:
            evidence = [{"name":"smoke","result":"pass","snapshot_id":"repo-f44-20260908-001","timestamp":"2026-09-08T00:00:00Z","reference":"http","digest":"a"*64}]
        return {
            "schema_version":1, "snapshot_id":"repo-f44-20260908-001", "from":"beta", "to":"stable",
            "risk_class":risk, "promotion_group":group,
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
        evidence_content = {"snapshot_id": "repo-f44-20260908-001", "result": "pass"}
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
    def test_fake_group_rejected(self, m_schema, m_pub):
        self.setup_env({"ro-control": "normal-app"}, ["ro-control"], beta_age_days=8)
        promo = self.build_promo("normal-app", group="fake-group")
        path = self.tmp / "promo.json"
        ro_repo.save(path, promo)

        with self.assertRaisesRegex(ro_repo.ContractError, "spoofed promotion_group"):
            ro_repo.promote(self.out, path, "test")

if __name__ == '__main__':
    unittest.main()
