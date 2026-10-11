import copy
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_backend_trust import canonical, digest, strict_json, verify_oidc, verify_envelope
from v3_backend_evidence import verify_evidence, verify_protected
from v3_migration import assess_manifest, assert_preserved, retirement_patch, writer_gate
from v3_pinned_upstream import member, repomd_members, primary_inventory, verify_upstream
from v3_vm_acceptance import Agent, run as run_vm
from v3_promotion_planner import PlanningError
from v3_policy_profile import sha
from v3_backend_support import Keys, Fixture, NOW
from test_v3_promotion_planner import assist, dolphin, snapshot
from test_v3_integration import REGISTRY


class InputsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = Keys()

    @classmethod
    def tearDownClass(cls):
        cls.keys.close()

    def setUp(self):
        self.fx = Fixture(self.keys)
        self.addCleanup(self.fx.close)

    def reject(self, call):
        with self.assertRaises(PlanningError):
            call()

    def test_oidc_wrong_actual_signature(self):
        raw, pins = self.keys.oidc(signer=self.keys.signers["approval"])
        self.reject(lambda: verify_oidc(raw, self.keys.jwks, jwks_sha256=digest(self.keys.jwks), pins=pins, now=NOW, fetched_at=NOW))

    def test_oidc_algorithm_and_embedded_key_substitution(self):
        for header in ({"alg": "none", "kid": "test-key"}, {"alg": "HS256", "kid": "test-key"}, {"alg": "RS256", "kid": "test-key", "jku": "https://evil.invalid"}, {"alg": "RS256", "kid": "other"}):
            raw, pins = self.keys.oidc(header=header)
            self.reject(lambda: verify_oidc(raw, self.keys.jwks, jwks_sha256=digest(self.keys.jwks), pins=pins, now=NOW, fetched_at=NOW))

    def test_oidc_duplicate_jwks(self):
        jwks = strict_json(self.keys.jwks)
        jwks["keys"].append(jwks["keys"][0])
        raw, pins = self.keys.oidc()
        data = canonical(jwks)
        self.reject(lambda: verify_oidc(raw, data, jwks_sha256=digest(data), pins=pins, now=NOW, fetched_at=NOW))

    def test_oidc_stale_jwks(self):
        raw, pins = self.keys.oidc()
        self.reject(lambda: verify_oidc(raw, self.keys.jwks, jwks_sha256=digest(self.keys.jwks), pins=pins, now=NOW, fetched_at=NOW-3601))

    def test_attestation_signature_role_and_payload_changes(self):
        signer = self.keys.signers["evidence"]
        raw = signer.envelope("tests", {"test": "exact", "issued_at": NOW, "expires_at": NOW+100})
        for change in (("role", "source"), ("domain", "other")):
            altered = strict_json(raw)
            altered[change[0]] = change[1]
            self.reject(lambda: verify_envelope(canonical(altered), role="tests", public_key=signer.public, key_sha256=signer.key_sha256, expected={"test": "exact"}, now=NOW))
        altered = strict_json(raw)
        altered["payload"]["test"] = "substituted"
        self.reject(lambda: verify_envelope(canonical(altered), role="tests", public_key=signer.public, key_sha256=signer.key_sha256, expected={"test": "exact"}, now=NOW))

    def test_expired_evidence_rejected(self):
        self.reject(lambda: verify_evidence(self.fx.proposal, self.fx.plan, self.fx.registry, self.fx.claim, self.fx.attestations, now=NOW+501))

    def test_forged_dwell_cannot_use_true_field(self):
        p = copy.deepcopy(self.fx.proposal)
        p["first_seen"]["published_at"] = "2026-10-11T11:59:00Z"
        p["proposal_sha256"] = sha({k: v for k, v in p.items() if k != "proposal_sha256"})
        self.reject(lambda: verify_evidence(p, self.fx.plan, self.fx.registry, self.fx.claim, self.fx.attestations, now=NOW))

    def test_missing_real_application_acceptance_rejected(self):
        attestations = dict(self.fx.attestations)
        expected = dict(self.fx.expectations["tests"], application_acceptance="UNVERIFIED")
        attestations["tests"] = self.keys.attestation("tests", expected)
        self.reject(lambda: verify_evidence(self.fx.proposal, self.fx.plan, self.fx.registry, self.fx.claim, attestations, now=NOW))

    def test_same_key_in_different_pem_encodings_is_not_independent(self):
        public = self.keys.signers["approval"].public + b"\n"
        args = dict(self.fx.approval_args, witness_key=public, witness_key_sha256=digest(public))
        self.reject(lambda: verify_protected(self.fx.proposal, self.fx.attempt, self.fx.evidence, self.fx.workload, **args))

    def test_policy_dwell_floor_cannot_be_shortened_in_proposal(self):
        p = copy.deepcopy(self.fx.proposal)
        p["minimum_beta_days"] = 1
        p["proposal_sha256"] = sha({k: v for k, v in p.items() if k != "proposal_sha256"})
        self.reject(lambda: verify_evidence(p, self.fx.plan, self.fx.registry, self.fx.claim, self.fx.attestations, now=NOW))

    def test_signed_baseline_still_requires_exact_approved_tree_digest(self):
        from v3_immutable_view import verify_result
        with mock.patch("v3_full_set_dnf._signed_view") as verifier:
            self.reject(lambda: verify_result(self.fx.source, self.fx.proposal, self.fx.plan,
                        beta=self.fx.source, baseline=self.fx.source, registry=self.fx.registry,
                        rpm_key="missing", rpm_key_sha256="a"*64, metadata_key="missing", metadata_key_sha256="b"*64))
            verifier.assert_not_called()

    def test_migration_complete_inventory(self):
        m = snapshot("repo-f44-20261011-001", assist() + dolphin())
        report = assess_manifest(m, REGISTRY)
        self.assertEqual(report["canonical_closure"], "PASS")
        self.assertEqual(set(report["groups"]), {"ro-assist", "ro-kde-dolphin"})

    def test_migration_missing_arch_and_source_are_real_blockers(self):
        for missing in ("aarch64", "src"):
            m = snapshot("repo-f44-20261011-001", [p for p in assist() if p["architecture"] != missing])
            self.assertEqual(assess_manifest(m, REGISTRY)["canonical_closure"], "FAIL")

    def test_migration_cannot_replace_an_unrelated_group(self):
        p = {"packages": assist() + dolphin()}
        self.reject(lambda: assert_preserved(p, {"packages": assist()}))

    def test_legacy_whole_snapshot_writer_blocks_activation(self):
        self.assertEqual(writer_gate(legacy_active=True, writer_realms=["v2", "v3"], immutable_clients=True, protected_import=True), "BLOCKED")

    def test_retirement_patch_is_complete_but_unapplied(self):
        path = pathlib.Path(__file__).parents[1] / ".github/workflows/promote-remote-stable.yml"
        before = path.read_bytes()
        patch = retirement_patch(path)
        self.assertEqual(patch.count("+    if: ${{ false }}"), 4)
        self.assertEqual(before, path.read_bytes())

    def test_upstream_rejects_unpinned_input_before_rpm_execution(self):
        self.reject(lambda: verify_upstream(self.fx.source, {}, None, rpm_key="missing", rpm_key_sha256="a"*64, now=NOW))

    def test_upstream_path_traversal_symlinks_rejected(self):
        (self.fx.source / "link").symlink_to("/etc/passwd")
        for path in ("../x", "/etc/passwd", "link", "a/../../x", "a\\b"):
            self.reject(lambda: member(self.fx.source, path))

    def test_upstream_metadata_checksums_enforced(self):
        root = self.fx.source
        (root / "repodata").mkdir()
        (root / "repodata/primary.xml").write_bytes(b"pinned")
        xml = '<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><checksum type="sha256">'+digest(b"pinned")+'</checksum><location href="repodata/primary.xml"/></data></repomd>'
        (root / "repodata/repomd.xml").write_text(xml)
        repomd_members(root, digest(xml.encode()))
        (root / "repodata/primary.xml").write_bytes(b"substituted")
        self.reject(lambda: repomd_members(root, digest(xml.encode())))

    def test_upstream_external_entity_rejected(self):
        (self.fx.source / "repodata").mkdir()
        raw = b'<!DOCTYPE x [<!ENTITY y SYSTEM "file:///etc/passwd">]><x>&y;</x>'
        (self.fx.source / "repodata/repomd.xml").write_bytes(raw)
        self.reject(lambda: repomd_members(self.fx.source, digest(raw)))

    def test_upstream_primary_cannot_fetch_an_unpinned_local_rpm(self):
        for path in ("../../../other.rpm", "file:///tmp/other.rpm", "https://evil.invalid/other.rpm", "%2e%2e/other.rpm"):
            raw = ('<metadata xmlns="http://linux.duke.edu/metadata/common"><package><name>bash</name><arch>x86_64</arch><version epoch="0" ver="1" rel="1"/><checksum type="sha256">'+'a'*64+'</checksum><location href="'+path+'"/></package></metadata>')
            (self.fx.source / "primary.xml").write_text(raw)
            self.reject(lambda: primary_inventory(self.fx.source, "primary.xml", [{"path":"bash.rpm","nevra":"bash-0:1-1.x86_64","sha256":"a"*64}]))

    def test_upstream_primary_checksum_nevra_and_location_match(self):
        raw = '<metadata xmlns="http://linux.duke.edu/metadata/common"><package><name>bash</name><arch>x86_64</arch><version epoch="0" ver="1" rel="1"/><checksum type="sha256">'+'a'*64+'</checksum><location href="bash.rpm"/></package></metadata>'
        (self.fx.source / "primary.xml").write_text(raw)
        package = {"path":"bash.rpm","nevra":"bash-0:1-1.x86_64","sha256":"a"*64}
        primary_inventory(self.fx.source, "primary.xml", [package])
        self.reject(lambda: primary_inventory(self.fx.source, "primary.xml", [{**package,"sha256":"b"*64}]))

    def test_real_artifacts_cannot_fall_back_to_system_upstream(self):
        from v3_real_acceptance import execute
        spec = {"schema_version":3,"scope":"v3-real-acceptance-inputs","promotion_group":"ro-assist","architecture":"x86_64",
                "snapshot_tree_sha256":"a"*64,"beta_tree_sha256":"a"*64,"baseline_tree_sha256":None,"plan_sha256":sha(self.fx.plan),"registry_sha256":sha(self.fx.registry),"config_paths":[]}
        with mock.patch("v3_real_acceptance.validate") as dnf:
            self.reject(lambda: execute(spec,snapshot=self.fx.source,baseline=None,beta=self.fx.source,plan=self.fx.plan,
                        registry=self.fx.registry,upstream=[],input_attestation=None,rpm_key="missing",rpm_key_sha256="a"*64,
                        metadata_key="missing",metadata_key_sha256="b"*64,output=self.fx.root/"output",now=NOW))
            dnf.assert_not_called()

    def test_unknown_vm_case_never_executes(self):
        agent = Agent("/missing/socket")
        with mock.patch.object(agent, "call") as call:
            self.reject(lambda: agent.execute("claim-green", 1))
            call.assert_not_called()

    def test_vm_truncated_output_is_failure(self):
        agent = Agent("/unused")
        with mock.patch.object(agent, "call", side_effect=[{"pid": 1}, {"exited": True, "exitcode": 0, "out-truncated": True}]):
            self.reject(lambda: agent.execute("plasma-integration", 1))

    def test_vm_claim_without_real_observations_is_failure(self):
        import base64
        agent = Agent("/unused")
        log = base64.b64encode(canonical({"case": "login-session", "result": "PASS", "observations": {}})).decode()
        with mock.patch.object(agent, "call", side_effect=[{"pid": 1}, {"exited": True, "exitcode": 0, "out-data": log}]):
            self.reject(lambda: agent.execute("login-session", 1))

    def test_new_schemas_reject_unknown_properties(self):
        import jsonschema
        root = pathlib.Path(__file__).parents[1] / "schemas"
        for name in ("backend-attempt-v3", "immutable-publication-v3", "pinned-upstream-v3", "real-acceptance-v3", "vm-acceptance-v3", "backend-envelope-v3"):
            schema = json.loads((root / (name + ".schema.json")).read_bytes())
            jsonschema.Draft202012Validator.check_schema(schema)
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate({"approved": True}, schema)


if __name__ == "__main__":
    unittest.main()
