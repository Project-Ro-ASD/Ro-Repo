"""Real PSOP/GPG/ledger state tests; model RPMs, native RPM suite is separate."""
import copy
import json
import pathlib
import shutil
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from psop_client_support import ClientFixture, DirectoryReader
from psop_client import Client, issue_descriptor, member, verify_metadata_links
from psop_pages import HTTPSReader, ExternalScope, checked_origin, GHRead, verify_external
from v3_backend_trust import canonical, digest, strict_json, test_workspace
from v3_promotion_planner import PlanningError
from ro_repo import ContractError


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.fx = ClientFixture()
        self.rpm_model = mock.patch("psop_client.verify_signed_rpms")
        self.rpm_model.start()

    def tearDown(self):
        self.rpm_model.stop();self.fx.close()

    def apply(self, job, **kwargs):
        return self.fx.client.update(job.descriptor, reader=job.reader, **kwargs)

    def test_full_signed_identity_and_monotonic_atomic_successor(self):
        first = self.fx.publication();self.apply(first)
        second = self.fx.publication(version="2.0", previous=first);self.apply(second)
        state = self.fx.client.active();self.assertEqual(state["generation"], 2)
        repo = (self.fx.client.root / state["slot"] / "repos/ro-psop-test.repo").read_text()
        for flag in ("gpgcheck=1", "repo_gpgcheck=1", "sslverify=1", "skip_if_unavailable=0"):
            self.assertIn(flag, repo)
        self.assertIn(second.signed.data["result_sha256"], repo)
        self.assertNotIn("/stable", repo)

    def test_valid_old_descriptor_is_not_a_latest_proof_for_first_client(self):
        first = self.fx.publication();self.fx.publication(version="2.0", previous=first)
        result = self.apply(first)
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["global_latest"], "UNVERIFIED")

    def test_signed_old_replay_and_generation_rollback_leave_state_unchanged(self):
        first = self.fx.publication();self.apply(first)
        second = self.fx.publication(version="2.0", previous=first);self.apply(second)
        before = (self.fx.client.root / "active.json").read_bytes()
        for job in (first, second):
            with self.assertRaisesRegex(PlanningError, "replay/rollback"):
                self.apply(job)
        self.assertEqual((self.fx.client.root / "active.json").read_bytes(), before)

    def test_expiry_and_unknown_signed_fields_cannot_start_dnf(self):
        first = self.fx.publication(seconds=30)
        invalid = self.fx.resign_descriptor(first.descriptor, approved=True)
        with self.assertRaises(ContractError):
            self.fx.client.update(invalid, reader=first.reader)
        self.fx.now += 31
        with self.assertRaisesRegex(PlanningError, "expired"):
            self.apply(first, operation="install", packages=["fixture"])
        self.assertIsNone(self.fx.client.active())

    def test_descriptor_wrong_result_receipt_or_metadata_root_rejected_even_signed(self):
        first = self.fx.publication()
        d = strict_json(first.descriptor)["payload"]
        receipt = {**d["receipt"], "result_sha256": "f" * 64}
        for change in ({"result_sha256": "f" * 64}, {"receipt": receipt, "receipt_sha256": __import__('v3_policy_profile').sha(receipt)},
                       {"metadata_key": {"sha256": self.fx.rpm.pin, "fingerprint": self.fx.rpm.fingerprint}},
                       {"previous_generation": 5}):
            with self.subTest(change=change), self.assertRaises(PlanningError):
                self.fx.client.update(self.fx.resign_descriptor(first.descriptor, **change), reader=first.reader)

    def test_descriptor_wrong_role_domain_signature_or_plain_json_rejected(self):
        first = self.fx.publication();d = strict_json(first.descriptor)
        cases = [canonical({"approved": True}), canonical({**d, "domain": "ro-repo-v3"}),
                 self.fx.context.envelope("source", {k: v for k, v in d["payload"].items() if k not in {"issued_at", "expires_at"}}, now=self.fx.now)]
        broken = copy.deepcopy(d);broken["payload"]["generation"] = 999;cases.append(canonical(broken))
        for raw in cases:
            with self.assertRaises((PlanningError, ContractError)):
                self.fx.client.update(raw, reader=first.reader)

    def test_missing_mixed_and_wrong_publication_preserve_active_repo_and_state(self):
        first = self.fx.publication();self.apply(first)
        second = self.fx.publication(version="2.0", previous=first)
        before = self.fx.client.active()
        for mutate in (lambda p, b: b + b"corrupt", lambda p, b: (_ for _ in ()).throw(FileNotFoundError(p))):
            reader = DirectoryReader(second.signed, second.reader.raw, mutation=mutate)
            with self.assertRaises((PlanningError, OSError)):
                self.fx.client.update(second.descriptor, reader=reader)
        with self.assertRaisesRegex(PlanningError, "publication identity"):
            self.fx.client.update(second.descriptor, reader=DirectoryReader(second.signed, first.reader.raw))
        self.assertEqual(self.fx.client.active(), before)

    def test_wrong_preinstalled_key_hash_and_role_fail_closed(self):
        first = self.fx.publication()
        p = pathlib.Path(self.fx.roots["metadata"]["path"]);p.write_bytes(p.read_bytes() + b" ")
        with self.assertRaisesRegex(PlanningError, "key pin"):
            self.apply(first)

    def test_prepare_failure_preserves_old_pointer_and_creates_no_pending(self):
        first = self.fx.publication();self.apply(first)
        second = self.fx.publication(version="2.0", previous=first)
        before = self.fx.client.active()
        def fail(stage):
            if stage == "after-preparation":raise RuntimeError("preparation fault")
        with self.assertRaisesRegex(RuntimeError, "preparation"):
            self.apply(second, inject=fail)
        self.assertEqual(self.fx.client.active(), before)
        self.assertFalse((self.fx.client.root / "pending.json").exists())

    def test_crash_journal_blocks_switch_and_exact_resume_commits(self):
        first = self.fx.publication()
        def fail(stage):
            if stage == "after-journal":raise RuntimeError("process stopped")
        with self.assertRaises(RuntimeError):self.apply(first, inject=fail)
        self.assertIsNone(self.fx.client.active())
        with self.assertRaisesRegex(PlanningError, "resume required"):
            self.apply(first)
        self.apply(first, resume=True)
        self.assertEqual(self.fx.client.active()["generation"], 1)

    def test_crash_after_active_pointer_is_recovered_without_second_transaction(self):
        first = self.fx.publication()
        def fail(stage):
            if stage == "after-active":raise RuntimeError("process stopped")
        with self.assertRaises(RuntimeError):self.apply(first, inject=fail)
        result = self.apply(first, resume=True)
        self.assertTrue(result["recovered_active_commit"])
        self.assertFalse((self.fx.client.root / "pending.json").exists())

    def test_actual_process_death_journal_and_active_commit_recover_after_restart(self):
        first = self.fx.publication()
        config = {"origin": self.fx.origin, "context": self.fx.context.pin,
            "publication_key": self.fx.context.signer("publication").public.decode(),
            "publication_pin": self.fx.context.signer("publication").key_sha256,
            "roots": self.fx.roots, "now": self.fx.now, "descriptor": first.descriptor.decode(),
            "signed": str(first.signed.path), "publication": first.reader.raw.decode()}
        program = '''import sys,json,pathlib,types,os
from unittest import mock
sys.path[:0]=[sys.argv[1]+"/tools",sys.argv[1]+"/tests"]
from psop_client import Client
from psop_client_support import DirectoryReader
v=json.loads(pathlib.Path(sys.argv[2]).read_text())
c=Client(sys.argv[3],origin=v["origin"],context=v["context"],publication_key=v["publication_key"].encode(),publication_pin=v["publication_pin"],roots=v["roots"],clock=lambda:v["now"])
r=DirectoryReader(types.SimpleNamespace(path=pathlib.Path(v["signed"])),v["publication"].encode())
def crash(stage):
 if stage==sys.argv[4]:os._exit(87)
with mock.patch("psop_client.verify_signed_rpms"):
 c.update(v["descriptor"].encode(),reader=r,inject=crash)
'''
        cfg = self.fx.context.path("child-client-config");cfg.write_bytes(canonical(config))
        for stage in ("after-journal", "after-active"):
            root = test_workspace()
            try:
                result = subprocess.run([sys.executable, "-c", program, str(pathlib.Path(__file__).parents[1]), str(cfg), str(root), stage], capture_output=True)
                self.assertEqual(result.returncode, 87, result.stderr.decode())
                client = self.fx.make_client(root=root)
                self.assertEqual(client.active() is None, stage == "after-journal")
                client.update(first.descriptor, reader=first.reader, resume=True)
                self.assertEqual(client.active()["generation"], 1)
                self.assertFalse((root / "pending.json").exists())
            finally:
                shutil.rmtree(root)

    def test_new_generation_does_not_automatically_authorize_package_downgrade(self):
        first = self.fx.publication(version="2.0");self.apply(first)
        second = self.fx.publication(version="1.0", previous=first)
        with self.assertRaisesRegex(PlanningError, "downgrade"):
            self.apply(second)
        self.assertEqual(self.fx.client.active()["generation"], 1)

    def test_expiry_during_preparation_starts_no_transaction_and_preserves_state(self):
        first = self.fx.publication(seconds=10)
        def expire(stage):
            if stage == "after-preparation":self.fx.now += 11
        with self.assertRaisesRegex(PlanningError, "expired before transaction"):
            self.apply(first, inject=expire)
        self.assertIsNone(self.fx.client.active())
        self.assertFalse((self.fx.client.root / "pending.json").exists())

    def test_arbitrary_dnf_flags_packages_and_downgrade_are_not_an_api(self):
        first = self.fx.publication()
        for operation, packages in (("downgrade", ["fixture"]), ("install", ["--nogpgcheck"]), ("upgrade", [])):
            with self.assertRaises(PlanningError):
                self.apply(first, operation=operation, packages=packages)
        self.assertIsNone(self.fx.client.active())

    def test_symlink_state_and_installroot_are_rejected(self):
        first = self.fx.publication()
        target = self.fx.client.root / "target";target.write_text("{}")
        (self.fx.client.root / "active.json").symlink_to(target)
        with self.assertRaisesRegex(PlanningError, "unsafe active"):
            self.apply(first)
        (self.fx.client.root / "active.json").unlink()
        (self.fx.client.root / "dnf-root").symlink_to("/")
        with self.assertRaisesRegex(PlanningError, "installroot"):
            self.apply(first, operation="install", packages=["fixture"])

    def test_production_origins_and_unsafe_inventory_members_rejected(self):
        for origin in ("https://repo.ro-asd.org", "https://localhost:18443/stable", "http://localhost:18443", "https://user@localhost:18443"):
            with self.assertRaises(PlanningError):checked_origin(origin)
        for path in ("../rpm", "rpm//a", "https://evil.invalid/a", "rpm/%2e%2e/a", "rpm/a\n", "file:a.rpm", "repodata/file:metadata.gz"):
            with self.assertRaises(PlanningError):member(path)

    def test_signed_metadata_url_override_is_rejected(self):
        first = self.fx.publication();stage = first.signed.path
        path = stage / "rpm/x86_64/repodata/repomd.xml"
        path.write_text(path.read_text().replace('href="repodata/primary.xml.gz"', 'href="https://evil.invalid/primary.xml.gz"'))
        with self.assertRaises(PlanningError):verify_metadata_links(stage, {})


class ExternalBoundaryTests(unittest.TestCase):
    def inventory(self):
        return {"repository": "tester/ro-psop-disposable-fixture", "repository_id": 1234, "node_id": "R_test",
            "branch": "psop-disposable-fixture", "origin": "https://tester.github.io/ro-psop-disposable-fixture",
            "operator": "fixture-only model authorization", "authorized_until": 200, "purpose": "read-only-psop-disposable-acceptance"}

    def test_external_inventory_cannot_select_production_and_expired_permission(self):
        for change in ({"repository": "Project-Ro-ASD/Ro-Repo"}, {"repository_id": 1159460821},
                       {"branch": "pages-storage"}, {"origin": "https://repo.ro-asd.org"}, {"authorized_until": 99}):
            with self.subTest(change=change), self.assertRaises(PlanningError):
                ExternalScope({**self.inventory(), **change}, now=100)

    def test_external_reader_cannot_mutate_or_expand_get_scope(self):
        scope = ExternalScope({**self.inventory(), "authorized_until": __import__('time').time_ns() // 10**9 + 100}, now=__import__('time').time_ns() // 10**9)
        transport = GHRead(scope)
        for method, path in (("POST", transport.base + "/pages/builds"), ("GET", "/repos/Project-Ro-ASD/Ro-Repo/pages"),
                             ("GET", transport.base + "/actions/secrets")):
            with mock.patch("subprocess.run") as external, self.assertRaises(PlanningError):
                transport.request(method, path)
            external.assert_not_called()


class ExternalIdentityModelTests(unittest.TestCase):
    """No external access/authorization: mocked REST observations, real crypto."""
    def setUp(self):
        self.fx = ClientFixture();self.rpm_model = mock.patch("psop_client.verify_signed_rpms");self.rpm_model.start()
        self.scope = ExternalScope(ExternalBoundaryTests().inventory(), now=100)
        self.origin = self.scope.value["origin"]
        self.job = self.fx.publication(origin=self.origin, scope=self.scope)
        self.client = self.fx.make_client(origin=self.origin, scope=self.scope)
        self.mutations = {}

    def tearDown(self):
        self.rpm_model.stop();self.fx.close()

    def transport(self, scope):
        import base64
        from v3_backend_trust import digest
        fx, job = self.fx, self.job
        record = fx.ledger.inspect(job.attempt)["attempt"]["prepared"]
        commit = record["target_git"]
        tree = fx.gateway._store._run(["rev-parse", commit + "^{tree}"]).decode().strip()
        branch = scope.value["branch"]
        root = "/repos/" + scope.value["repository"]
        requests, mutations = [], self.mutations
        class FakeRead(GHRead):
            def request(self, method, path, body=None, **kwargs):
                if method != "GET" or body is not None:raise AssertionError("mutation")
                requests.append(path);suffix = path[len(root):]
                v = {"": {"id": 1234, "node_id": "R_test", "full_name": scope.value["repository"], "description": "RO PSOP DISPOSABLE ACCEPTANCE ONLY"},
                    "/pages": {"build_type": "legacy", "source": {"branch": branch, "path": "/"}},
                    "/git/ref/heads/" + branch: {"ref": "refs/heads/" + branch, "object": {"type": "commit", "sha": commit}},
                    "/pages/builds/11": {"commit": commit, "status": "built", "error": {"message": None}},
                    "/deployments/12": {"id": 12, "sha": commit, "ref": branch, "environment": "github-pages"},
                    "/actions/runs/13": {"id": 13, "head_sha": commit, "head_branch": branch, "path": "dynamic/pages/pages-build-deployment", "event": "dynamic", "status": "completed", "conclusion": "success"},
                    "/deployments/12/statuses?per_page=1": [{"state": "success", "log_url": "https://github.com/" + scope.value["repository"] + "/actions/runs/13/job/14"}],
                    "/git/commits/" + commit: {"sha": commit, "tree": {"sha": tree}},
                    "/git/trees/" + tree + "?recursive=1": {"sha": tree, "truncated": False, "tree": [{"path": p, "sha": h, "type": "blob", "mode": "100644"} for p, h in record["target_files"].items()]}}
                if suffix.startswith("/git/blobs/"):
                    oid = suffix.rsplit("/", 1)[1];raw = fx.gateway._store._run(["cat-file", "blob", oid])
                    value = {"sha": oid, "encoding": "base64", "content": base64.b64encode(raw).decode(), "size": len(raw)}
                else:value = copy.deepcopy(v[suffix])
                if suffix in mutations:value = mutations[suffix](value, requests)
                self.observations[path] = digest(canonical(value))
                return value
        return FakeRead(scope)

    def run_model(self):
        target = self.fx.gateway.receipt(self.job.attempt)["target_git"]
        with mock.patch("psop_pages.GHRead", side_effect=self.transport), mock.patch("psop_pages.HTTPSReader", return_value=self.job.reader):
            return verify_external(self.scope, self.client, self.job.descriptor, commit=target, build_id="11", deployment_id="12", run_id="13")

    def test_exact_git_build_run_and_all_public_bytes_are_required(self):
        report = self.run_model()
        self.assertEqual(report["status"], "PASS_OBSERVATION")
        self.assertEqual(report["global_cdn_freshness"], "UNVERIFIED")
        self.mutations["/actions/runs/13"] = lambda v, _: {**v, "head_sha": "f" * 40}
        with self.assertRaisesRegex(PlanningError, "build/deployment/run"):
            self.run_model()

    def test_successful_old_build_appearing_after_full_probe_is_rejected(self):
        def old_build(v, requests):
            if len([p for p in requests if p.endswith("/pages/builds/11")]) > 1:
                return {**v, "commit": "f" * 40}
            return v
        self.mutations["/pages/builds/11"] = old_build
        with self.assertRaisesRegex(PlanningError, "build/deployment/run"):
            self.run_model()


if __name__ == "__main__":
    unittest.main()
