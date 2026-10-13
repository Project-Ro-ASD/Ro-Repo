import copy
import concurrent.futures
import pathlib
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]/"tools"))
from v3_backend_support import Keys, Fixture, NOW
from v3_backend_trust import TestSigner, canonical, strict_json
from v3_branch_pages import BranchPagesIdentity, BranchPagesDeployment, BranchHTTPSReader
from v3_client_update import discovery_payload, Client
from v3_fenced_publisher import FencedPublisher, rehearsal_server
from v3_github_provider import GitHubStorage
from v3_immutable_view import IsolatedStore
from v3_pages_backend import ImmutableBranchStore, GitReader
from v3_pages_finalization_support import fresh_authority
from v3_provider_support import ProtocolServer
from v3_provider_transport import ProviderTransport, ProviderUnavailable, ProviderHTTPError
from v3_publication_outbox import Coordinator, SimulatedDeployment, Outbox
from v3_publication_backend import Backend
from v3_promotion_planner import PlanningError


class PagesFinalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = Keys()
        cls.observer = TestSigner(cls.keys.root, "finalization-observer")

    @classmethod
    def tearDownClass(cls):
        cls.keys.close()

    def setUp(self):
        self.fx = Fixture(self.keys)
        self.addCleanup(self.fx.close)
        self.api = ProtocolServer(self.fx, self.keys)
        self.addCleanup(self.api.close)
        self.storage = GitHubStorage.rehearsal(self.api.transport, root=self.fx.root,
            repository="test/disposable", repository_id=123, node_id="R_test", ref="refs/heads/isolated-storage")
        self.signer = self.keys.signers["publication"]

    def prepared(self, *, seconds=30):
        self.fx.advance("AUTHORIZED")
        self.view = IsolatedStore(self.fx.root).stage(self.fx.result, self.fx.approval, self.signer,
            origin="https://test.invalid", audit_key_sha256=self.keys.signers["audit"].key_sha256, now=self.fx.now)
        self.fx.backend.signed(self.fx.attempt, self.view)
        self.fx.backend.staged(self.fx.attempt, self.view)
        self.outbox = Outbox(self.fx.backend)
        self.outbox.enqueue(self.view, self.fx.approval, self.api.initial)
        self.fence = self.outbox.claim(self.fx.attempt, "worker", seconds=seconds)
        self.publisher = FencedPublisher(self.fx.backend, self.storage)

    def stage(self):
        return self.publisher.stage(self.view, self.fx.approval, self.signer, owner="worker", fence=self.fence)

    def test_real_boundary_rejects_second_worker_and_expired_lease(self):
        self.prepared()
        with self.assertRaises(PlanningError):
            self.outbox.claim(self.fx.attempt, "other")
        self.fx.now += 31
        with self.assertRaises(PlanningError):
            self.stage()
        self.assertEqual(self.storage.head(), self.api.initial)

    def test_two_distinct_publishers_share_one_storage_admission_realm(self):
        self.prepared()
        other=Fixture(self.keys,attempt="competing-publisher",version="0.2.6")
        self.addCleanup(other.close)
        other.ledger=self.fx.ledger
        other.backend=Backend(other.ledger)
        other.advance("AUTHORIZED")
        view=IsolatedStore(other.root).stage(other.result,other.approval,self.signer,origin="https://test.invalid",
            audit_key_sha256=self.keys.signers["audit"].key_sha256,now=NOW)
        other.backend.signed(other.attempt,view)
        other.backend.staged(other.attempt,view)
        outbox=Outbox(other.backend)
        outbox.enqueue(view,other.approval,self.api.initial)
        fence=outbox.claim(other.attempt,"other")
        def publish(args):
            v,a,o,f=args
            try:
                self.publisher.stage(v,a,self.signer,owner=o,fence=f)
                return "won"
            except PlanningError:
                return "blocked"
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results=list(pool.map(publish,[(self.view,self.fx.approval,"worker",self.fence),(view,other.approval,"other",fence)]))
        self.assertEqual(sorted(results),["blocked","won"])

    def test_expired_worker_request_arriving_over_http_has_no_git_effect(self):
        self.prepared(seconds=5)
        http = rehearsal_server(self.publisher, {self.fx.attempt:(self.view, self.fx.approval, self.signer)},
                                {"worker":{"token":"worker-only", "expires_at":NOW+100}})
        thread = threading.Thread(target=http.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(http.server_close)
        self.addCleanup(thread.join, 3)
        self.addCleanup(http.shutdown)
        transport = ProviderTransport.rehearsal("http://127.0.0.1:"+str(http.server_port),
            lambda:("worker-only", self.fx.now+30), lambda:self.fx.now, root=self.fx.root)
        self.fx.now += 6
        with self.assertRaises(ProviderHTTPError):
            transport.request("POST", "/v1/stage", {"attempt_id":self.fx.attempt, "fence":self.fence})
        self.assertEqual(self.storage.head(), self.api.initial)
        self.assertFalse(any(method=="POST" for method,_,_ in self.api.calls))

    def test_lease_expiring_during_upload_is_checked_again_before_cas(self):
        self.prepared(seconds=5)
        original = self.api.respond
        def delayed(method,path,body):
            response = original(method,path,body)
            if method=="POST" and path.endswith("/git/blobs"):
                self.fx.now += 6
            return response
        with patch.object(self.api, "respond", side_effect=delayed):
            with self.assertRaises(PlanningError):
                self.stage()
        self.assertEqual(self.storage.head(), self.api.initial)

    def test_lease_expiring_during_admission_audit_rolls_back_before_git_cas(self):
        self.prepared()
        audit=self.keys.signers["audit"]
        original=audit.sign
        def delayed(data):
            raw=original(data)
            if strict_json(data).get("operation")=="outbox-provider-admit":
                self.fx.now += 31
            return raw
        with patch.object(audit,"sign",side_effect=delayed):
            with self.assertRaises(PlanningError):
                self.stage()
        self.assertEqual(self.storage.head(),self.api.initial)
        self.assertNotIn("provider_intent",self.fx.ledger.inspect(self.fx.attempt)["attempt"]["proofs"]["OUTBOX"]["receipts"])

    def test_lost_git_response_reconciles_durable_service_owned_intent(self):
        self.prepared()
        self.api.lose_cas = True
        with self.assertRaises(ProviderUnavailable):
            self.stage()
        job = self.fx.ledger.inspect(self.fx.attempt)["attempt"]["proofs"]["OUTBOX"]
        self.assertEqual(job["receipts"]["provider_intent"]["status"], "IN_FLIGHT")
        self.fx.now += 31
        restarted = FencedPublisher(self.fx.backend, self.storage)
        self.assertEqual(restarted.reconcile(self.fx.attempt)["status"], "CONFIRMED")
        self.assertEqual(self.fx.ledger.inspect(self.fx.attempt)["attempt"]["state"], "STAGED")
        with self.assertRaises(PlanningError):
            discovery_payload(self.fx.ledger, self.view, "a"*64, origin="https://test.invalid")

    def test_unknown_request_at_old_head_blocks_all_successors(self):
        self.prepared()
        self.publisher._admit(self.fx.attempt, "worker", self.fence, "stage", self.api.initial, "a"*40)
        with self.assertRaises(PlanningError):
            self.publisher.reconcile(self.fx.attempt)
        self.fx.now += 31
        fence = self.outbox.claim(self.fx.attempt, "other")
        with self.assertRaises(PlanningError):
            self.publisher.stage(self.view, self.fx.approval, self.signer, owner="other", fence=fence)
        self.assertEqual(self.storage.head(), self.api.initial)

    def test_changed_git_head_leaves_unknown_intent_blocked(self):
        self.prepared()
        self.publisher._admit(self.fx.attempt, "worker", self.fence, "stage", self.api.initial, "a"*40)
        self.api.store._cas({"external-beta-history.asc":b"external signed history"}, self.api.initial)
        with self.assertRaises(PlanningError):
            self.publisher.reconcile(self.fx.attempt)

    def test_branch_staging_and_signed_records_preserve_all_previous_bytes(self):
        self.prepared()
        before = self.storage.files(self.api.initial)
        receipt = self.stage()
        deployment = self.keys.attestation("deployment", {"result_stable_sha256":self.view.sha256,
            "publication_sha256":self.view.envelope_sha256, "git_commit":receipt["git_commit"], "deployment_id":"test-only"})
        from v3_immutable_view import verify_remote, DirectoryReader
        remote = verify_remote(self.view, DirectoryReader(self.view), deployment, now=self.fx.now)
        self.fx.backend.remotely_verified(self.fx.attempt, remote)
        self.fx.backend.publish(self.fx.attempt, self.fx.approval)
        advertised = self.publisher.advertise(self.view, self.fx.approval, remote, self.signer, owner="worker", fence=self.fence)
        after = self.storage.files(advertised["git_commit"])
        self.assertEqual({p:after[p] for p in before}, before)
        self.assertIn("v3/advertisements/"+self.fx.approval.sha256+".json", after)
        self.assertNotIn("v3/stable.json", after)

    def branch_job(self, crash=None):
        self.prepared()
        self.branch = ImmutableBranchStore(self.fx.root)
        self.coordinator = Coordinator(self.fx.backend, self.branch, SimulatedDeployment(self.branch, self.keys.attestation))
        def inject(at):
            if at==crash:
                raise RuntimeError("interrupted first publication")
        return self.coordinator.run(self.view, self.fx.approval, self.signer, owner="worker", fence=self.fence, inject=inject)

    def reauthorization(self, *, attempt="fresh-first", mutate=None):
        self.fx.now += 301
        resume = self.fx.backend.first_resume_binding(self.fx.attempt)
        if mutate:
            resume = mutate(copy.deepcopy(resume))
        evidence, result, approval = fresh_authority(self.fx, attempt, operation="resume-first", resume=resume)
        raw = self.observer.envelope("restore-observation", {"resume":resume, "writers_fenced":True, "requests_drained":True,
            "issued_at":self.fx.now, "expires_at":self.fx.now+60})
        return evidence, result, approval, raw

    def apply_reauthorization(self, inputs, *, attempt="fresh-first"):
        evidence,result,approval,raw = inputs
        return self.fx.backend.reauthorize_first(attempt, evidence, result, approval,
            observation_raw=raw, observation_key=self.observer.public, observation_pin=self.observer.key_sha256)

    def test_expired_first_intent_gets_fresh_child_and_completes_without_reset(self):
        with self.assertRaises(RuntimeError):
            self.branch_job("after-git-advertisement")
        before = self.fx.ledger.inspect(self.fx.attempt)["attempt"]
        old_files = self.branch._files(self.branch.head())
        inputs = self.reauthorization()
        child = self.apply_reauthorization(inputs)
        self.assertEqual(child["state"], "AUTHORIZED")
        self.assertEqual(self.fx.ledger.inspect(self.fx.attempt)["attempt"], before)
        self.assertEqual(self.fx.ledger.inspect()["head"]["generation"], 1)
        with self.assertRaises(PlanningError):
            discovery_payload(self.fx.ledger, self.view, "a"*64, origin="https://test.invalid")
        evidence,result,approval,_ = inputs
        view = IsolatedStore(self.fx.root).stage(result, approval, self.signer, origin="https://test.invalid",
            audit_key_sha256=self.keys.signers["audit"].key_sha256, now=self.fx.now)
        self.fx.backend.signed("fresh-first", view)
        self.fx.backend.staged("fresh-first", view)
        outbox = Outbox(self.fx.backend)
        outbox.enqueue(view, approval, self.branch.head())
        fence = outbox.claim("fresh-first", "new-worker")
        self.coordinator.run(view, approval, self.signer, owner="new-worker", fence=fence)
        after = self.branch._files(self.branch.head())
        self.assertEqual({p:after[p] for p in old_files}, old_files)
        discovery = discovery_payload(self.fx.ledger, view, "b"*64, origin="https://test.invalid")
        self.assertEqual(discovery["generation"], 1)
        self.assertEqual(discovery["attempt_id"], "fresh-first")

    def test_crash_after_db_intent_can_be_reauthorized_idempotently(self):
        with self.assertRaises(RuntimeError):
            self.branch_job("after-db-intent")
        inputs = self.reauthorization()
        one = self.apply_reauthorization(inputs)
        self.assertEqual(self.apply_reauthorization(inputs), one)

    def test_stale_recovery_checkpoint_cannot_authorize_child(self):
        with self.assertRaises(RuntimeError):
            self.branch_job("after-db-intent")
        def mutate(resume):
            resume["checkpoint"]["sha256"]="a"*64
            return resume
        inputs = self.reauthorization(mutate=mutate)
        with self.assertRaises(PlanningError):
            self.apply_reauthorization(inputs)

    def test_reauthorization_rejects_new_jwt_reusing_consumed_jti(self):
        with self.assertRaises(RuntimeError):
            self.branch_job("after-db-intent")
        original=self.keys.oidc
        def replay(attempt,changes=None,**kwargs):
            return original(attempt,changes={**(changes or {}),"jti":"jti-"+self.fx.attempt},**kwargs)
        with patch.object(self.keys,"oidc",side_effect=replay):
            inputs=self.reauthorization()
        before=self.fx.ledger.inspect()
        with self.assertRaises(PlanningError):
            self.apply_reauthorization(inputs)
        self.assertEqual(self.fx.ledger.inspect(),before)

    def test_competing_fresh_children_cannot_fork_one_predecessor(self):
        with self.assertRaises(RuntimeError):
            self.branch_job("after-db-intent")
        inputs=self.reauthorization()
        self.apply_reauthorization(inputs)
        resume=self.fx.backend.first_resume_binding(self.fx.attempt)
        evidence,result,approval=fresh_authority(self.fx,"competing-child",operation="resume-first",resume=resume)
        raw=self.observer.envelope("restore-observation", {"resume":resume,"writers_fenced":True,"requests_drained":True,
            "issued_at":self.fx.now,"expires_at":self.fx.now+60})
        with self.assertRaises(PlanningError):
            self.apply_reauthorization((evidence,result,approval,raw),attempt="competing-child")

    def test_expired_unsigned_child_can_resume_via_new_child_without_reusing_parent(self):
        with self.assertRaises(RuntimeError):
            self.branch_job("after-db-intent")
        inputs=self.reauthorization()
        first=self.apply_reauthorization(inputs)
        self.fx.now += 301
        resume=self.fx.backend.first_resume_binding("fresh-first")
        evidence,result,approval=fresh_authority(self.fx,"next-fresh-child",operation="resume-first",resume=resume)
        raw=self.observer.envelope("restore-observation", {"resume":resume,"writers_fenced":True,"requests_drained":True,
            "issued_at":self.fx.now,"expires_at":self.fx.now+60})
        child=self.apply_reauthorization((evidence,result,approval,raw),attempt="next-fresh-child")
        self.assertEqual(child["immutable"]["resume"]["predecessor"],"fresh-first")
        self.assertEqual(self.fx.ledger.inspect("fresh-first")["attempt"],first)
        self.assertEqual(self.fx.ledger.inspect()["head"]["generation"],1)

    def test_failed_published_parent_is_preserved_while_fresh_child_is_added(self):
        with self.assertRaises(RuntimeError):
            self.branch_job("after-db-intent")
        self.fx.backend.fail(self.fx.attempt,"expired interrupted first deployment")
        failed=self.fx.ledger.inspect(self.fx.attempt)["attempt"]
        inputs=self.reauthorization()
        self.apply_reauthorization(inputs)
        self.assertEqual(self.fx.ledger.inspect(self.fx.attempt)["attempt"],failed)

    def test_reauthorization_requires_drained_requests_and_new_workload(self):
        with self.assertRaises(RuntimeError):
            self.branch_job("after-db-intent")
        evidence,result,approval,_ = self.reauthorization()
        resume=approval.payload["request"]["resume"]
        raw = self.observer.envelope("restore-observation", {"resume":resume, "writers_fenced":True, "requests_drained":False,
            "issued_at":self.fx.now, "expires_at":self.fx.now+60})
        with self.assertRaises(PlanningError):
            self.apply_reauthorization((evidence,result,approval,raw))
        with self.assertRaises(PlanningError):
            self.fx.backend.reauthorize_first("fresh-first", evidence,result,self.fx.approval,
                observation_raw=raw, observation_key=self.observer.public, observation_pin=self.observer.key_sha256)

    def test_expired_reauthorization_and_post_verified_bootstrap_are_rejected(self):
        with self.assertRaises(RuntimeError):
            self.branch_job("after-db-intent")
        inputs=self.reauthorization()
        self.fx.now += 301
        with self.assertRaises(PlanningError):
            self.apply_reauthorization(inputs)

    def test_discovery_rejects_out_of_order_or_missing_immutable_public_bytes(self):
        self.branch_job()
        self.assertEqual(self.fx.ledger.inspect(self.fx.attempt)["attempt"]["state"], "POST_VERIFIED")
        client=Client(self.fx.root, origin="https://test.invalid", discovery_key=self.observer.public,
            discovery_pin=self.observer.key_sha256, publication_key=self.signer.public, publication_pin=self.signer.key_sha256,
            rpm_key_url="file:///test/rpm.asc", metadata_key_url="file:///test/metadata.asc", clock=lambda:self.fx.now)
        def discovery(nonce):
            payload=discovery_payload(self.fx.ledger,self.view,nonce,origin="https://test.invalid")
            return self.observer.envelope("client-discovery", {**payload,"issued_at":self.fx.now,"expires_at":self.fx.now+60})
        with patch.object(GitReader,"read",side_effect=FileNotFoundError("older Pages build/CDN does not contain selected view")):
            with self.assertRaises(PlanningError):
                client.update(discovery, reader_factory=lambda *args:GitReader(self.branch,self.view))
        self.assertFalse((self.fx.root/"client-state.json").exists())
        with self.assertRaises(PlanningError):
            self.fx.backend.first_resume_binding(self.fx.attempt)

    def identity_facts(self, commit):
        base=self.storage.base
        self.api.handlers[base+"/pages"]=lambda m,b:(200,{"build_type":"legacy","source":{"branch":"isolated-storage","path":"/"}})
        self.api.handlers[base+"/pages/builds/1"]=lambda m,b:(200,{"commit":commit,"status":"built","error":{"message":None}})
        self.api.handlers[base+"/deployments/2"]=lambda m,b:(200,{"id":2,"sha":commit,"ref":"isolated-storage","environment":"github-pages"})
        self.api.handlers[base+"/actions/runs/3"]=lambda m,b:(200,{"id":3,"head_sha":commit,"head_branch":"isolated-storage",
            "path":"dynamic/pages/pages-build-deployment","event":"dynamic","status":"completed","conclusion":"success"})
        self.api.handlers[base+"/deployments/2/statuses"]=lambda m,b:(200,[{"state":"success","log_url":"https://github.com/test/disposable/actions/runs/3/job/4"}])
        return BranchPagesIdentity(self.storage,branch="isolated-storage")

    def test_branch_build_deployment_and_run_identity_match_exact_commit(self):
        identity=self.identity_facts(self.api.initial)
        facts=identity.identify(self.api.initial,build_id="1",deployment_id="2",run_id="3")
        self.assertEqual(facts["public_visibility"],"UNVERIFIED")
        self.api.store._cas({"new-build.asc":b"preserved bytes"},self.api.initial)
        with self.assertRaises(PlanningError):
            identity.identify(self.api.initial,build_id="1",deployment_id="2",run_id="3")

    def test_success_api_with_missing_public_bytes_is_not_deployment_verification(self):
        self.prepared()
        commit=self.stage()["git_commit"]
        identity=self.identity_facts(commit)
        self.api.handlers["/v1/deployment-observation"]=lambda m,b:(200,self.api.envelope(self.observer,"deployment",
            {**b,"deployment_id":"github-pages:1:2:3"}))
        deployment=BranchPagesDeployment(self.api.transport, public_key=self.observer.public,
            key_sha256=self.observer.key_sha256,origin="https://test.invalid")
        with patch.object(BranchHTTPSReader,"_get",side_effect=FileNotFoundError("CDN propagation delay")):
            with self.assertRaises(PlanningError):
                deployment.verify_branch(identity,self.view,commit,build_id="1",deployment_id="2",run_id="3",now=self.fx.now)

    def test_production_guards_and_disposable_cloud_authorization_are_explicit(self):
        self.prepared()
        with self.assertRaises(PlanningError):
            self.publisher.activate_production()
        transport=ProviderTransport("https://api.github.com",lambda:None,lambda:NOW)
        for authorized,repo in ((False,"test/ro-v3-disposable-example"),(True,"Project-Ro-ASD/Ro-Repo")):
            with self.assertRaises(PlanningError):
                GitHubStorage.disposable_acceptance(transport, root=self.fx.root,operator_authorized=authorized,
                    repository=repo,repository_id=123,node_id="R_test",ref="refs/heads/disposable-pages")


if __name__=="__main__":
    unittest.main()
