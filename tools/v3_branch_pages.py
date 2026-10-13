"""Read-only branch Pages identity and immutable advertisement verification.

Build/deployment/run API facts are observations, never cryptographic authority.
The independently signed deployment witness and every public byte are still
verified by the existing IndependentDeployment/verify_remote protocol.
"""
import re

from v3_github_provider import oid
from v3_immutable_view import HTTPSReader
from v3_protected_provider import IndependentDeployment
from v3_promotion_planner import PlanningError


def numeric(value):
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*", value):
        raise PlanningError("exact numeric GitHub provider identity required")
    return value


class BranchPagesIdentity:
    def __init__(self, storage, *, branch="pages-storage"):
        if storage.ref != "refs/heads/" + branch:
            raise PlanningError("Pages source and exact Git ref must agree")
        self.storage, self.branch = storage, branch

    def settings(self):
        self.storage.identity()
        value = self.storage.transport.request("GET", self.storage.base + "/pages")
        if value.get("build_type") != "legacy" or value.get("source") != {"branch": self.branch, "path": "/"}:
            raise PlanningError("branch Pages source changed; no silent fallback to deployment POST")
        return value

    def identify(self, commit, *, build_id, deployment_id, run_id):
        oid(commit)
        build_id, deployment_id, run_id = map(numeric, (build_id, deployment_id, run_id))
        self.settings()
        if self.storage.head() != commit:
            raise PlanningError("Pages candidate Git head changed")
        base, transport = self.storage.base, self.storage.transport
        build = transport.request("GET", base + "/pages/builds/" + build_id)
        deployment = transport.request("GET", base + "/deployments/" + deployment_id)
        run = transport.request("GET", base + "/actions/runs/" + run_id)
        # Status lists are deliberately not assumed complete. Fetch the latest
        # status by exact ID using the REST endpoint's ordered first page.
        statuses = transport.request("GET", base + "/deployments/" + deployment_id + "/statuses?per_page=1", allow_list=True)
        latest = statuses[0] if isinstance(statuses, list) and statuses else None
        if (build.get("commit") != commit or build.get("status") != "built" or build.get("error", {}).get("message") is not None or
                deployment.get("id") != int(deployment_id) or deployment.get("sha") != commit or
                deployment.get("ref") != self.branch or deployment.get("environment") != "github-pages" or
                run.get("id") != int(run_id) or run.get("head_sha") != commit or run.get("head_branch") != self.branch or
                run.get("path") != "dynamic/pages/pages-build-deployment" or run.get("event") != "dynamic" or
                run.get("status") != "completed" or run.get("conclusion") != "success" or
                latest is None or latest.get("state") != "success" or
                latest.get("log_url", "").split("/job/")[0] != "https://github.com/" + self.storage.repository + "/actions/runs/" + run_id):
            raise PlanningError("exact successful branch Pages build/deployment/run not established")
        return {"git_commit":commit, "build_id":build_id, "deployment_id":deployment_id, "run_id":run_id,
                "witness_deployment_id":"github-pages:" + build_id + ":" + deployment_id + ":" + run_id,
                "public_visibility":"UNVERIFIED", "production_activation":"BLOCKED"}

    def resolve(self, commit):
        """Bounded read; absence/pending build is an explicit retryable block."""
        oid(commit)
        transport,base=self.storage.transport,self.storage.base
        builds=transport.request("GET",base+"/pages/builds?per_page=100",allow_list=True)
        deployments=transport.request("GET",base+"/deployments?environment=github-pages&per_page=100",allow_list=True)
        runs=transport.request("GET",base+"/actions/runs?branch="+self.branch+"&per_page=100").get("workflow_runs",[])
        build=next((b for b in builds if b.get("commit")==commit and b.get("status")=="built"),None)
        deployment=next((d for d in deployments if d.get("sha")==commit and d.get("environment")=="github-pages"),None)
        run=next((r for r in runs if r.get("head_sha")==commit and r.get("path")=="dynamic/pages/pages-build-deployment" and r.get("conclusion")=="success"),None)
        if not build or not deployment or not run:
            raise PlanningError("exact branch Pages deployment not yet independently identifiable")
        return self.identify(commit,build_id=build["url"].rsplit("/",1)[1],deployment_id=str(deployment["id"]),run_id=str(run["id"]))


class BranchHTTPSReader(HTTPSReader):
    def __init__(self, origin, result_digest, attempt, *, authorization_sha256, check_deployment=lambda _:None):
        super().__init__(origin, result_digest, attempt)
        if not isinstance(authorization_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", authorization_sha256):
            raise PlanningError("exact immutable advertisement identity required")
        self.advertisement_url = origin.rstrip("/") + "/v3/advertisements/" + authorization_sha256 + ".json"
        self.check_deployment = check_deployment


class BranchPagesDeployment(IndependentDeployment):
    def __init__(self, *args, identity=None, **kwargs):
        super().__init__(*args,**kwargs)
        self.identity=identity

    def verify(self, view, commit, *, now, ledger=None, signer=None):
        if self.identity is None:
            raise PlanningError("independently pinned branch Pages identity adapter required")
        facts=self.identity.resolve(commit)
        return self.verify_branch(self.identity,view,commit,build_id=facts["build_id"],deployment_id=facts["deployment_id"],
                                  run_id=facts["run_id"],now=now,ledger=ledger,signer=signer)

    def verify_branch(self, identity, view, commit, *, build_id, deployment_id, run_id, now, ledger=None, signer=None):
        facts = identity.identify(commit, build_id=build_id, deployment_id=deployment_id, run_id=run_id)
        def check(expected):
            if expected != commit:
                raise PlanningError("branch deployment commit substitution")
            identity.identify(commit, build_id=build_id, deployment_id=deployment_id, run_id=run_id)
        def reader(origin, result, attempt):
            return BranchHTTPSReader(origin, result, attempt,
                authorization_sha256=view.descriptor["authorization_sha256"], check_deployment=check)
        return super().verify(view, commit, now=now, ledger=ledger, signer=signer, reader_factory=reader,
            expected_deployment_id=facts["witness_deployment_id"])
