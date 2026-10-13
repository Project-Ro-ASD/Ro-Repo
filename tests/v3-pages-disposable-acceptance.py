"""Prepared cloud test; NEVER run without explicit operator authorization.

Creates no repositories/settings/credentials. Requires a precreated marked test
repo, App token selected ONLY for it, seeded disposable-pages ref/Pages source.
Writes synthetic test-only immutable objects there; no production repo allowed.
"""
import argparse
import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from v3_backend_support import Keys, Fixture, NOW
from v3_backend_trust import canonical
from v3_branch_pages import BranchPagesIdentity
from v3_github_provider import GitHubStorage
from v3_immutable_view import DisposablePagesProject, IsolatedStore, HTTPSReader
from v3_provider_transport import ProviderTransport
from v3_promotion_planner import PlanningError
from v3_pages_finalization_support import fresh_authority


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--operator-authorized", action="store_true")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", required=True, type=int)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if not args.operator_authorized or args.output.exists():
        raise PlanningError("explicit operator authorization and new immutable output required")
    token = os.environ.get("RO_V3_DISPOSABLE_APP_TOKEN")
    expiry = int(os.environ.get("RO_V3_DISPOSABLE_APP_TOKEN_EXPIRY", "0"))
    if not token or not 0 < expiry-time.time() <= 3600:
        raise PlanningError("operator-provisioned short-lived single-test-repo App token required")
    keys = Keys()
    fx = None
    try:
        fx = Fixture(keys)
        project = DisposablePagesProject(root=fx.root, repository=args.repository,
                                         operator_authorized=args.operator_authorized)
        project.base_url(args.origin)
        transport = ProviderTransport("https://api.github.com", lambda:(token, expiry), time.time)
        storage = GitHubStorage.disposable_acceptance(transport, root=keys.root, operator_authorized=True,
            repository=args.repository, repository_id=args.repository_id, node_id=args.node_id, ref="refs/heads/disposable-pages")
        identity = BranchPagesIdentity(storage, branch="disposable-pages")
        identity.settings()
        base = storage.head()
        before = storage.files(base)
        if ".nojekyll" not in before:
            raise PlanningError("operator must seed static-file branch source with .nojekyll")
        # Synthetic fixture capabilities use their explicit TEST clock; provider
        # credentials and actual network observations use real UTC separately.
        fx.now = int(time.time())
        fx.evidence, fx.result, fx.approval = fresh_authority(fx, fx.attempt)
        fx.advance("AUTHORIZED")
        view = IsolatedStore(fx.root).stage(fx.result, fx.approval, keys.signers["publication"],
            origin=args.origin, audit_key_sha256=keys.signers["audit"].key_sha256, now=fx.now,
            disposable_project=project)
        receipt = storage.stage(view, fx.approval, expected=base, publication_key=keys.signers["publication"].public,
                                publication_pin=keys.signers["publication"].key_sha256, now=fx.now)
        commit = receipt["git_commit"]
        after = storage.files(commit)
        if any(after.get(path) != sha for path,sha in before.items()):
            raise PlanningError("cloud test lost preexisting signed bytes")
        facts = None
        deadline = min(time.time()+600, expiry)
        while time.time() < deadline:
            builds = transport.request("GET", storage.base+"/pages/builds?per_page=100", allow_list=True)
            deployments = transport.request("GET", storage.base+"/deployments?environment=github-pages&per_page=100", allow_list=True)
            runs = transport.request("GET", storage.base+"/actions/runs?branch=disposable-pages&per_page=100")["workflow_runs"]
            build = next((v for v in builds if v.get("commit")==commit and v.get("status")=="built"), None)
            deployment = next((v for v in deployments if v.get("sha")==commit), None)
            run = next((v for v in runs if v.get("head_sha")==commit and v.get("conclusion")=="success"), None)
            if build and deployment and run:
                facts = identity.identify(commit, build_id=build["url"].rsplit("/",1)[1], deployment_id=str(deployment["id"]), run_id=str(run["id"]))
                break
            time.sleep(3)
        if facts is None:
            raise PlanningError("App CAS did not yield exact branch Pages deployment within acceptance bound")
        reader = HTTPSReader(args.origin, view.sha256, fx.attempt, disposable_project=project)
        if reader.publication()!=view.envelope or any(reader.read(i["path"])!=(view.path/"payload"/i["path"]).read_bytes() for i in view.result.inventory):
            raise PlanningError("build success without exact public immutable bytes")
        args.output.write_bytes(canonical({"scope":"disposable-cloud-branch-positive-acceptance", "publishable":False,
            "provider":facts, "app_trigger_and_cas":"PASS", "synthetic_public_bytes":"PASS",
            "late_build_ordering":"UNVERIFIED", "provider_deadline_fencing":"UNVERIFIED", "production_activation":"BLOCKED"}))
    finally:
        if fx is not None:
            fx.close()
        keys.close()


if __name__ == "__main__":
    main()
