"""Read current GitHub/Pages facts without retrieving credentials or mutating.

GH handles existing read authorization; this script never requests a bearer,
creates a repo, changes settings, dispatches a build or writes a cloud ref.
"""
import argparse
import json
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]/"tools"))
from v3_backend_trust import digest, strict_json
from v3_branch_pages import BranchPagesIdentity
from v3_github_provider import GitHubStorage
from v3_immutable_view import HTTPSReader
from v3_provider_transport import ProviderTransport
from v3_promotion_planner import PlanningError


class GHRead(ProviderTransport):
    def __init__(self):
        super().__init__("https://api.github.com", lambda:None, time.time)

    def request(self, method, path, body=None, *, allow_list=False):
        if method != "GET" or body is not None or not path.startswith("/repos/Project-Ro-ASD/Ro-Repo"):
            raise PlanningError("read-only production facts audit rejects mutations")
        result = subprocess.run(["gh", "api", "--method", "GET", path.lstrip("/")], capture_output=True, timeout=30)
        if result.returncode:
            raise PlanningError("read-only GitHub API unavailable")
        return strict_json(result.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if args.output.exists():
        raise PlanningError("immutable read-only observation output already exists")
    transport = GHRead()
    repo = transport.request("GET", "/repos/Project-Ro-ASD/Ro-Repo")
    storage = GitHubStorage(transport, repository="Project-Ro-ASD/Ro-Repo", repository_id=1159460821,
                            node_id=repo["node_id"], ref="refs/heads/pages-storage")
    commit = storage.head()
    identity = BranchPagesIdentity(storage)
    settings = identity.settings()
    builds = transport.request("GET", storage.base + "/pages/builds?per_page=100", allow_list=True)
    deployments = transport.request("GET", storage.base + "/deployments?environment=github-pages&per_page=100", allow_list=True)
    runs = transport.request("GET", storage.base + "/actions/runs?branch=pages-storage&per_page=100")["workflow_runs"]
    build = next((v for v in builds if v["commit"] == commit and v["status"] == "built"), None)
    deployment = next((v for v in deployments if v["sha"] == commit and v["environment"] == "github-pages"), None)
    run = next((v for v in runs if v["head_sha"] == commit and v["path"] == "dynamic/pages/pages-build-deployment"), None)
    if None in (build, deployment, run):
        raise PlanningError("exact current Pages provider identities not found in bounded read")
    facts = identity.identify(commit, build_id=build["url"].rsplit("/",1)[1], deployment_id=str(deployment["id"]), run_id=str(run["id"]))
    files = storage.files(commit)
    reader = HTTPSReader("https://repo.ro-asd.org", "0"*64, "read-only-audit")
    public = {}
    for path in ("rpm/fedora/44/beta/publication-v1.json", "rpm/fedora/44/beta/publication-v1.json.asc"):
        raw = storage.blob(files[path])
        observed = reader._get(path, "https://repo.ro-asd.org/" + path)
        if raw != observed:
            raise PlanningError("current beta public bytes do not match exact Git commit")
        public[path] = digest(observed)
    identity.identify(commit, build_id=facts["build_id"], deployment_id=facts["deployment_id"], run_id=facts["run_id"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"scope":"read-only-current-pages-observation", "publishable":False,
        "observed_at":int(time.time()), "settings":settings, "provider":facts,
        "tree_entries":len(files), "current_stable_paths":[p for p in files if p=="v3/stable.json" or p.startswith(("v3/advertisements/", "rpm/fedora/44/stable/", "publications/fedora/44/stable/"))],
        "beta_publication_https_sha256":public, "full_beta_rpm_visibility":"UNVERIFIED",
        "app_push_trigger":"UNVERIFIED", "late_build_ordering":"UNVERIFIED", "historical_empty_stable":"UNVERIFIED"}, indent=2)+"\n")
    print("PASS: read-only actual Pages identities and two beta publication HTTPS byte comparisons; production BLOCKED")


if __name__ == "__main__":
    main()
