"""Read-only GitHub API collector for V3 beta workflow-run/job evidence.

Never grants publication authority. Caller must separately verify signed
publication manifests and completeness of the immutable Pages archive.
"""
import argparse
import datetime
import json
import os
import pathlib
import re
import urllib.error
import urllib.parse
import urllib.request

from v3_promotion_planner import PlanningError
from v3_github_beta_audit import validate_history

REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RUN = re.compile(r"^[1-9][0-9]*$")
WORKFLOW = "publish-remote-beta.yml"


def collect(repository, token, request_json, *, page_size=100):
    if not REPO.fullmatch(repository) or not token:
        raise PlanningError("missing trusted GitHub API repository/token")
    runs = []
    seen = set()
    page = 1
    while True:
        # A bounded page walk, never rely on the first response alone.
        if page > 100:
            raise PlanningError("GitHub Actions run pagination limit reached")
        path = f"/repos/{repository}/actions/workflows/{WORKFLOW}/runs?per_page={page_size}&page={page}"
        value = request_json(path, token)
        if not isinstance(value, dict) or not isinstance(value.get("total_count"), int) or not isinstance(value.get("workflow_runs"), list):
            raise PlanningError("invalid GitHub workflow response")
        entries = value["workflow_runs"]
        if len(entries) > page_size:
            raise PlanningError("unexpected GitHub pagination size")
        for item in entries:
            if not isinstance(item, dict) or not RUN.fullmatch(str(item.get("id", ""))):
                raise PlanningError("invalid workflow run record")
            rid = str(item["id"])
            if rid in seen:
                raise PlanningError("duplicate GitHub run across pages")
            seen.add(rid)
            runs.append(item)
        if len(runs) >= value["total_count"]:
            if len(runs) != value["total_count"]:
                raise PlanningError("inconsistent total GitHub runs")
            break
        if not entries:
            raise PlanningError("truncated GitHub run pagination")
        page += 1
    # All successful publication runs, plus completed failed/cancelled attempts
    # retained in coverage counts, are fetched. No guessing archive completeness.
    successes = [r for r in runs if r.get("status") == "completed" and r.get("conclusion") == "success"]
    jobs_records = []
    for run in successes:
        rid = str(run["id"])
        page = 1
        jobs = []
        while True:
            if page > 100:
                raise PlanningError("GitHub job pagination limit reached")
            data = request_json(f"/repos/{repository}/actions/runs/{rid}/jobs?per_page={page_size}&page={page}", token)
            if not isinstance(data, dict) or not isinstance(data.get("total_count"), int) or not isinstance(data.get("jobs"), list):
                raise PlanningError("invalid GitHub job response")
            batch = data["jobs"]
            if len(batch) > page_size:
                raise PlanningError("unexpected job pagination size")
            jobs.extend(batch)
            if len(jobs) >= data["total_count"]:
                if len(jobs) != data["total_count"]:
                    raise PlanningError("inconsistent total jobs")
                break
            if not batch:
                raise PlanningError("truncated GitHub job pagination")
            page += 1
        jobs_records.append({"run_id":rid,"jobs":jobs})
    return {"scope":"v3-github-beta-api-collection-untrusted",
            "repository":repository,
            "total_workflow_runs":len(runs),
            "successful_runs":len(successes),
            "run_details":successes,
            "job_details":jobs_records,
            "api_response_immutability_verified":False,
            "archive_completeness_verified":False,
            "publishable":False}


def github_json(path, token):
    url = "https://api.github.com" + path
    req = urllib.request.Request(url, headers={
        "Authorization":"Bearer "+token,
        "Accept":"application/vnd.github+json",
        "X-GitHub-Api-Version":"2022-11-28",
        "User-Agent":"ro-repo-v3-audit"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except (OSError, urllib.error.HTTPError, ValueError) as exc:
        raise PlanningError("GitHub API collection failed") from exc


def audit(collection, signed_rows, now):
    if not isinstance(collection, dict) or collection.get("publishable") is not False:
        raise PlanningError("invalid collection")
    verified = validate_history(signed_rows, collection["run_details"], collection["job_details"], now)
    return {"scope":"v3-read-only-beta-api-audit",
            "checked_publications":len(verified),
            "github_run_job_metadata_consistent":True,
            "historical_enumeration_claimed":collection["total_workflow_runs"],
            "authenticated_api_source_requires_protected_runner":True,
            "remote_pages_bytes_rechecked":False,
            "publication_authorized":False,
            "publishable":False}


def main():
    p = argparse.ArgumentParser(description="Read-only GitHub beta metadata audit")
    p.add_argument("--repository",required=True)
    p.add_argument("--output",required=True)
    p.add_argument("--signed-history",help="optional trusted signed-history JSON (from separate GPG validation)")
    p.add_argument("--now",help="required with --signed-history")
    a=p.parse_args()
    token=os.environ.get("GITHUB_TOKEN")
    if not token:
        raise PlanningError("GITHUB_TOKEN required")
    result=collect(a.repository,token,github_json)
    if a.signed_history:
        if not a.now:
            p.error("--now required with --signed-history")
        result["audit"]=audit(result,json.loads(pathlib.Path(a.signed_history).read_text()),a.now)
    out=pathlib.Path(a.output)
    if out.exists() or out.is_symlink():
        raise PlanningError("refusing to overwrite audit file")
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps({"successful_runs":result["successful_runs"],"publishable":False}))


if __name__=="__main__":
    main()
