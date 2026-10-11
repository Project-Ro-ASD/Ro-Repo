"""Test-only GitHub Actions runtime identity cross-check, never an approval.

Run from the dedicated workflow_dispatch job on main with read-only API scopes.
Compare GitHub-provided runner environment claims against live API run/job/ref
metadata and reject missing, changed, duplicate, stale or replayed identities.

This is NOT a signed OIDC/Sigstore attestation, trusted runner proof, or proof
of human authorization. Produces no production publication authority.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re

from v3_github_beta_api import github_json
from v3_promotion_planner import PlanningError
from v3_promotion_policy import _time

REPO = "Project-Ro-ASD/Ro-Repo"
REPOSITORY_ID = 1159460821
WORKFLOW = ".github/workflows/v3-readonly-context-audit.yml"
JOB = "audit-identity"
RUN_ID = re.compile(r"^[1-9][0-9]*$")
SHA = re.compile(r"^[0-9a-f]{40}$")
BASE = "/repos/" + REPO
REQUIRED_ENV = (
    "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID",
    "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_SHA",
    "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW_REF",
    "GITHUB_JOB", "GITHUB_ACTOR", "RUNNER_NAME", "RUNNER_GROUP_NAME",
)


def _positive(value):
    return (type(value) is int and value > 0
            or isinstance(value, str) and RUN_ID.fullmatch(value) is not None)


def _api(request_json, token, path):
    try:
        value = request_json(path, token)
    except PlanningError:
        raise
    except Exception as exc:
        raise PlanningError("GitHub runtime API fetch failed") from exc
    if not isinstance(value, dict):
        raise PlanningError("malformed GitHub runtime API response")
    return value


def _ref(request_json, token):
    data = _api(request_json, token, BASE + "/git/ref/heads/main")
    obj = data.get("object")
    if (data.get("ref") != "refs/heads/main"
            or not isinstance(obj, dict) or obj.get("type") != "commit"
            or not isinstance(obj.get("sha"), str) or not SHA.fullmatch(obj["sha"])):
        raise PlanningError("invalid GitHub main ref response")
    return obj["sha"]


def _run_jobs(request_json, token, run_id, page_size=100):
    records, seen = [], set()
    page, count = 1, None
    while True:
        if page > 100:
            raise PlanningError("GitHub job pagination limit exceeded")
        data = _api(
            request_json, token,
            BASE + "/actions/runs/" + run_id + "/jobs?per_page="
            + str(page_size) + "&page=" + str(page),
        )
        total = data.get("total_count")
        jobs = data.get("jobs")
        if (type(total) is not int or total < 1 or total > 10000
                or not isinstance(jobs, list) or len(jobs) > page_size):
            raise PlanningError("malformed GitHub runtime jobs page")
        if count is None:
            count = total
        elif count != total:
            raise PlanningError("GitHub job total changed during pagination")
        for job in jobs:
            ident = job.get("id") if isinstance(job, dict) else None
            if not _positive(ident) or str(ident) in seen:
                raise PlanningError("duplicate or invalid GitHub job identity")
            seen.add(str(ident))
            records.append(job)
        if len(records) == count:
            break
        if not jobs or len(records) > count:
            raise PlanningError("incomplete GitHub jobs pagination")
        page += 1
    return records


def verify_context(environ, token, request_json, *, now=None):
    """Fail closed on mismatched live workflow_dispatch identity.

    The environment itself is not a trust root. The caller must establish
    workflow code integrity separately and use a scoped GitHub API credential.
    """
    if not isinstance(environ, dict):
        raise PlanningError("missing trusted runtime environment")
    if any(not isinstance(environ.get(k), str) or not environ[k] for k in REQUIRED_ENV):
        raise PlanningError("incomplete GitHub runtime environment")
    if not isinstance(token, str) or not token:
        raise PlanningError("read-only GitHub API token required")
    if (environ["GITHUB_REPOSITORY"] != REPO
            or environ["GITHUB_REPOSITORY_ID"] != str(REPOSITORY_ID)
            or environ["GITHUB_EVENT_NAME"] != "workflow_dispatch"
            or environ["GITHUB_REF"] != "refs/heads/main"
            or not SHA.fullmatch(environ["GITHUB_SHA"])
            or not RUN_ID.fullmatch(environ["GITHUB_RUN_ID"])
            or environ["GITHUB_RUN_ATTEMPT"] != "1"
            or environ["GITHUB_WORKFLOW_REF"] != REPO + "/" + WORKFLOW + "@refs/heads/main"
            or environ["GITHUB_JOB"] != JOB):
        raise PlanningError("untrusted GitHub workflow runtime context")
    current = _time(now) if now is not None else dt.datetime.now(dt.timezone.utc)
    repository = _api(request_json, token, BASE)
    if (type(repository.get("id")) is not int
            or repository["id"] != REPOSITORY_ID
            or repository.get("full_name") != REPO):
        raise PlanningError("GitHub repository identity mismatch")
    if _ref(request_json, token) != environ["GITHUB_SHA"]:
        raise PlanningError("GitHub main commit changed before audit")

    run_id = environ["GITHUB_RUN_ID"]
    run = _api(request_json, token, BASE + "/actions/runs/" + run_id)
    actor = run.get("actor")
    triggering_actor = run.get("triggering_actor")
    repo_info = run.get("repository")
    if (not _positive(run.get("id")) or str(run["id"]) != run_id
            or run.get("path") != WORKFLOW
            or run.get("event") != "workflow_dispatch"
            or run.get("head_branch") != "main"
            or run.get("head_sha") != environ["GITHUB_SHA"]
            or run.get("run_attempt") != 1
            or run.get("status") != "in_progress" or run.get("conclusion") is not None
            or not isinstance(actor, dict)
            or actor.get("login") != environ["GITHUB_ACTOR"]
            or not isinstance(triggering_actor, dict)
            or triggering_actor.get("login") != environ["GITHUB_ACTOR"]
            or not isinstance(repo_info, dict)
            or repo_info.get("id") != REPOSITORY_ID):
        raise PlanningError("GitHub workflow run identity mismatch")
    run_start = _time(run.get("run_started_at"))
    if not run_start <= current <= run_start + dt.timedelta(hours=2):
        raise PlanningError("stale or future GitHub audit run")

    jobs = _run_jobs(request_json, token, run_id)
    if len(jobs) != 1:
        raise PlanningError("unexpected extra or missing audit jobs")
    job = jobs[0]
    if (job.get("name") != JOB or str(job.get("run_id")) != run_id
            or job.get("run_attempt") != 1
            or job.get("head_sha") != environ["GITHUB_SHA"]
            or job.get("status") != "in_progress" or job.get("conclusion") is not None
            or job.get("runner_name") != environ["RUNNER_NAME"]
            or job.get("runner_group_name") != environ["RUNNER_GROUP_NAME"]):
        raise PlanningError("GitHub audit job identity mismatch")
    job_start = _time(job.get("started_at"))
    if not run_start <= job_start <= current:
        raise PlanningError("GitHub audit job timing mismatch")
    if _ref(request_json, token) != environ["GITHUB_SHA"]:
        raise PlanningError("GitHub main commit changed during audit")

    # An integrity digest of compared values, NOT a signature or attestation.
    detail = {
        "repository": REPO,
        "repository_id": REPOSITORY_ID,
        "workflow_path": WORKFLOW,
        "commit": environ["GITHUB_SHA"],
        "run_id": run_id,
        "run_attempt": 1,
        "job_id": str(job["id"]),
        "job_name": JOB,
        "runner_name": environ["RUNNER_NAME"],
        "runner_group_name": environ["RUNNER_GROUP_NAME"],
        "actor": environ["GITHUB_ACTOR"],
        "run_started_at": run["run_started_at"],
        "job_started_at": job["started_at"],
    }
    digest = hashlib.sha256(
        json.dumps(detail, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "scope": "v3-readonly-github-runtime-consistency-test-only",
        "checked_identity": detail,
        "identity_sha256": digest,
        "github_run_job_main_ref_consistent_at_check": True,
        "runtime_claims_cryptographically_attested": False,
        "protected_environment_approval_verified": False,
        "oidc_identity_verified": False,
        "independent_production_authority": False,
        "approval_granted": False,
        "publishable": False,
    }


def main():
    parser = argparse.ArgumentParser(description="Read-only Actions run/job identity check")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = pathlib.Path(args.output)
    if output.is_symlink() or output.exists():
        raise PlanningError("refusing to overwrite runtime audit output")
    result = verify_context(dict(os.environ), os.environ.get("GITHUB_TOKEN"), github_json)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("x", encoding="utf-8") as handle:
            json.dump(result, handle, sort_keys=True, indent=2)
            handle.write("\n")
    except FileExistsError as exc:
        raise PlanningError("refusing to overwrite runtime audit output") from exc
    print(json.dumps({"identity_sha256": result["identity_sha256"], "publishable": False}))


if __name__ == "__main__":
    main()
