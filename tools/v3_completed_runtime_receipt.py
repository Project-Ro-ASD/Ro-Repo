"""Offline read-only verification of a completed V3 manual Actions identity receipt.

Cross-check a saved receipt against separately fetched, complete GitHub API
run, job and artifact metadata. The caller must authenticate API provenance
and supply genuine artifact bytes independently. No approval or publication.
"""
import argparse
import hashlib
import json
import pathlib
import re

from v3_actions_run_context import REPO, REPOSITORY_ID, WORKFLOW, JOB
from v3_promotion_planner import PlanningError
from v3_promotion_policy import _time

SHA = re.compile(r"^[0-9a-f]{40}$")
RUN = re.compile(r"^[1-9][0-9]*$")
RECEIPT_SCOPE = "v3-readonly-github-runtime-consistency-test-only"


def verify_receipt(receipt, run, jobs, artifacts):
    if not isinstance(receipt, dict) or receipt.get("scope") != RECEIPT_SCOPE:
        raise PlanningError("invalid runtime receipt scope")
    for name in ("publishable", "approval_granted", "oidc_identity_verified",
                 "protected_environment_approval_verified",
                 "runtime_claims_cryptographically_attested"):
        if receipt.get(name) is not False:
            raise PlanningError("runtime receipt claims forbidden authority")
    identity = receipt.get("checked_identity")
    digest = receipt.get("identity_sha256")
    if (not isinstance(identity, dict) or not isinstance(digest, str)
            or not re.fullmatch("[0-9a-f]{64}", digest)):
        raise PlanningError("invalid runtime receipt identity")
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    if hashlib.sha256(canonical).hexdigest() != digest:
        raise PlanningError("runtime receipt digest mismatch")
    rid, sha, job_id = (identity.get("run_id"), identity.get("commit"),
                        identity.get("job_id"))
    if (identity.get("repository") != REPO
            or identity.get("repository_id") != REPOSITORY_ID
            or identity.get("workflow_path") != WORKFLOW
            or identity.get("job_name") != JOB
            or identity.get("run_attempt") != 1
            or not isinstance(rid, str) or not RUN.fullmatch(rid)
            or not isinstance(job_id, str) or not RUN.fullmatch(job_id)
            or not isinstance(sha, str) or not SHA.fullmatch(sha)):
        raise PlanningError("unexpected runtime receipt subject")
    if not isinstance(run, dict) or not isinstance(run.get("repository"), dict):
        raise PlanningError("missing GitHub run evidence")
    actor = run.get("actor")
    trigger = run.get("triggering_actor")
    if (str(run.get("id")) != rid or run["repository"].get("id") != REPOSITORY_ID
            or run.get("path") != WORKFLOW or run.get("event") != "workflow_dispatch"
            or run.get("head_branch") != "main" or run.get("head_sha") != sha
            or run.get("run_attempt") != 1 or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or not isinstance(actor, dict) or actor.get("login") != identity.get("actor")
            or not isinstance(trigger, dict) or trigger.get("login") != identity.get("actor")):
        raise PlanningError("completed GitHub run mismatches receipt")
    if not isinstance(jobs, list) or len(jobs) != 1 or not isinstance(jobs[0], dict):
        raise PlanningError("missing or unexpected completed GitHub jobs")
    job = jobs[0]
    if (str(job.get("id")) != job_id or str(job.get("run_id")) != rid
            or job.get("name") != JOB or job.get("run_attempt") != 1
            or job.get("head_sha") != sha or job.get("status") != "completed"
            or job.get("conclusion") != "success"
            or job.get("runner_name") != identity.get("runner_name")
            or job.get("runner_group_name") != identity.get("runner_group_name")):
        raise PlanningError("completed GitHub job mismatches receipt")
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise PlanningError("expected exactly one runtime audit artifact")
    artifact = artifacts[0]
    expected_name = "v3-actions-context-" + rid + "-1"
    if (not isinstance(artifact, dict) or artifact.get("name") != expected_name
            or artifact.get("expired") is not False
            or type(artifact.get("size_in_bytes")) is not int
            or not 0 < artifact["size_in_bytes"] <= 1024 * 1024
            or not isinstance(artifact.get("workflow_run"), dict)
            or str(artifact["workflow_run"].get("id")) != rid
            or artifact["workflow_run"].get("head_sha") != sha):
        raise PlanningError("GitHub runtime artifact metadata mismatch")
    start = _time(identity.get("run_started_at"))
    job_start = _time(identity.get("job_started_at"))
    run_updated = _time(run.get("updated_at"))
    started = _time(job.get("started_at"))
    completed = _time(job.get("completed_at"))
    if not (start <= job_start == started <= completed <= run_updated):
        raise PlanningError("invalid completed runtime timeline")
    return {
        "scope": "v3-completed-runtime-receipt-consistency-untrusted",
        "repository": REPO,
        "run_id": rid,
        "run_commit": sha,
        "receipt_identity_sha256": digest,
        "completed_run_and_job_consistent": True,
        "artifact_metadata_consistent": True,
        "artifact_bytes_authenticated_by_this_check": False,
        "api_provenance_cryptographically_authenticated": False,
        "oidc_verified": False,
        "protected_approval_verified": False,
        "approval_granted": False,
        "publishable": False,
    }


def main():
    p = argparse.ArgumentParser(description="Offline completed read-only audit receipt consistency")
    for value in ("receipt", "run", "jobs", "artifacts"):
        p.add_argument("--" + value, required=True)
    args = p.parse_args()
    def load(file):
        path = pathlib.Path(file)
        if path.is_symlink() or not path.is_file():
            raise PlanningError("unsafe offline evidence file")
        return json.loads(path.read_text(encoding="utf-8"))
    print(json.dumps(verify_receipt(
        load(args.receipt), load(args.run), load(args.jobs), load(args.artifacts)),
        sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
