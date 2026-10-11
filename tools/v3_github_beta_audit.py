"""Read-only GitHub Actions beta publication provenance assessment (test-only).

A trusted caller must supply COMPLETE archived runs and GitHub API responses,
independently sourced (not user-edited). This validator checks consistency
but NEVER grants approval. First-seen uses completed remote verification,
NOT the self-declared signed publication timestamp.
"""
import argparse
import datetime as dt
import json
import pathlib
import re

from v3_promotion_planner import PlanningError
from v3_promotion_policy import evaluate, _time

RUN = re.compile(r"^[1-9][0-9]*$")
SHA = re.compile(r"^[0-9a-f]{40}$")
PATH = ".github/workflows/publish-remote-beta.yml"
REQUIRED_JOBS = ("sign-beta-publication", "publish-beta", "verify-remote-beta")


def validate_history(signed_rows, run_details, jobs_details, now):
    if not isinstance(signed_rows, list) or not signed_rows:
        raise PlanningError("signed beta history missing")
    if not isinstance(run_details, list) or not isinstance(jobs_details, list):
        raise PlanningError("missing GitHub evidence")
    runs = {}
    for item in run_details:
        if not isinstance(item, dict) or not RUN.fullmatch(str(item.get("id", ""))) or str(item["id"]) in runs:
            raise PlanningError("malformed/duplicate GitHub run")
        runs[str(item["id"])] = item
    jobs = {}
    for record in jobs_details:
        if not isinstance(record, dict) or not RUN.fullmatch(str(record.get("run_id", ""))) or str(record["run_id"]) in jobs:
            raise PlanningError("malformed/duplicate jobs record")
        jobs[str(record["run_id"])] = record.get("jobs")
    if set(runs) != set(jobs):
        raise PlanningError("run and job evidence sets disagree")
    rows = {}
    for row in signed_rows:
        if not isinstance(row, dict) or set(row) != {"publication_run", "published_at", "promotion_group", "candidate_sha256"}:
            raise PlanningError("malformed signed history")
        run = row["publication_run"]
        if run in rows:
            raise PlanningError("duplicate signed publication run")
        rows[run] = row
    if set(rows) != set(runs):
        raise PlanningError("incomplete GitHub beta archive coverage")
    now_time = _time(now)
    verified = []
    for run_id in sorted(rows, key=int):
        record = runs[run_id]
        if (str(record.get("id")) != run_id or record.get("path") != PATH
                or record.get("event") != "workflow_dispatch"
                or record.get("status") != "completed" or record.get("conclusion") != "success"
                or record.get("head_branch") != "main"
                or not isinstance(record.get("head_sha"), str) or not SHA.fullmatch(record["head_sha"])
                or record.get("run_attempt") != 1):
            raise PlanningError("GitHub beta run not trusted for dwell: " + run_id)
        started = _time(record.get("run_started_at"))
        finished = _time(record.get("updated_at"))
        signed = _time(rows[run_id]["published_at"])
        if not started <= signed <= finished <= now_time:
            raise PlanningError("signed beta timestamp outside actual GitHub run")
        job_set = jobs[run_id]
        if not isinstance(job_set, list) or len(job_set) != len(REQUIRED_JOBS) or {j.get("name") for j in job_set if isinstance(j, dict)} != set(REQUIRED_JOBS):
            raise PlanningError("incomplete beta workflow jobs")
        order = []
        for name in REQUIRED_JOBS:
            j = next(j for j in job_set if j["name"] == name)
            if str(j.get("run_id")) != run_id or j.get("status") != "completed" or j.get("conclusion") != "success":
                raise PlanningError("unsuccessful beta publication job")
            a, b = _time(j.get("started_at")), _time(j.get("completed_at"))
            if not started <= a <= b <= finished:
                raise PlanningError("job timestamps disagree with GitHub run")
            order.append((a, b))
        if not (order[0][1] <= order[1][0] and order[1][1] <= order[2][0]):
            raise PlanningError("beta workflow job ordering invalid")
        # Conservative first-seen: only after public remote tree verification.
        timestamp = order[2][1].isoformat().replace("+00:00", "Z")
        verified.append({**rows[run_id], "published_at": timestamp})
    return verified


def assess(candidate, signed_rows, runs, jobs, risk_class, mode, now, reason=None):
    verified = validate_history(signed_rows, runs, jobs, now)
    result = evaluate(candidate, verified, risk_class, mode, now, reason=reason)
    result.update({
        "github_run_job_metadata_consistent": True,
        "conservative_time_source": "verify-remote-beta job completion",
        "github_api_provenance_authenticated": False,
        "complete_historical_run_enumeration_verified": False,
        "remote_pages_bytes_rechecked": False,
        "approval_granted": False, "publishable": False,
    })
    return result


def main():
    p = argparse.ArgumentParser(description="Offline audit of GitHub beta publication run metadata")
    for field in ("candidate", "signed-rows", "runs", "jobs", "risk", "mode", "now"):
        p.add_argument("--" + field, required=True)
    p.add_argument("--reason")
    a = p.parse_args()
    def read(filename):
        f = pathlib.Path(filename)
        if f.is_symlink() or not f.is_file():
            raise PlanningError("missing or unsafe evidence input")
        return json.loads(f.read_text())
    out = assess(read(a.candidate), read(a.signed_rows), read(a.runs), read(a.jobs),
                 a.risk, a.mode, a.now, a.reason)
    print(json.dumps(out, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
