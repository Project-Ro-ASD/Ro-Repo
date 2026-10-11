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
DIGEST = re.compile(r"^[0-9a-f]{64}$")
SNAP = re.compile(r"^repo-f44-[0-9]{8}-[0-9]{3}$")
PATH = ".github/workflows/publish-remote-beta.yml"
REQUIRED_JOBS = ("sign-beta-publication", "publish-beta", "verify-remote-beta")


def _split_signed_history(signed_rows):
    """Verify selection matches signed archive coverage; never silently drop runs."""
    if isinstance(signed_rows, list):
        if not signed_rows:
            raise PlanningError("signed beta history missing")
        return signed_rows, None
    required = {"scope", "promotion_group", "signed_publications", "candidate_history",
                "archive_completeness_verified", "trusted_publication_times_verified", "publishable"}
    if (not isinstance(signed_rows, dict) or set(signed_rows) != required
            or signed_rows["scope"] != "v3-signed-beta-archive-bundle-untrusted"
            or any(signed_rows[k] is not False for k in (
                "archive_completeness_verified", "trusted_publication_times_verified", "publishable"))):
        raise PlanningError("invalid signed archive bundle")
    group = signed_rows["promotion_group"]
    publications = signed_rows["signed_publications"]
    selected = signed_rows["candidate_history"]
    if (not isinstance(group, str) or not group or not isinstance(publications, list)
            or not publications or not isinstance(selected, list)):
        raise PlanningError("invalid signed archive selection")
    times, expected, actual = {}, {}, {}
    for pub in publications:
        if not isinstance(pub, dict) or set(pub) != {
                "publication_run", "published_at", "snapshot_id", "store_tree_sha256", "candidate_sha256"}:
            raise PlanningError("malformed signed archive publication")
        rid = pub["publication_run"]
        digest = pub["candidate_sha256"]
        if (not isinstance(rid, str) or not RUN.fullmatch(rid) or rid in times
                or not isinstance(pub["snapshot_id"], str) or not SNAP.fullmatch(pub["snapshot_id"])
                or not isinstance(pub["store_tree_sha256"], str)
                or not DIGEST.fullmatch(pub["store_tree_sha256"])
                or (digest is not None and (not isinstance(digest, str) or not DIGEST.fullmatch(digest)))):
            raise PlanningError("invalid or duplicate signed archive publication")
        _time(pub["published_at"])
        times[rid] = pub["published_at"]
        if digest is not None:
            expected[rid] = {"publication_run": rid, "published_at": pub["published_at"],
                             "promotion_group": group, "candidate_sha256": digest}
    for row in selected:
        if not isinstance(row, dict) or set(row) != {
                "publication_run", "published_at", "promotion_group", "candidate_sha256"}:
            raise PlanningError("malformed selected candidate history")
        rid = row["publication_run"]
        if not isinstance(rid, str) or not RUN.fullmatch(rid) or rid in actual:
            raise PlanningError("invalid or duplicate candidate publication")
        actual[rid] = row
    if actual != expected:
        raise PlanningError("signed archive candidate selection mismatch")
    return selected, times


def validate_history(signed_rows, run_details, jobs_details, now):
    selected, signed_times = _split_signed_history(signed_rows)
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
    for row in selected:
        if not isinstance(row, dict) or set(row) != {"publication_run", "published_at", "promotion_group", "candidate_sha256"}:
            raise PlanningError("malformed signed history")
        run = row["publication_run"]
        if not isinstance(run, str) or not RUN.fullmatch(run) or run in rows:
            raise PlanningError("duplicate signed publication run")
        rows[run] = row
    if signed_times is None:
        signed_times = {run: row["published_at"] for run, row in rows.items()}
    if set(signed_times) != set(runs):
        raise PlanningError("incomplete GitHub beta archive coverage")
    now_time = _time(now)
    verified = []
    for run_id in sorted(signed_times, key=int):
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
        signed = _time(signed_times[run_id])
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
        if run_id in rows:
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
