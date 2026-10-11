"""Read-only live GitHub Actions artifact receipt verification (V3).

Fetch a completed manual identity run, ALL associated jobs/artifacts, and the
raw artifact ZIP. Reuse existing fail-closed ZIP and completed-receipt checks.
Token is never forwarded on ZIP redirects. This is a consistency audit, not
an OIDC attestation, protected approval or stable publication.
"""
import argparse
import json
import os
import pathlib
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from v3_actions_run_context import REPO, REPOSITORY_ID
from v3_actions_zip_receipt import MAX_ARCHIVE, verify_artifact_zip
from v3_github_beta_api import github_json
from v3_promotion_planner import PlanningError

ROOT = "/repos/" + REPO
RUN = re.compile(r"^[1-9][0-9]*$")
MAX_ITEMS = 1000
PER_PAGE = 100
REDIRECT_HOSTS = ("objects.githubusercontent.com", "results-receiver.actions.githubusercontent.com")


def _id(value, label="run"):
    if not isinstance(value, str) or not RUN.fullmatch(value):
        raise PlanningError("invalid GitHub " + label + " identifier")
    return value


def _json(request_json, token, path):
    try:
        value = request_json(path, token)
    except PlanningError:
        raise
    except Exception as exc:
        raise PlanningError("GitHub read-only evidence request failed") from exc
    if not isinstance(value, dict):
        raise PlanningError("malformed GitHub read-only evidence response")
    return value


def _all_pages(request_json, token, relative, field):
    if field not in ("jobs", "artifacts"):
        raise PlanningError("unsupported GitHub evidence page type")
    items, ids, total, page = [], set(), None, 1
    while True:
        if page > 10:
            raise PlanningError("GitHub evidence pagination limit reached")
        result = _json(request_json, token, ROOT + relative +
                       "?per_page=" + str(PER_PAGE) + "&page=" + str(page))
        count, batch = result.get("total_count"), result.get(field)
        if (type(count) is not int or count < 0 or count > MAX_ITEMS
                or not isinstance(batch, list) or len(batch) > PER_PAGE):
            raise PlanningError("invalid GitHub evidence pagination payload")
        if total is None:
            total = count
        elif total != count:
            raise PlanningError("GitHub evidence total changed across pages")
        for item in batch:
            if not isinstance(item, dict):
                raise PlanningError("invalid GitHub evidence record")
            ident = item.get("id")
            if type(ident) is not int or ident <= 0 or ident in ids:
                raise PlanningError("invalid or duplicate GitHub evidence ID")
            ids.add(ident)
            items.append(item)
        if len(items) == total:
            return items
        if not batch or len(items) > total:
            raise PlanningError("truncated GitHub evidence pagination")
        page += 1


def collect_evidence(run_id, token, request_json):
    run_id = _id(run_id)
    if not isinstance(token, str) or not token:
        raise PlanningError("read-only GitHub token required")
    run = _json(request_json, token, ROOT + "/actions/runs/" + run_id)
    if str(run.get("id")) != run_id:
        raise PlanningError("GitHub run ID mismatch")
    jobs = _all_pages(request_json, token, "/actions/runs/" + run_id + "/jobs", "jobs")
    artifacts = _all_pages(request_json, token, "/actions/runs/" + run_id + "/artifacts", "artifacts")
    if len(artifacts) != 1:
        raise PlanningError("expected exactly one completed identity artifact")
    return run, jobs, artifacts


def _allowed_redirect(url):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    return (parsed.scheme == "https" and parsed.username is None and
            parsed.password is None and parsed.port in (None, 443) and
            (host in REDIRECT_HOSTS or
             host.endswith(".blob.core.windows.net") or
             host.endswith(".actions.githubusercontent.com")))


class _ArtifactRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _allowed_redirect(newurl):
            raise PlanningError("untrusted artifact download redirect")
        request = super().redirect_request(req, fp, code, msg, headers, newurl)
        if request is None:
            raise PlanningError("artifact redirect refused")
        # Python's default redirect handler can copy Authorization headers to
        # another host. Explicitly strip them before following CDN redirects.
        request.headers = {key: value for key, value in request.headers.items()
                           if key.lower() not in ("authorization", "cookie")}
        request.unredirected_hdrs = {
            key: value for key, value in request.unredirected_hdrs.items()
            if key.lower() not in ("authorization", "cookie")}
        return request


def download_artifact_zip(artifact_id, token, output):
    ident = str(artifact_id)
    _id(ident, "artifact")
    if not isinstance(token, str) or not token:
        raise PlanningError("GitHub API token missing")
    url = "https://api.github.com" + ROOT + "/actions/artifacts/" + ident + "/zip"
    request = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ro-repo-v3-readonly-receipt",
    })
    opener = urllib.request.build_opener(_ArtifactRedirect())
    destination = pathlib.Path(output)
    if destination.exists() or destination.is_symlink():
        raise PlanningError("refusing to overwrite downloaded receipt")
    try:
        with opener.open(request, timeout=60) as response:
            if response.status != 200 or not _allowed_redirect(response.geturl()):
                raise PlanningError("unexpected GitHub artifact destination")
            with destination.open("xb") as file:
                size = 0
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_ARCHIVE:
                        raise PlanningError("GitHub identity ZIP exceeds limit")
                    file.write(chunk)
        if size <= 0:
            raise PlanningError("GitHub identity ZIP is empty")
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise PlanningError("GitHub artifact ZIP download failed") from exc


def audit_live_run(run_id, token, request_json, download_zip):
    run, jobs, artifacts = collect_evidence(run_id, token, request_json)
    # Check the basic status before fetching any binary payload.
    if (run.get("status") != "completed" or run.get("conclusion") != "success"
            or run.get("event") != "workflow_dispatch"
            or run.get("head_branch") != "main" or run.get("run_attempt") != 1):
        raise PlanningError("manual identity workflow did not complete successfully")
    with tempfile.TemporaryDirectory(prefix="ro-repo-v3-readonly-") as dirname:
        archive = pathlib.Path(dirname) / "artifact.zip"
        download_zip(artifacts[0]["id"], token, archive)
        verified = verify_artifact_zip(archive, run, jobs, artifacts)
    # One final API GET detects a run that changed during the verification.
    final = _json(request_json, token, ROOT + "/actions/runs/" + run_id)
    for field in ("id", "head_sha", "run_attempt", "status", "conclusion", "updated_at"):
        if final.get(field) != run.get(field):
            raise PlanningError("GitHub identity run changed during verification")
    return {
        "scope": "v3-live-readonly-artifact-receipt-audit",
        "repository": REPO,
        "run_id": run_id,
        "artifact_id": verified["artifact_id"],
        "receipt_identity_sha256": verified["receipt_identity_sha256"],
        "artifact_zip_matches_github_api_digest": True,
        "completed_run_and_job_consistency_checked": True,
        "all_jobs_and_artifacts_paginated": True,
        "github_api_provenance_independently_authenticated": False,
        "oidc_attestation_verified": False,
        "protected_approval_verified": False,
        "approval_granted": False,
        "publishable": False,
    }


def main():
    p = argparse.ArgumentParser(description="Read-only completed manual identity artifact audit")
    p.add_argument("--source-run-id", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()
    if (os.environ.get("GITHUB_REPOSITORY") != REPO
            or os.environ.get("GITHUB_REPOSITORY_ID") != str(REPOSITORY_ID)
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"):
        raise PlanningError("not running in expected read-only GitHub workflow context")
    output = pathlib.Path(args.output)
    if output.is_symlink() or output.exists():
        raise PlanningError("refusing to replace audit result")
    report = audit_live_run(args.source_run_id, os.environ.get("GITHUB_TOKEN"),
                            github_json, download_artifact_zip)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("x", encoding="utf-8") as fp:
            json.dump(report, fp, sort_keys=True, indent=2)
            fp.write("\n")
    except FileExistsError as exc:
        raise PlanningError("refusing to replace audit result") from exc
    print(json.dumps({"source_run_id": report["run_id"], "publishable": False}))


if __name__ == "__main__":
    main()
