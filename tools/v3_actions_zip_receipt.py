"""Fail-closed, read-only binding of a completed V3 Actions identity receipt to its ZIP.

Checks the downloaded artifact ZIP against the GitHub API artifact SHA-256
digest, extracts exactly one bounded receipt JSON, and verifies its run/job
identity using v3_completed_runtime_receipt. This is *not* an attestation:
API metadata and downloaded bytes still require a trusted acquisition path.
Never authorizes production promotion or signing.
"""
import argparse
import hashlib
import json
import pathlib
import re
import stat
import zipfile

from v3_actions_run_context import REPO, REPOSITORY_ID
from v3_completed_runtime_receipt import verify_receipt
from v3_promotion_planner import PlanningError

SHA256 = re.compile(r"^sha256:([0-9a-f]{64})$")
MEMBER = "v3-context-audit.json"
MAX_ARCHIVE = 2 * 1024 * 1024
MAX_REPORT = 256 * 1024
MAX_RATIO = 1000


def _unique_json(raw):
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise PlanningError("duplicate receipt JSON key")
            value[key] = item
        return value
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              PlanningError("non-finite receipt JSON value")))
    except PlanningError:
        raise
    except (UnicodeError, ValueError) as exc:
        raise PlanningError("invalid artifact receipt JSON") from exc


def _read_zip(archive, expected_digest):
    path = pathlib.Path(archive)
    if (path.is_symlink() or not path.is_file() or
            not 0 < path.stat().st_size <= MAX_ARCHIVE):
        raise PlanningError("missing or unsafe downloaded artifact ZIP")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected_digest:
        raise PlanningError("downloaded artifact ZIP digest mismatch")
    try:
        with zipfile.ZipFile(path, "r") as file:
            members = file.infolist()
            if len(members) != 1 or members[0].filename != MEMBER:
                raise PlanningError("unexpected artifact ZIP members")
            info = members[0]
            mode = (info.external_attr >> 16) & 0o170000
            if (info.is_dir() or info.flag_bits & 0x1 or
                    mode not in (0, stat.S_IFREG) or
                    not 0 < info.file_size <= MAX_REPORT or
                    info.compress_size <= 0 or
                    info.file_size > info.compress_size * MAX_RATIO):
                raise PlanningError("unsafe or oversized artifact receipt member")
            raw = file.read(info)
            if len(raw) != info.file_size:
                raise PlanningError("incomplete artifact receipt bytes")
    except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError,
            OSError, EOFError) as exc:
        raise PlanningError("invalid artifact ZIP container") from exc
    receipt = _unique_json(raw)
    if not isinstance(receipt, dict):
        raise PlanningError("artifact receipt must be a JSON object")
    return receipt


def verify_artifact_zip(archive, run, jobs, artifacts):
    """Match ZIP SHA256 to GitHub artifact metadata and validate actual receipt."""
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise PlanningError("expected exactly one Actions identity artifact")
    meta = artifacts[0]
    if not isinstance(meta, dict):
        raise PlanningError("malformed GitHub artifact metadata")
    artifact_id = meta.get("id")
    digest = meta.get("digest")
    workflow = meta.get("workflow_run")
    if (type(artifact_id) is not int or artifact_id <= 0
            or not isinstance(digest, str) or not SHA256.fullmatch(digest)
            or meta.get("url") !=
                "https://api.github.com/repos/" + REPO + "/actions/artifacts/" + str(artifact_id)
            or meta.get("archive_download_url") !=
                "https://api.github.com/repos/" + REPO + "/actions/artifacts/" + str(artifact_id) + "/zip"
            or not isinstance(workflow, dict)
            or workflow.get("repository_id") != REPOSITORY_ID):
        raise PlanningError("untrusted GitHub artifact identity or digest")
    receipt = _read_zip(archive, SHA256.fullmatch(digest).group(1))
    result = verify_receipt(receipt, run, jobs, artifacts)
    if result.get("publishable") is not False or result.get("approval_granted") is not False:
        raise PlanningError("artifact verification cannot authorize a publication")
    return {
        "scope": "v3-actions-zip-receipt-api-digest-binding-untrusted",
        "repository": REPO,
        "run_id": result["run_id"],
        "artifact_id": artifact_id,
        "github_artifact_zip_sha256": digest,
        "receipt_identity_sha256": result["receipt_identity_sha256"],
        "artifact_zip_matches_supplied_github_api_digest": True,
        "completed_runtime_metadata_consistent": True,
        "zip_member_count_checked": 1,
        "independently_authenticated_api_provenance": False,
        "oidc_signature_verified": False,
        "protected_environment_authorization_verified": False,
        "approval_granted": False,
        "publishable": False,
    }


def main():
    p = argparse.ArgumentParser(description="Offline check of GitHub Actions identity artifact ZIP bytes")
    p.add_argument("--artifact-zip", required=True)
    for field in ("run", "jobs", "artifacts"):
        p.add_argument("--" + field, required=True)
    args = p.parse_args()

    def load(path):
        file = pathlib.Path(path)
        if file.is_symlink() or not file.is_file() or file.stat().st_size > MAX_ARCHIVE:
            raise PlanningError("unsafe offline GitHub metadata file")
        try:
            return json.loads(file.read_text(encoding="utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise PlanningError("malformed GitHub metadata JSON") from exc

    result = verify_artifact_zip(args.artifact_zip, load(args.run),
                                 load(args.jobs), load(args.artifacts))
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
