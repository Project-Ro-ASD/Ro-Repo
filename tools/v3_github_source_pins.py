"""Read-only V3 GitHub source-pin consistency gate.

Bind PR65's beta byte audit to GitHub REST repository identity, pinned main
and pages-storage refs, and public metadata key bytes from an exact main SHA.

Caller-provided expected SHAs and key SHA256 are *not* themselves authenticated.
A future protected workflow must supply and protect these trust anchors, control
API token/runner identity and validate deployment authorization. Never publish.
"""
import argparse
import base64
import binascii
import hashlib
import json
import os
import pathlib
import re

from v3_beta_evidence_bridge import REPOSITORY
from v3_github_beta_api import collect, github_json
from v3_promotion_planner import PlanningError
from v3_remote_beta_tree import verify_remote_beta
from v3_signed_beta_history import _json_file

REPOSITORY_ID = 1159460821
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
KEY_PATH = "keys/production/ro-asd-metadata-signing-public.asc"
KEY_LIMIT = 64 * 1024
ROOT = "/repos/" + REPOSITORY


def _check_sha(value, pattern, name):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PlanningError("invalid pinned " + name)


def _get(request_json, path, token):
    try:
        result = request_json(path, token)
    except PlanningError:
        raise
    except Exception as exc:
        raise PlanningError("GitHub provenance API request failed") from exc
    if not isinstance(result, dict):
        raise PlanningError("malformed GitHub provenance response")
    return result


def _ref(request_json, branch, token):
    path = ROOT + "/git/ref/heads/" + branch
    response = _get(request_json, path, token)
    obj = response.get("object")
    if (response.get("ref") != "refs/heads/" + branch
            or not isinstance(obj, dict)
            or obj.get("type") != "commit"
            or not isinstance(obj.get("sha"), str)
            or not SHA1.fullmatch(obj["sha"])):
        raise PlanningError("invalid GitHub branch ref: " + branch)
    return obj["sha"]


def _refs_match(request_json, token, main_sha, pages_sha):
    if _ref(request_json, "main", token) != main_sha:
        raise PlanningError("GitHub main branch differs from pinned commit")
    if _ref(request_json, "pages-storage", token) != pages_sha:
        raise PlanningError("GitHub Pages branch differs from pinned commit")


def _api_file_bytes(request_json, token, main_sha, path=KEY_PATH, limit=KEY_LIMIT):
    response = _get(request_json, ROOT + "/contents/" + path + "?ref=" + main_sha, token)
    encoded = response.get("content")
    blob = response.get("sha")
    if (response.get("path") != path or response.get("type") != "file"
            or response.get("encoding") != "base64"
            or not isinstance(encoded, str)
            or not isinstance(blob, str) or not SHA1.fullmatch(blob)
            or type(response.get("size")) is not int
            or response["size"] < 1 or response["size"] > limit):
        raise PlanningError("invalid GitHub metadata public key response")
    try:
        raw = base64.b64decode("".join(encoded.split()), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PlanningError("invalid GitHub public key base64") from exc
    if len(raw) != response["size"]:
        raise PlanningError("GitHub public key size mismatch")
    git_blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    if git_blob != blob:
        raise PlanningError("GitHub public key Git blob mismatch")
    return raw


def _api_key_bytes(request_json, token, main_sha):
    return _api_file_bytes(request_json, token, main_sha)


def verify_registry_pin(request_json, token, main_sha, registry):
    """Bind the derived policy to registry bytes from the exact pinned source."""
    from v3_policy_profile import sha
    _check_sha(main_sha, SHA1, "registry commit")
    raw = _api_file_bytes(request_json, token, main_sha, "config/producers-v2.json", 1024 * 1024)
    from v3_actions_zip_receipt import _unique_json
    fetched = _unique_json(raw)
    if fetched != registry:
        raise PlanningError("local producer registry diverges from pinned main source")
    return {"registry_sha256": sha(registry), "registry_file_sha256": hashlib.sha256(raw).hexdigest(),
            "source_main_commit": main_sha, "independently_authenticated": False}


def verify_source_pins(request_json, token, *, expected_main_sha,
                       expected_pages_sha, expected_key_sha256, local_key):
    """Fail closed on ref, repository or exact key-byte mismatch.

    Expected pins MUST be provided independently by a trusted caller;
    untrusted CLI flags alone do not establish an independent trust root.
    """
    _check_sha(expected_main_sha, SHA1, "main commit")
    _check_sha(expected_pages_sha, SHA1, "Pages commit")
    _check_sha(expected_key_sha256, SHA256, "metadata key digest")
    if not isinstance(token, str) or not token.strip():
        raise PlanningError("GitHub API token required")
    path = pathlib.Path(local_key)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > KEY_LIMIT:
        raise PlanningError("unsafe local metadata public key")
    repo = _get(request_json, ROOT, token)
    if (type(repo.get("id")) is not int or repo["id"] != REPOSITORY_ID
            or repo.get("full_name") != REPOSITORY):
        raise PlanningError("unexpected GitHub repository identity")
    _refs_match(request_json, token, expected_main_sha, expected_pages_sha)
    key_bytes = _api_key_bytes(request_json, token, expected_main_sha)
    if hashlib.sha256(key_bytes).hexdigest() != expected_key_sha256:
        raise PlanningError("GitHub metadata public key does not match pin")
    if path.read_bytes() != key_bytes:
        raise PlanningError("local metadata public key differs from pinned GitHub bytes")
    _refs_match(request_json, token, expected_main_sha, expected_pages_sha)
    return {
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "pinned_main_commit": expected_main_sha,
        "pinned_pages_commit": expected_pages_sha,
        "metadata_public_key_sha256": expected_key_sha256,
        "github_repository_and_refs_match_caller_pins": True,
        "local_public_key_matches_exact_main_commit_bytes": True,
        "pins_independently_authenticated": False,
        "protected_runner_authenticated": False,
        "publishable": False,
    }


def audit_with_live_pins(request_json, token, *, expected_main_sha,
                         expected_pages_sha, expected_key_sha256, local_key,
                         pages_checkout, registry, promotion_group, now,
                         audit_beta=verify_remote_beta, collect_runs=collect):
    """Collect, audit and recheck refs to detect movement during the operation."""
    anchors = verify_source_pins(
        request_json, token,
        expected_main_sha=expected_main_sha,
        expected_pages_sha=expected_pages_sha,
        expected_key_sha256=expected_key_sha256, local_key=local_key,
    )
    collection = collect_runs(REPOSITORY, token, request_json)
    result = audit_beta(
        collection, pages_checkout, expected_pages_sha, registry,
        promotion_group, local_key, expected_key_sha256, now,
    )
    if (not isinstance(result, dict) or result.get("publishable") is not False
            or result.get("caller_pinned_pages_commit") != expected_pages_sha
            or result.get("repository") != REPOSITORY):
        raise PlanningError("invalid read-only beta audit result")
    _refs_match(request_json, token, expected_main_sha, expected_pages_sha)
    return {
        "scope": "v3-github-anchored-beta-audit-untrusted",
        "source_checks": anchors,
        "beta_tree_audit": result,
        "refs_unchanged_before_and_after_audit": True,
        "caller_pins_independently_authenticated": False,
        "api_runner_provenance_authenticated": False,
        "remote_unlisted_files_excluded": False,
        "historical_publication_time_proven": False,
        "approval_granted": False,
        "publishable": False,
    }


def main():
    p = argparse.ArgumentParser(description="Test-only GitHub branch and metadata pin audit")
    p.add_argument("--trusted-main-commit", required=True)
    p.add_argument("--trusted-pages-commit", required=True)
    p.add_argument("--trusted-metadata-key-sha256", required=True)
    p.add_argument("--metadata-key", required=True)
    p.add_argument("--pages-checkout", required=True)
    p.add_argument("--registry", required=True)
    p.add_argument("--promotion-group", required=True)
    p.add_argument("--now", required=True)
    p.add_argument("--output", required=True)
    a = p.parse_args()
    output = pathlib.Path(a.output)
    if output.is_symlink() or output.exists():
        raise PlanningError("refusing to replace test-only audit report")
    registry = _json_file(pathlib.Path(a.registry))
    result = audit_with_live_pins(
        github_json, os.environ.get("GITHUB_TOKEN"),
        expected_main_sha=a.trusted_main_commit,
        expected_pages_sha=a.trusted_pages_commit,
        expected_key_sha256=a.trusted_metadata_key_sha256,
        local_key=a.metadata_key, pages_checkout=a.pages_checkout,
        registry=registry, promotion_group=a.promotion_group, now=a.now,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("x", encoding="utf-8") as handle:
            json.dump(result, handle, sort_keys=True, indent=2)
            handle.write("\n")
    except FileExistsError as exc:
        raise PlanningError("refusing to replace test-only audit report") from exc
    print(json.dumps({"repository": REPOSITORY, "publishable": False}))


if __name__ == "__main__":
    main()
