"""Read-only, bounded byte comparison of the full pinned remote beta tree.

Extends the signed metadata checks with exact expected-file parity for all
RPMs, DNF repodata, historical beta publication stores and snapshot trees.
The trusted *source* of the Git SHA, metadata key and API response is still
NOT established here. GitHub Pages cannot be remotely enumerated by this
module, so unknown extra remote files are not ruled out. No publishing.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from v3_pages_archive_provenance import (
    REMOTE_ORIGIN, verify_checkout, verify_pages_metadata,
    remote_metadata_bytes,
)
from v3_beta_evidence_bridge import REPOSITORY
from v3_github_beta_api import collect, github_json
from v3_signed_beta_history import _json_file
from v3_promotion_planner import PlanningError

PREFIXES = (
    "rpm/fedora/44/beta",
    "publications/fedora/44/beta",
    "snapshots/fedora/44",
)
# The original empty snapshot-root directory uses this placeholder; it is not
# a published RPM, signed manifest or immutable publication payload.
GIT_PLACEHOLDER = "snapshots/fedora/44/.gitkeep"
SHA1 = re.compile(r"^[0-9a-f]{40}$")
PATH = re.compile(r"^[A-Za-z0-9_./+@-]+$")
CHUNK = 1024 * 1024
MAX_FILES = 10000
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024


def _safe_path(value):
    return (isinstance(value, str) and PATH.fullmatch(value) is not None
            and all(part not in ("", ".", "..") for part in value.split("/"))
            and any(value.startswith(prefix + "/") for prefix in PREFIXES))


def _tree_entries(root):
    """Get every expected public file from pinned HEAD, not a guessed filename list."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-tree", "-r", "-z", "HEAD", "--", *PREFIXES],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PlanningError("pinned tree enumeration unavailable") from exc
    if result.returncode:
        raise PlanningError("pinned tree enumeration failed")
    expected = {}
    for item in result.stdout.split(b"\0"):
        if not item:
            continue
        try:
            header, name = item.split(b"\t", 1)
            mode, kind, sha = header.decode("ascii").split()
            relative = name.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise PlanningError("malformed pinned Git tree entry") from exc
        if (not _safe_path(relative) or mode != "100644"
                or kind != "blob" or not SHA1.fullmatch(sha)
                or relative in expected):
            raise PlanningError("unsafe or duplicate pinned Git entry")
        if relative != GIT_PLACEHOLDER:
            expected[relative] = sha
    if not expected or len(expected) > MAX_FILES:
        raise PlanningError("empty or excessive pinned remote beta inventory")
    if not all(any(p.startswith(prefix + "/") for p in expected) for prefix in PREFIXES):
        raise PlanningError("missing required beta inventory subtree")
    return expected


def _check_worktree(root, expected):
    """No untracked files, missing files or symlinks in the tested subtrees."""
    found = set()
    for prefix in PREFIXES:
        directory = root / prefix
        if directory.is_symlink() or not directory.is_dir():
            raise PlanningError("missing or unsafe beta inventory directory")
        for base, dirs, files in os.walk(directory, followlinks=False):
            for child in dirs:
                if (pathlib.Path(base) / child).is_symlink():
                    raise PlanningError("symlink directory in pinned beta inventory")
            for child in files:
                target = pathlib.Path(base) / child
                if target.is_symlink() or not target.is_file():
                    raise PlanningError("unsafe file in pinned beta inventory")
                relative = target.relative_to(root).as_posix()
                if relative != GIT_PLACEHOLDER:
                    if not _safe_path(relative):
                        raise PlanningError("unsafe worktree inventory path")
                    found.add(relative)
    if found != set(expected):
        raise PlanningError("missing or untracked beta inventory file")


def _validate_git_blob(path, expected_sha):
    length = path.stat().st_size
    if length > MAX_FILE_BYTES:
        raise PlanningError("pinned beta file exceeds safety limit")
    git = hashlib.sha1()
    git.update(("blob " + str(length) + "\0").encode("ascii"))
    with path.open("rb") as handle:
        while True:
            block = handle.read(CHUNK)
            if not block:
                break
            git.update(block)
    if git.hexdigest() != expected_sha:
        raise PlanningError("local beta bytes differ from pinned Git blob")
    return length


def remote_file_chunks(url):
    """HTTPS GET of a fixed-origin file; no redirects; streamed bounded reads."""
    if not url.startswith(REMOTE_ORIGIN) or "?" not in url:
        raise PlanningError("invalid remote beta URL")
    request = urllib.request.Request(
        url, headers={"Accept": "application/octet-stream",
                      "Accept-Encoding": "identity",
                      "Cache-Control": "no-cache",
                      "User-Agent": "ro-repo-v3-read-only-tree-audit"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status != 200 or response.geturl() != url:
                raise PlanningError("remote beta file redirected or unavailable")
            while True:
                block = response.read(CHUNK)
                if not block:
                    break
                yield block
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise PlanningError("remote beta file fetch failed") from exc


def verify_tree_bytes(site_root, expected_sha, *, fetch_chunks=remote_file_chunks):
    root = verify_checkout(site_root, expected_sha)
    expected = _tree_entries(root)
    _check_worktree(root, expected)
    total = 0
    digests = {}
    for relative, git_sha in sorted(expected.items()):
        path = root / relative
        size = _validate_git_blob(path, git_sha)
        total += size
        if total > MAX_TOTAL_BYTES:
            raise PlanningError("pinned beta tree exceeds audit byte limit")
        url = (REMOTE_ORIGIN + urllib.parse.quote(relative, safe="/-_.~")
               + "?v3-audit=" + expected_sha)
        length = 0
        sha256 = hashlib.sha256()
        with path.open("rb") as local:
            for block in fetch_chunks(url):
                if not isinstance(block, bytes) or not block:
                    raise PlanningError("invalid remote beta download chunk")
                length += len(block)
                if length > size or length > MAX_FILE_BYTES:
                    raise PlanningError("remote beta file size mismatch or limit")
                if local.read(len(block)) != block:
                    raise PlanningError("remote beta byte mismatch: " + relative)
                sha256.update(block)
            if length != size or local.read(1):
                raise PlanningError("remote beta file is incomplete: " + relative)
        digests[relative] = sha256.hexdigest()
    return {
        "scope": "v3-remote-beta-pinned-tree-parity-test-only",
        "caller_pinned_pages_commit": expected_sha,
        "checked_file_count": len(expected),
        "checked_total_bytes": total,
        "expected_file_sha256": digests,
        "all_expected_remote_files_byte_equal": True,
        "remote_unlisted_extra_files_excluded": False,
        "caller_commit_and_key_pins_independently_authenticated": False,
        "historical_availability_proven": False,
        "approval_granted": False,
        "publishable": False,
    }


def verify_remote_beta(collection, site_root, expected_sha, registry,
                       promotion_group, metadata_key, key_sha256, now,
                       *, fetch_metadata=remote_metadata_bytes,
                       fetch_chunks=remote_file_chunks):
    metadata = verify_pages_metadata(
        collection, site_root, expected_sha, registry, promotion_group,
        metadata_key, key_sha256, now, fetch_bytes=fetch_metadata,
    )
    # Metadata/signature + GitHub run evidence must succeed before a bulk
    # remote read. The result remains test-only even when both pass.
    tree = verify_tree_bytes(site_root, expected_sha, fetch_chunks=fetch_chunks)
    return {
        "scope": "v3-beta-complete-expected-tree-check-untrusted",
        "repository": REPOSITORY,
        "promotion_group": promotion_group,
        "caller_pinned_pages_commit": expected_sha,
        "signed_metadata_files_checked": metadata["remote_signed_metadata_files_checked"],
        "published_candidate_records_checked": metadata["matched_candidate_publications"],
        "all_expected_remote_files_byte_equal": tree["all_expected_remote_files_byte_equal"],
        "checked_file_count": tree["checked_file_count"],
        "checked_total_bytes": tree["checked_total_bytes"],
        "expected_file_sha256": tree["expected_file_sha256"],
        "pages_ref_origin_authenticated": False,
        "metadata_public_key_pin_independently_authenticated": False,
        "unknown_remote_extra_files_excluded": False,
        "historical_publication_times_proven": False,
        "protected_approval_verified": False,
        "publishable": False,
    }


def main():
    p = argparse.ArgumentParser(description="Read-only full expected remote beta file parity")
    p.add_argument("--pages-checkout", required=True)
    p.add_argument("--expected-pages-commit", required=True)
    p.add_argument("--registry", required=True)
    p.add_argument("--promotion-group", required=True)
    p.add_argument("--metadata-key", required=True)
    p.add_argument("--metadata-key-sha256", required=True)
    p.add_argument("--now", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()
    if not os.environ.get("GITHUB_TOKEN"):
        raise PlanningError("GITHUB_TOKEN is required")
    output = pathlib.Path(args.output)
    if output.is_symlink() or output.exists():
        raise PlanningError("audit output already exists")
    records = collect(REPOSITORY, os.environ["GITHUB_TOKEN"], github_json)
    report = verify_remote_beta(
        records, args.pages_checkout, args.expected_pages_commit,
        _json_file(pathlib.Path(args.registry)), args.promotion_group,
        args.metadata_key, args.metadata_key_sha256, args.now,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("x", encoding="utf-8") as dest:
            json.dump(report, dest, sort_keys=True, indent=2)
            dest.write("\n")
    except FileExistsError as exc:
        raise PlanningError("audit output already exists") from exc
    print(json.dumps({"checked_file_count": report["checked_file_count"],
                      "checked_total_bytes": report["checked_total_bytes"],
                      "publishable": False}))


if __name__ == "__main__":
    main()
