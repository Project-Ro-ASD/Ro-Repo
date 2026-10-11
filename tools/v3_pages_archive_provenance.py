"""Read-only V3 Pages metadata provenance check against an exact local Git tree.

Combines the PR63 GPG/API bridge with a caller-pinned pages-storage checkout
and live HTTPS byte comparison of *signed metadata files*. This does not prove
who authorized the Git ref, historical Pages uptime, complete RPM/store bytes,
or production publish eligibility. No branch or production channel is written.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import urllib.error
import urllib.request

from v3_beta_evidence_bridge import REPOSITORY, verify_evidence
from v3_github_beta_api import collect, github_json
from v3_promotion_planner import PlanningError
from v3_signed_beta_history import _json_file

GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
RUN = re.compile(r"^[1-9][0-9]*$")
SNAP = re.compile(r"^repo-f44-[0-9]{8}-[0-9]{3}$")
REMOTE_ORIGIN = "https://repo.ro-asd.org/"
METADATA_LIMIT = 4 * 1024 * 1024


def _git(root, *args, optional=False):
    try:
        done = subprocess.run(
            ["git", "-C", str(root), *args], text=True, capture_output=True,
            timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PlanningError("Git verification unavailable") from exc
    if done.returncode != 0:
        if optional:
            return None
        raise PlanningError("Git Pages checkout verification failed")
    return done.stdout.strip()


def verify_checkout(site_root, expected_sha):
    """Check actual HEAD and local pages-storage ref against a caller-supplied SHA.

    Branch/ref origin authentication is deliberately NOT claimed. A protected
    workflow must independently fetch and pin the GitHub API branch commit.
    """
    root = pathlib.Path(site_root)
    if (root.is_symlink() or not root.is_dir()
            or not isinstance(expected_sha, str) or not GIT_SHA.fullmatch(expected_sha)):
        raise PlanningError("invalid Pages checkout or commit pin")
    root = root.resolve()
    top = _git(root, "rev-parse", "--show-toplevel")
    if pathlib.Path(top).resolve() != root:
        raise PlanningError("Pages root must be the exact Git checkout root")
    if _git(root, "rev-parse", "--verify", "HEAD") != expected_sha:
        raise PlanningError("Pages checkout HEAD differs from pinned commit")
    # Prefer the fetched remote-tracking ref. Permit an exact local
    # pages-storage branch for isolated fixtures or offline checkout use.
    remote = _git(root, "rev-parse", "--verify", "refs/remotes/origin/pages-storage", optional=True)
    local = _git(root, "rev-parse", "--verify", "refs/heads/pages-storage", optional=True)
    if remote is not None and remote != expected_sha:
        raise PlanningError("Pages remote-tracking branch differs from pin")
    if remote is None and local != expected_sha:
        raise PlanningError("Pages branch ref differs from pinned commit")
    return root


def _tracked_bytes(root, relative):
    """Verify working-tree file bytes match the exact HEAD tree blob."""
    target = root / relative
    if target.is_symlink() or not target.is_file():
        raise PlanningError("missing or symlinked Pages metadata file")
    if target.stat().st_size > METADATA_LIMIT:
        raise PlanningError("oversized Pages metadata")
    line = _git(root, "ls-tree", "HEAD", "--", relative)
    entries = line.splitlines()
    if len(entries) != 1 or "\t" not in line:
        raise PlanningError("metadata not tracked by pinned Pages commit")
    left, name = line.split("\t", 1)
    fields = left.split()
    if (name != relative or len(fields) != 3
            or fields[0] != "100644" or fields[1] != "blob"
            or not GIT_SHA.fullmatch(fields[2])):
        raise PlanningError("unsafe or unexpected Pages tree entry")
    disk_hash = _git(root, "hash-object", "--no-filters", "--", relative)
    if disk_hash != fields[2]:
        raise PlanningError("Pages checkout file differs from pinned Git tree")
    return target.read_bytes()


def remote_metadata_bytes(url):
    """HTTPS-only, same-host, no-redirect bounded read of historical metadata."""
    if not url.startswith(REMOTE_ORIGIN) or "?" not in url:
        raise PlanningError("invalid Pages metadata URL")
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/octet-stream", "Accept-Encoding": "identity",
                 "Cache-Control": "no-cache", "User-Agent": "ro-repo-v3-read-only-audit"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.geturl() != url or response.status != 200:
                raise PlanningError("Pages metadata redirect or status mismatch")
            raw = response.read(METADATA_LIMIT + 1)
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise PlanningError("remote Pages metadata fetch failed") from exc
    if len(raw) > METADATA_LIMIT:
        raise PlanningError("remote Pages metadata too large")
    return raw


def verify_pages_metadata(collection, site_root, expected_sha, registry,
                          promotion_group, metadata_key, metadata_key_sha256,
                          now, *, fetch_bytes=remote_metadata_bytes):
    """GPG/API checks + pinned checkout + remote metadata exact-byte checks.

    A successful result stays test-only. The caller-supplied Git SHA and key
    hash are not external attestations of provenance or authorization.
    """
    root = verify_checkout(site_root, expected_sha)
    pubs = root / "publications/fedora/44/beta"
    snaps = root / "snapshots/fedora/44"
    base = verify_evidence(
        collection, pubs, snaps, registry, promotion_group,
        metadata_key, metadata_key_sha256, now,
    )
    needed = set()
    ids = set()
    for record in collection["run_details"]:
        rid = str(record["id"])
        if not RUN.fullmatch(rid) or rid in ids:
            raise PlanningError("invalid or duplicate beta run")
        ids.add(rid)
        prefix = "publications/fedora/44/beta/" + rid
        manifest_rel = prefix + "/publication-v1.json"
        local = _tracked_bytes(root, manifest_rel)
        try:
            pub = json.loads(local)
        except (ValueError, UnicodeDecodeError) as exc:
            raise PlanningError("invalid pinned publication JSON") from exc
        snap = pub.get("snapshot_id") if isinstance(pub, dict) else None
        if (not isinstance(snap, str) or not SNAP.fullmatch(snap)
                or pub.get("publication_run") != rid or pub.get("channel") != "beta"):
            raise PlanningError("pinned publication identity mismatch")
        snap_prefix = "snapshots/fedora/44/" + snap
        needed.update((manifest_rel, manifest_rel + ".asc",
                       snap_prefix + "/repository-snapshot-v1.json",
                       snap_prefix + "/repository-snapshot-v1.json.asc"))
    if len(ids) != base["signed_publications_checked"]:
        raise PlanningError("Pages publication coverage count mismatch")
    digests = {}
    for rel in sorted(needed):
        local = _tracked_bytes(root, rel)
        # No user-supplied host, path or arbitrary query is accepted.
        url = REMOTE_ORIGIN + rel + "?v3-audit=" + expected_sha
        remote = fetch_bytes(url)
        if not isinstance(remote, bytes) or local != remote:
            raise PlanningError("remote Pages signed metadata byte mismatch: " + rel)
        digests[rel] = hashlib.sha256(local).hexdigest()
    return {
        "scope": "v3-pages-signed-metadata-provenance-test-only",
        "repository": REPOSITORY,
        "caller_pinned_pages_commit": expected_sha,
        "promotion_group": promotion_group,
        "archived_publications_checked": len(ids),
        "remote_signed_metadata_files_checked": len(digests),
        "signed_metadata_sha256": digests,
        "local_pages_git_tree_bytes_match_pinned_commit": True,
        "remote_archived_signed_metadata_byte_match": True,
        "github_run_and_signed_archive_consistency_checked": True,
        "matched_candidate_publications": base["matching_candidate_publications"],
        "candidate_remote_verify_times": base["candidate_remote_verify_times"],
        "pages_branch_source_authenticated_independently": False,
        "metadata_key_pin_authenticated_independently": False,
        "remote_entire_rpm_and_store_tree_verified": False,
        "historical_first_public_availability_proven": False,
        "protected_runner_provenance_verified": False,
        "approval_granted": False,
        "publishable": False,
    }


def main():
    parser = argparse.ArgumentParser(description="Read-only pinned Pages signed metadata audit")
    parser.add_argument("--pages-checkout", required=True, help="Local pages-storage Git checkout")
    parser.add_argument("--expected-pages-commit", required=True, help="Caller-pinned exact 40-char Git SHA")
    parser.add_argument("--registry", required=True)
    parser.add_argument("--promotion-group", required=True)
    parser.add_argument("--metadata-key", required=True)
    parser.add_argument("--metadata-key-sha256", required=True)
    parser.add_argument("--now", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not os.environ.get("GITHUB_TOKEN"):
        raise PlanningError("GITHUB_TOKEN is required")
    registry = _json_file(pathlib.Path(args.registry))
    api_records = collect(REPOSITORY, os.environ["GITHUB_TOKEN"], github_json)
    report = verify_pages_metadata(
        api_records, args.pages_checkout, args.expected_pages_commit,
        registry, args.promotion_group, args.metadata_key,
        args.metadata_key_sha256, args.now,
    )
    output = pathlib.Path(args.output)
    if output.is_symlink():
        raise PlanningError("symlink output not allowed")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, sort_keys=True, indent=2)
            handle.write("\n")
    except FileExistsError as exc:
        raise PlanningError("refusing to overwrite audit output") from exc
    print(json.dumps({"archived_publications_checked": report["archived_publications_checked"],
                      "remote_signed_metadata_files_checked": report["remote_signed_metadata_files_checked"],
                      "publishable": False}))


if __name__ == "__main__":
    main()
