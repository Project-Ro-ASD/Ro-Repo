"""Read-only PSOP phase-A audit. This module never grants publication authority.

GitHub collection uses a fixed GET allowlist, excluding secrets and credentials.
The source guard freezes existing runtime/workflows while PR-A is under review.
It must be explicitly replaced by a reviewed contract before PR-B changes them.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import re
import stat
import subprocess
import tempfile

BASE_MAIN = "3d4b56bd7509988f3715305ab9e2e09394635448"
PAGES_COMMIT = "097ba6ba7ab73d87c36f7ec9829b017b083b1883"
V2_REVIEWED_CONTRACT_SHA256 = "481e9c6a57cf7e92e8b2b3ab0cd6dff7ef3c27386974323a556c9e5ddf3a5e57"
V2_REVIEWED_CONTRACT = "docs/v2-selected-stable-source-contract.json"
BASELINE_SHA256 = "62d32c79d1c86f0aacd3d22f087712389a79122f2cb28b342226b29a600925f1"
REPOSITORY = "Project-Ro-ASD/Ro-Repo"
PROTECTED = (".github", "config", "fixtures", "keys", "schemas", "scripts", "tools",
             "tests", "store", "x86_64", "aarch64", "noarch", "SRPMS")
ADDITIONS = {"tools/psop_audit.py", "tests/test_psop_contract.py"}
# Explicit PR-B additions only. The original 234-file baseline/digest is intact.
# No wildcard, new workflow, credential file or production activation entry point.
ADDITIONS |= {
    "tools/psop_context.py", "tools/psop_inputs.py", "tools/psop_history.py",
    "tools/psop_genesis.py", "tools/psop_plan.py", "tools/psop_result.py",
    "tools/psop_authorization.py", "tools/psop_signing.py", "tools/psop_ledger.py",
    "tools/psop_outbox.py", "tools/psop_storage_gateway.py", "tools/psop_receipts.py",
    "schemas/psop-review-v1.schema.json", "schemas/psop-approval-v1.schema.json",
    "schemas/psop-publication-v1.schema.json", "tests/test_psop_publisher.py",
    "tests/test_psop_inputs.py", "tests/psop_support.py", "tests/psop-offline-e2e.py",
}
# PR-C integration only; the original baseline and PR-B list stay intact.
ADDITIONS |= {
    "tools/psop_client.py", "tools/psop_pages.py", "schemas/psop-client-descriptor-v1.schema.json",
    "tests/psop_client_support.py", "tests/psop_acceptance_support.py", "tests/test_psop_client.py",
    "tests/test_psop_provider_faults.py", "tests/psop-fedora44-dnf5-e2e.py",
    "tests/psop-pages-disposable-acceptance.py", ".github/workflows/psop-acceptance-tests.yml",
    "tests/psop_evidence.py",
}
PUBLIC_ROOTS = {
    "rpm": {"path": "keys/production/ro-asd-rpm-signing-public.asc",
            "sha256": "d73e92fcbf1dc9f8900459fa34b5eaa053570f11532ffc8e53373e8289b7ee51",
            "fingerprint": "38CB87F6FBD645309432A6E22E02DEE8828B769B"},
    "metadata": {"path": "keys/production/ro-asd-metadata-signing-public.asc",
                 "sha256": "4eaf0b2903e60442c2f05325a43d85046bba850059b732dfc71e330f5e9e0809",
                 "fingerprint": "1715DDA529B9ADB46D47CB389A62B8F9026E75E5"},
}
GITHUB_GETS = (
    "branches/main", "branches/pages-storage", "pulls/77", "pulls/78", "pulls/79",
    "actions/runs/37935890476", "rulesets", "rulesets/22656730", "environments",
    "environments/repo-beta/deployment-branch-policies",
    "environments/repo-stable/deployment-branch-policies",
    "environments/repo-production-signing/deployment-branch-policies",
    "environments/github-pages/deployment-branch-policies", "pages",
    "actions/workflows/promote-remote-stable.yml/runs?per_page=100",
)


class AuditError(ValueError):
    pass


def _read(root, rel):
    """No traversal, symlink or non-regular member may supply audit evidence."""
    path = pathlib.PurePosixPath(rel)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != rel or "\\" in rel:
        raise AuditError("unsafe audit path")
    root = pathlib.Path(root)
    if root.is_symlink():
        raise AuditError("symlinked audit root")
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise AuditError("symlinked audit member: " + rel)
    if not stat.S_ISREG(current.stat().st_mode):
        raise AuditError("non-regular audit member: " + rel)
    return current.read_bytes()


def validate_profile(profile, root):
    """Validate the inert review profile, never a runtime authorization object."""
    expected = {
        "schema_version": 1, "profile": "psop-pages-stable", "phase": "A",
        "production_activation": False, "writer_authority": [],
        "strict_v3_compatible": False,
        "provider_guarantees": {"deadline_fencing": False, "pages_build_ordering": False,
                                "global_cdn_freshness": False},
        "public_roots": PUBLIC_ROOTS,
    }
    # Canonical JSON comparison also distinguishes booleans from integers.
    canonical = lambda value: json.dumps(value, sort_keys=True, allow_nan=False)
    if canonical(profile) != canonical(expected):
        raise AuditError("phase-A profile cannot activate, merge writer authority or assert strict guarantees")
    for role in PUBLIC_ROOTS.values():
        if hashlib.sha256(_read(root, role["path"])).hexdigest() != role["sha256"]:
            raise AuditError("independently pinned public trust root mismatch")
    return {"profile_contract": "PASS", "production_activation": "BLOCKED", "publishable": False}


def audit_source(root, baseline):
    """Report baseline drift, including additional workflow/code entry points."""
    baseline_hash = hashlib.sha256(json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if baseline.get("base_main") != BASE_MAIN or baseline_hash != BASELINE_SHA256:
        raise AuditError("missing or incorrect phase-A source baseline")
    root = pathlib.Path(root)
    # Preserve the historical phase-A baseline. This separately pinned review
    # contract permits only exact V2 source bytes, never wildcard exemptions.
    files = dict(baseline["files"])
    contract_path = root / V2_REVIEWED_CONTRACT
    if contract_path.exists():
        raw = _read(root, V2_REVIEWED_CONTRACT)
        if hashlib.sha256(raw).hexdigest() != V2_REVIEWED_CONTRACT_SHA256:
            raise AuditError("incorrect reviewed V2 source contract")
        contract = json.loads(raw)
        if contract["base_baseline_sha256"] != BASELINE_SHA256:
            raise AuditError("V2 source contract baseline mismatch")
        for rel, change in contract["files"].items():
            previous = files.get(rel)
            if change["previous_sha256"] != (previous["sha256"] if previous else None):
                raise AuditError("V2 source contract prior digest mismatch")
            files[rel] = {"sha256": change["sha256"], "mode": change["mode"]}
    issues = []
    for rel, expected in files.items():
        try:
            raw = _read(root, rel)
            mode = "100755" if (root / rel).stat().st_mode & stat.S_IXUSR else "100644"
            if hashlib.sha256(raw).hexdigest() != expected["sha256"] or mode != expected["mode"]:
                issues.append("changed: " + rel)
        except (OSError, AuditError):
            issues.append("missing/unsafe: " + rel)
    for folder in PROTECTED:
        directory = root / folder
        if directory.is_symlink():
            issues.append("symlinked protected directory: " + folder)
            continue
        for path in directory.rglob("*"):
            rel = path.relative_to(root).as_posix()
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            if path.is_dir() and not path.is_symlink():
                continue
            if rel not in files and rel not in ADDITIONS:
                issues.append("unreviewed addition: " + rel)
    return {"source_preservation": "FAIL" if issues else "PASS", "issues": sorted(set(issues)),
            "base_main": BASE_MAIN, "publishable": False, "production_activation": "BLOCKED"}


def _git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True)


def audit_history(root, commit):
    """Scan every reachable tree; absence says nothing about deleted/unreachable refs."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise AuditError("history audit requires an exact Git commit")
    shallow = _git(root, "rev-parse", "--is-shallow-repository").strip() == "true"
    commits = _git(root, "rev-list", commit).splitlines()
    hits, immutable_drift, inventories = [], [], {}
    # Check trees, not just commit messages or current HTTP availability.
    for item in commits:
        rows = _git(root, "ls-tree", "-r", item).splitlines()
        entries = {row.split("\t", 1)[1]: row.split("\t", 1)[0] for row in rows}
        paths = list(entries)
        inventories[item] = {p: value for p, value in entries.items()
                             if p.startswith(("snapshots/fedora/44/", "publications/fedora/44/",
                                              "promotions/fedora/44/", "rollbacks/fedora/44/"))}
        stable = [p for p in paths if p.startswith(("rpm/fedora/44/stable/",
                  "publications/fedora/44/stable/", "promotions/fedora/44/"))]
        if stable:
            hits.append({"commit": item, "paths": stable})
    for item in commits:
        parents = _git(root, "show", "-s", "--format=%P", item).split()
        for parent in parents:
            if parent not in inventories:
                continue  # shallow boundaries are explicitly UNVERIFIED below
            for path, previous in inventories[parent].items():
                if inventories[item].get(path) != previous:
                    immutable_drift.append({"commit": item, "parent": parent, "path": path})
    paths = _git(root, "ls-tree", "-r", "--name-only", commit).splitlines()
    snapshots = sorted({p.split("/")[3] for p in paths
                        if p.startswith("snapshots/fedora/44/repo-")})
    return {"commit": commit, "reachable_commits_checked": len(commits), "shallow": shallow,
            "stable_tree_hits": hits, "snapshots": snapshots,
            "immutable_history": "FAIL" if immutable_drift else "UNVERIFIED" if shallow else "PASS",
            "immutable_drift": immutable_drift,
            "historical_absence": "UNVERIFIED" if shallow else "NO_HITS_IN_REACHABLE_TREES" if not hits else "FOUND",
            "deleted_or_unreachable_history": "UNVERIFIED", "publishable": False}


def collect_github():
    """GET public configuration only. Caller must keep access errors UNVERIFIED."""
    observations = []
    for endpoint in GITHUB_GETS:
        response = subprocess.run(["gh", "api", "--method", "GET",
                                   "repos/" + REPOSITORY + "/" + endpoint],
                                  text=True, capture_output=True)
        if response.returncode:
            # Retain structured API errors only, never CLI diagnostics/credentials.
            try:
                error = json.loads(response.stdout)
            except ValueError:
                error = {"message": "GET unavailable; recheck access separately"}
            observations.append({"endpoint": endpoint, "status": "UNVERIFIED", "error": error})
        else:
            observations.append({"endpoint": endpoint, "status": "PASS", "data": json.loads(response.stdout)})
    return {"observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "repository": REPOSITORY, "method": "GET", "observations": observations,
            "secret_endpoints_requested": False, "publishable": False}


def audit_signing(root, pages_root):
    """Verify public input bytes in disposable GPG/RPMDB stores, without DNF."""
    from v3_signed_beta_history import _keyring, _signature, signed_archive_bundle
    from v3_promotion_planner import PlanningError
    import ro_repo
    root, pages_root = pathlib.Path(root), pathlib.Path(pages_root)
    # Always pin public roots externally, before invoking GPG/RPM verification.
    for role in PUBLIC_ROOTS.values():
        if hashlib.sha256(_read(root, role["path"])).hexdigest() != role["sha256"]:
            raise AuditError("public signing root mismatch")
    if pages_root.is_symlink() or not pages_root.is_dir():
        raise AuditError("unsafe extracted Pages tree")
    for path in pages_root.rglob("*"):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise AuditError("unsafe Pages member")
    snapshots = sorted((pages_root / "snapshots/fedora/44").glob("repo-*"))
    publications = sorted((pages_root / "publications/fedora/44/beta").iterdir())
    if not snapshots or not publications:
        raise AuditError("missing public signing inputs")
    metadata, rpm = PUBLIC_ROOTS["metadata"], PUBLIC_ROOTS["rpm"]
    result = {"scope": "read-only extracted public inputs; no DNF or private keys",
              "snapshots": [], "publications": [], "publishable": False}
    with tempfile.TemporaryDirectory(prefix="psop-public-audit-") as temp:
        ring = _keyring(root / metadata["path"], metadata["sha256"], temp)
        home = pathlib.Path(temp) / "gnupg"
        subprocess.run(["gpg", "--no-options", "--homedir", str(home), "--batch", "--import",
                        str(root / metadata["path"])], check=True, capture_output=True)
        try:
            for snapshot in snapshots:
                manifest = _signature(snapshot, "repository-snapshot-v1.json", ring)
                if (manifest.get("rpm_signing_fingerprint") != rpm["fingerprint"] or
                        manifest.get("metadata_signing_fingerprint") != metadata["fingerprint"]):
                    raise AuditError("snapshot signing role mismatch")
                ro_repo.verify_production_candidate(snapshot, home, manifest["creation_provenance"]["run"])
                rpms = sorted((snapshot / "rpm").rglob("*.rpm"))
                ro_repo.verify_signed_rpms(rpms, root / rpm["path"])
                result["snapshots"].append({"snapshot_id": snapshot.name,
                    "metadata_and_rpm_signatures": "PASS", "rpm_paths": len(rpms)})
            for publication in publications:
                value = _signature(publication, "publication-v1.json", ring)
                result["publications"].append({"run": publication.name,
                    "metadata_signature": "PASS", "fields": sorted(value)})
            registry = json.loads(_read(root, "config/producers-v2.json"))
            try:
                signed_archive_bundle(pages_root / "publications/fedora/44/beta",
                    pages_root / "snapshots/fedora/44", registry, "ro-assist",
                    root / metadata["path"], metadata["sha256"],
                    datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
                result["strict_history"] = {"status": "PASS"}
            except PlanningError as exc:
                result["strict_history"] = {"status": "BLOCKED", "reason": str(exc)}
        finally:
            subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"], capture_output=True)
    # The caller binds these local bytes to an exact Git tree separately.
    # This report is never proof of remote availability or publisher approval.
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("source", "history", "github", "signing"))
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument("--commit", default=PAGES_COMMIT)
    parser.add_argument("--pages-root", type=pathlib.Path)
    args = parser.parse_args()
    if args.command == "history":
        result = audit_history(args.root, args.commit)
    elif args.command == "github":
        result = collect_github()
    elif args.command == "signing":
        if args.pages_root is None:
            parser.error("signing requires --pages-root (an extracted exact public Git tree)")
        result = audit_signing(args.root, args.pages_root)
    else:
        profile = json.loads(_read(args.root, "docs/psop/phase-a-profile.json"))
        baseline = json.loads(_read(args.root, "docs/evidence/psop-phase1/base-protected-files.json"))
        result = {**audit_source(args.root, baseline), **validate_profile(profile, args.root)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if "FAIL" in (result.get("source_preservation"), result.get("immutable_history")) else 0


if __name__ == "__main__":
    raise SystemExit(main())
