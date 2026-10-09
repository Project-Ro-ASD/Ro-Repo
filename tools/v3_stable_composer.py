"""Stage a V3 stable package set from two local, immutable snapshot trees.

This is an OFFLINE, UNTRUSTED candidate materializer. It intentionally does not
sign RPMs, generate DNF repodata, authorize promotion, or publish any channel.
Callers must verify signed source snapshot manifests, RPM signatures,
attestations and policy evidence *before* using this output in a production
signing/publishing workflow.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import tempfile

from v3_promotion_planner import PlanningError, _parse, plan

SNAPSHOT_ID = re.compile(r"^repo-f44-[0-9]{8}-[0-9]{3}$")


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_snapshot(root):
    if not isinstance(root, pathlib.Path):
        root = pathlib.Path(root)
    if root.is_symlink() or not root.is_dir() or not SNAPSHOT_ID.fullmatch(root.name):
        raise PlanningError("invalid or symlinked snapshot directory")
    manifest_path = root / "repository-snapshot-v1.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise PlanningError("snapshot manifest missing or symlinked")
    try:
        with manifest_path.open("r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, ValueError) as exc:
        raise PlanningError("snapshot manifest cannot be read") from exc
    if not isinstance(manifest, dict) or manifest.get("snapshot_id") != root.name:
        raise PlanningError("snapshot path and manifest identity differ")
    return root, manifest


def _file_paths(root, entry):
    name, epoch, version, release, arch = _parse(entry)
    filename = entry["filename"]
    if filename != f"{name}-{version}-{release}.{arch}.rpm":
        raise PlanningError("RPM filename does not match exact NEVRA")
    folders = ("source",) if arch in {"src", "nosrc"} else (
        ("x86_64", "aarch64") if arch == "noarch" else (arch,)
    )
    for folder in folders:
        repo_root = root / "rpm"
        arch_dir = repo_root / folder
        location = arch_dir / filename
        if (repo_root.is_symlink() or arch_dir.is_symlink() or location.is_symlink()
                or not arch_dir.is_dir() or not location.is_file()):
            raise PlanningError(f"missing or unsafe source RPM: {folder}/{filename}")
        if not stat.S_ISREG(location.stat().st_mode):
            raise PlanningError("source RPM must be a regular file")
        yield folder, location


def _copy_exact(root, entry, candidate, inventory):
    signed_digest = entry["published_signed_artifact_sha256"]
    for folder, source in _file_paths(root, entry):
        if _sha256(source) != signed_digest:
            raise PlanningError(f"signed RPM digest mismatch: {source.name} ({folder})")
        rel = f"rpm/{folder}/{source.name}"
        dest = candidate / rel
        if dest.exists() or dest.is_symlink():
            raise PlanningError("RPM filename collision in composed repository")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
        if _sha256(dest) != signed_digest:
            raise PlanningError(f"RPM changed during staging: {rel}")
        inventory.append({"path": rel, "sha256": signed_digest})


def compose(beta_snapshot_dir, stable_snapshot_dir, registry, promotion_group, output_dir):
    """Materialize a deterministic signed-RPM *candidate*, never a repository.

    No repodata, no GPG signing, no production action. Output must be new.
    stable_snapshot_dir=None bootstraps an empty stable package set.
    """
    beta_dir, beta = _read_snapshot(beta_snapshot_dir)
    if stable_snapshot_dir is None:
        stable_dir = stable = None
    else:
        stable_dir, stable = _read_snapshot(stable_snapshot_dir)
    proposal = plan(beta, stable, registry, promotion_group)

    output = pathlib.Path(output_dir)
    if output.exists() or output.is_symlink():
        raise PlanningError("immutable composition output path already exists")
    if not output.name or output.name in {".", ".."}:
        raise PlanningError("invalid output directory")
    output_absolute = output.resolve()
    for source_dir in (beta_dir, stable_dir):
        if source_dir is None:
            continue
        source_absolute = source_dir.resolve()
        if output_absolute == source_absolute or source_absolute in output_absolute.parents:
            raise PlanningError("refusing to place composition inside an input snapshot")

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = pathlib.Path(tempfile.mkdtemp(prefix=".v3-stable-stage-", dir=output.parent))
    staged = temporary / "candidate"
    try:
        staged.mkdir()
        chosen_keys = {(p["nevra"], p["architecture"]) for p in proposal["selected_group_packages"]}
        inventory = []
        for item in proposal["resulting_stable_packages"]:
            source_dir = beta_dir if (item["nevra"], item["architecture"]) in chosen_keys else stable_dir
            if source_dir is None:
                raise PlanningError("stable package has no source snapshot")
            _copy_exact(source_dir, item, staged, inventory)

        inventory.sort(key=lambda row: row["path"])
        composition = {
            "schema_version": 1,
            "scope": "offline-v3-untrusted-composition",
            "promotion_group": promotion_group,
            "candidate_sha256": proposal["candidate_sha256"],
            "beta_snapshot_id": beta["snapshot_id"],
            "previous_stable_snapshot_id": None if stable is None else stable["snapshot_id"],
            "plan_sha256": hashlib.sha256(_canonical(proposal)).hexdigest(),
            "files": inventory,
            "rpm_file_count": len(inventory),
            "signature_verified": False,
            "rpm_signature_verified": False,
            "dnf_installability_verified": False,
            "repository_metadata_signed": False,
            "approval_granted": False,
            "publishable": False,
        }
        (staged / "promotion-plan-v3.json").write_bytes(_canonical(proposal) + b"\n")
        (staged / "composition-v3.json").write_bytes(_canonical(composition) + b"\n")
        if output.exists() or output.is_symlink():
            raise PlanningError("composition output appeared concurrently")
        os.rename(staged, output)
        return composition
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Stage unsigned, non-publishable V3 stable candidate")
    parser.add_argument("--beta-snapshot", required=True)
    parser.add_argument("--stable-snapshot", help="omit for empty first stable bootstrap")
    parser.add_argument("--registry", required=True)
    parser.add_argument("--promotion-group", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    with pathlib.Path(args.registry).open("r", encoding="utf-8") as stream:
        registry = json.load(stream)
    print(json.dumps(compose(args.beta_snapshot, args.stable_snapshot, registry, args.promotion_group, args.output),
                     sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
