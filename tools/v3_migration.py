"""Read-only V2 inventory import rehearsal and explicit writer cutover proposal.

No stable pointer, workflow or ledger is changed. Actual adoption requires a
fresh protected authorization, authenticated legacy history, remote checks,
client migration and a separate activation PR.
"""
import difflib
import pathlib
import shutil
import tempfile

from v3_backend_trust import digest
from v3_integration import tree_inventory
from v3_policy_profile import profile, sha
from v3_promotion_planner import PlanningError, _policies, _packages, _parse, plan


def retirement_patch(workflow):
    """Reviewable future patch, never applied to the active V2 workflow."""
    import yaml
    raw = pathlib.Path(workflow).read_text()
    value = yaml.safe_load(raw)
    if not isinstance(value.get("jobs"), dict) or not value["jobs"]:
        raise PlanningError("unrecognized legacy stable writer")
    modified = raw.splitlines(keepends=True)
    # The current single writer job is a two-space YAML mapping. Fail rather
    # than making a partial retirement patch if its shape ever changes.
    names = set(value["jobs"])
    found = set()
    lines = []
    in_jobs = False
    for line in modified:
        if line == "jobs:\n":
            in_jobs = True
        lines.append(line)
        if in_jobs and line.startswith("  ") and not line.startswith("   ") and line.strip().endswith(":"):
            name = line.strip()[:-1]
            if name in names:
                if "if" in value["jobs"][name]:
                    raise PlanningError("legacy job already has a condition; manual retirement review required")
                lines.append("    if: ${{ false }} # Future V3 cutover: retire whole-beta stable writer\n")
                found.add(name)
    if found != names:
        raise PlanningError("legacy stable writer patch incomplete")
    return "".join(difflib.unified_diff(modified, lines, fromfile="a/.github/workflows/promote-remote-stable.yml", tofile="b/.github/workflows/promote-remote-stable.yml"))


def writer_gate(*, legacy_active, writer_realms, immutable_clients, protected_import):
    if legacy_active or not writer_realms or len(set(writer_realms)) != 1 or not immutable_clients or not protected_import:
        return "BLOCKED"
    # Passing the proposed writer configuration is insufficient to activate
    # the milestone: its production adapters remain disabled in code.
    return "BLOCKED"


def assess_manifest(manifest, registry):
    groups, owners = _policies(registry)
    packages = _packages(manifest, owners)
    present = sorted({owners[_parse(p)[0]] for p in packages.values()})
    issues = []
    for group in present:
        policy = profile(registry, group)
        members = [p for p in packages.values() if owners[_parse(p)[0]] == group]
        for arch in policy["architectures"]:
            names = {_parse(p)[0] for p in members if p["architecture"] == arch}
            if names != set(policy["package_names"]):
                issues.append(group + "/" + arch + ": incomplete canonical binary set")
        if len([p for p in members if p["architecture"] == "src"]) != 1:
            issues.append(group + ": missing/ambiguous SRPM closure")
        try:
            # Validate linkage, all subpackages and exact bytes without a change.
            unchanged = plan(manifest, manifest, registry, group)
            if sorted(unchanged["resulting_stable_packages"], key=lambda p: p["nevra"]) != sorted(manifest["packages"], key=lambda p: p["nevra"]):
                raise PlanningError("silent cross-group replacement")
        except PlanningError as exc:
            issues.append(group + ": " + str(exc))
    return {"groups": present, "issues": sorted(set(issues)), "canonical_closure": "FAIL" if issues else "PASS"}


def rehearse(source, registry, *, metadata_key, metadata_key_sha256, rpm_key, rpm_key_sha256,
             storage_commit, workflow):
    from v3_full_set_dnf import _signed_view, _rpm_set_preflight
    from v3_signed_beta_history import _keyring
    import re
    if not isinstance(storage_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", storage_commit):
        raise PlanningError("exact V2 storage commit required")
    before = tree_inventory(source)
    with tempfile.TemporaryDirectory(prefix="v3-migration-") as directory:
        work = pathlib.Path(directory)
        frozen = work / pathlib.Path(source).name
        shutil.copytree(source, frozen, symlinks=True)
        if tree_inventory(frozen) != before:
            raise PlanningError("V2 input changed while freezing")
        ring = _keyring(metadata_key, metadata_key_sha256, work)
        manifest = _signed_view(frozen, ring)
        preflight = _rpm_set_preflight(frozen, manifest, rpm_key, rpm_key_sha256, work / "preflight")
        assessment = assess_manifest(manifest, registry)
        if tree_inventory(source) != before or tree_inventory(frozen) != before:
            raise PlanningError("V2 input changed during import rehearsal")
    patch = retirement_patch(workflow)
    return {"schema_version": 3, "scope": "v3-v2-migration-proposal", "publishable": False,
            "storage_commit": storage_commit, "legacy_snapshot_id": manifest["snapshot_id"],
            "legacy_tree_sha256": sha(before), "packages": manifest["packages"], "inventory": before,
            "rpm_preflight_sha256": sha(preflight), "registry_sha256": sha(registry), **assessment,
            "history_preserved": True, "rpm_bytes_preserved": True,
            "legacy_writer_sha256": digest(pathlib.Path(workflow).read_bytes()), "retirement_patch": patch,
            "activation": "BLOCKED", "protected_import": "UNVERIFIED", "immutable_clients": "UNVERIFIED"}


def assert_preserved(proposal, resulting_manifest):
    if resulting_manifest["packages"] != proposal["packages"]:
        raise PlanningError("migration may not silently replace any group or RPM bytes")
    return "PASS"
