"""Offline V3 component promotion planner.

Pure metadata calculation. Not a trust verifier, RPM solver, signer or publisher.
Production promotion MUST independently authenticate inputs and validate the final
repository transaction before acting on any plan.
"""
import hashlib
import json
import re


class PlanningError(ValueError):
    """An ambiguous or unsafe promotion proposal."""


FIELDS = ("nevra", "filename", "architecture", "producer_manifest_digest",
          "producer_artifact_sha256", "published_signed_artifact_sha256")
DIGEST = re.compile(r"^[a-f0-9]{64}$")
ARCHES = {"x86_64", "aarch64", "noarch", "src", "nosrc"}


def _parse(entry):
    if not isinstance(entry, dict) or any(not isinstance(entry.get(k), str) or not entry[k] for k in FIELDS):
        raise PlanningError("missing or malformed package metadata")
    for field in FIELDS[3:]:
        if not DIGEST.fullmatch(entry[field]):
            raise PlanningError("invalid package digest")
    try:
        head, arch = entry["nevra"].rsplit(".", 1)
        prefix, release = head.rsplit("-", 1)
        name_epoch, version = prefix.rsplit(":", 1)
        name, epoch = name_epoch.rsplit("-", 1)
    except ValueError as exc:
        raise PlanningError("malformed NEVRA") from exc
    if not name or not epoch.isdecimal() or not version or not release or arch not in ARCHES:
        raise PlanningError("malformed NEVRA")
    if arch != entry["architecture"] or not entry["filename"].endswith(".rpm") or "/" in entry["filename"] or "\\" in entry["filename"]:
        raise PlanningError("invalid filename or architecture")
    return name, epoch, version, release, arch


def _policies(registry):
    if not isinstance(registry, dict) or not isinstance(registry.get("producers"), list):
        raise PlanningError("invalid producer registry")
    groups, owner = {}, {}
    for producer in registry["producers"]:
        for component in producer.get("components", []):
            group = component.get("promotion_group")
            names = component.get("package_names")
            arches = component.get("architectures")
            if not isinstance(group, str) or not group or not isinstance(names, list) or not names or not isinstance(arches, list) or not arches:
                raise PlanningError("invalid component policy")
            if group in groups:
                raise PlanningError("ambiguous promotion group")
            if len(names) != len(set(names)) or not set(arches) <= ARCHES or len(arches) != len(set(arches)):
                raise PlanningError("invalid policy names or architectures")
            for name in names:
                if not isinstance(name, str) or not name or name in owner:
                    raise PlanningError("ambiguous package owner")
                owner[name] = group
            groups[group] = {"names": set(names), "arches": set(arches), "component": component.get("component"),
                             "complete": component.get("require_complete_architecture_set", False)}
    return groups, owner


def _packages(manifest, owner, *, empty=False):
    if manifest is None and empty:
        return {}
    if not isinstance(manifest, dict) or manifest.get("fedora_release") != 44 or not isinstance(manifest.get("packages"), list):
        raise PlanningError("invalid snapshot manifest")
    result = {}
    binary_names = set()
    for entry in manifest["packages"]:
        name, epoch, ver, rel, arch = _parse(entry)
        if name not in owner:
            raise PlanningError("unregistered package in snapshot: " + name)
        identity = (name, arch)
        if identity in result:
            raise PlanningError("duplicate name/architecture in snapshot")
        result[identity] = dict(entry)
        if arch not in {"src", "nosrc"}:
            binary_names.add(name)
    for name, arch in result:
        if arch in {"src", "nosrc"} and name not in binary_names:
            raise PlanningError("orphan source package")
    return result


def _group_of(entry, owner):
    return owner[_parse(entry)[0]]


def _verify_candidate(packages, policy, owner, group):
    selected = [v for v in packages.values() if _group_of(v, owner) == group]
    if not selected:
        raise PlanningError("candidate group absent")
    binaries = [p for p in selected if p["architecture"] not in {"src", "nosrc"}]
    sources = [p for p in selected if p["architecture"] in {"src", "nosrc"}]
    if not binaries or not sources:
        raise PlanningError("candidate missing binary or SRPM")
    found_names = {_parse(p)[0] for p in binaries}
    if found_names != policy["names"]:
        raise PlanningError("candidate has incomplete binary package names")
    if any(p["architecture"] not in policy["arches"] for p in binaries):
        raise PlanningError("candidate contains forbidden architecture")
    # Every advertised supported architecture must be covered, except noarch
    # which is a single architecture shared by all target repository views.
    if policy["complete"] and any({_parse(p)[0] for p in binaries if p["architecture"] == arch} != policy["names"] for arch in policy["arches"]):
        raise PlanningError("candidate has incomplete architecture set")
    if len(sources) != 1:
        raise PlanningError("candidate must contain one source RPM")
    source_name, source_epoch, source_ver, source_rel, _ = _parse(sources[0])
    digest = sources[0]["producer_manifest_digest"]
    for p in selected:
        name, epoch, version, release, _ = _parse(p)
        if (epoch, version, release) != (source_epoch, source_ver, source_rel) or p["producer_manifest_digest"] != digest:
            raise PlanningError("candidate source/provenance mismatch")
    if source_name not in policy["names"]:
        raise PlanningError("unexpected source package name")
    return selected


def plan(candidate_snapshot, stable_snapshot, registry, promotion_group):
    """Return deterministic JSON-compatible dry-run; NEVER modifies inputs.

    stable_snapshot=None means the first, empty stable publication.
    All manifests here are UNTRUSTED until upstream signature/attestation checks.
    """
    groups, owner = _policies(registry)
    if promotion_group not in groups:
        raise PlanningError("unknown promotion group")
    candidate = _packages(candidate_snapshot, owner)
    stable = _packages(stable_snapshot, owner, empty=True)
    chosen = _verify_candidate(candidate, groups[promotion_group], owner, promotion_group)
    old_group = {key: p for key, p in stable.items() if _group_of(p, owner) == promotion_group}
    additions = {(_parse(p)[0], p["architecture"]): p for p in chosen}
    result = {key: p for key, p in stable.items() if key not in old_group}
    for key, p in additions.items():
        other = result.get(key)
        if other is not None:
            raise PlanningError("candidate collides with another stable group")
        result[key] = p
    # Preserve immutable identities of all unrelated previously stable packages.
    for key, p in stable.items():
        if _group_of(p, owner) != promotion_group and result.get(key) != p:
            raise PlanningError("unrelated stable package changed")
    for key, p in additions.items():
        prev = old_group.get(key)
        if prev is not None and prev["nevra"] == p["nevra"] and prev["published_signed_artifact_sha256"] != p["published_signed_artifact_sha256"]:
            raise PlanningError("same NEVRA has different signed bytes")
    before = sorted(old_group.values(), key=lambda p: (p["nevra"], p["filename"]))
    after = sorted(chosen, key=lambda p: (p["nevra"], p["filename"]))
    final = sorted(result.values(), key=lambda p: (p["nevra"], p["filename"]))
    canonical = json.dumps(after, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema_version": 1,
        "scope": "offline-v3-untrusted-plan",
        "promotion_group": promotion_group,
        "candidate_sha256": hashlib.sha256(canonical).hexdigest(),
        "candidate_snapshot_id": candidate_snapshot.get("snapshot_id"),
        "stable_base_snapshot_id": None if stable_snapshot is None else stable_snapshot.get("snapshot_id"),
        "replaced_group_packages": before,
        "selected_group_packages": after,
        "resulting_stable_packages": final,
        "unchanged_stable_package_count": len(stable) - len(old_group),
        "requires_signature_validation": True,
        "requires_dnf_dependency_validation": True,
        "publishable": False,
    }
