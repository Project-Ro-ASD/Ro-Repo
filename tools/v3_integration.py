"""Integrated V3 proposal and acceptance gate. No production write commands.

Reuse the signed archive/API bridge, planner, composer, RPM preflight and group
validator. Even a consistent, locally signed proposal cannot grant production
authority: OIDC, protected approval and independently supplied trust roots are
still unavailable. Production activation is a separate reviewed change.
"""
import argparse
import hashlib
import json
import pathlib
import shutil
import tempfile

from v3_beta_evidence_bridge import verify_evidence
from v3_group_validation import stable_set_digest, validate_claim
from v3_policy_profile import canonical, sha, profile, require_complete
from v3_promotion_planner import PlanningError, plan, _parse
from v3_promotion_policy import evaluate, _time
from v3_rpm_preflight import verify as verify_rpms
from v3_signed_beta_history import _signature, _keyring, _json_file
from v3_stable_composer import compose, _sha256

PRODUCTION_GATES = (
    "independent-trust-roots", "source-attestation", "complete-live-beta-history",
    "oidc-workload-identity", "protected-environment-authorization",
    "production-publication-approval", "independent-remote-verification",
)


def tree_inventory(root):
    root = pathlib.Path(root)
    if root.is_symlink() or not root.is_dir():
        raise PlanningError("unsafe repository tree")
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise PlanningError("unsafe repository member")
        if path.is_file():
            files.append({"path": path.relative_to(root).as_posix(), "sha256": _sha256(path)})
    if not files:
        raise PlanningError("empty repository tree")
    return files


def _provenance(build, manifest, selected, policy):
    from ro_repo import validate_schema
    validate_schema(build, "snapshot-build-evidence-v1")
    if (build["snapshot_id"] != manifest["snapshot_id"] or
            build["metadata_signing_fingerprint"] != manifest["metadata_signing_fingerprint"] or
            build["rpm_signing_fingerprint"] != manifest["rpm_signing_fingerprint"]):
        raise PlanningError("build evidence snapshot/signing role mismatch")
    needed = {p["producer_manifest_digest"] for p in selected}
    matching = [c for c in build["components"] if c["acceptance_manifest_digest"] in needed]
    if (len(matching) != len(needed) or
            {c["acceptance_manifest_digest"] for c in matching} != needed or
            any(c["source_repository"] != policy["repository"] or
                c["signing_run"] not in build["source_signing_runs"] for c in matching)):
        raise PlanningError("candidate acceptance/source/signing provenance mismatch")
    return sorted(matching, key=lambda c: c["acceptance_manifest_digest"])


def proposal(p, registry, history, provenance, *, now, mode="normal", reason=None,
             previous_sha256=None, result_sha256=None, evidence=None):
    """Deterministic review object; callers must verify input acquisition."""
    policy = require_complete(p, registry)
    assessment = evaluate(p, history, policy["risk_class"], mode, now, reason=reason)
    # Public first-seen is deliberately separate from identity, preventing a
    # newer containing beta snapshot from resetting unchanged artifact dwell.
    identity = {"promotion_group": p["promotion_group"], "fedora_release": 44,
                "policy": policy, "packages": p["selected_group_packages"],
                "source_provenance": provenance}
    candidate = sha(identity)
    evidence = {} if evidence is None else evidence
    if not isinstance(evidence, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                           or len(v) != 64 or any(c not in "0123456789abcdef" for c in v)
                                           for k, v in evidence.items()):
        raise PlanningError("invalid immutable evidence identities")
    for digest in (previous_sha256, result_sha256):
        if digest is not None and (not isinstance(digest, str) or len(digest) != 64 or
                                   any(c not in "0123456789abcdef" for c in digest)):
            raise PlanningError("invalid stable state digest")
    if (p["stable_base_snapshot_id"] is None) != (previous_sha256 is None):
        raise PlanningError("previous stable snapshot/digest mismatch")
    body = {
        "schema_version": 3, "scope": "v3-integrated-proposal-untrusted",
        "candidate_sha256": candidate, "artifact_set_sha256": p["candidate_sha256"],
        "candidate_identity": identity, "promotion_group": p["promotion_group"],
        "mode": mode, "reason": assessment["reason"], "policy_version": policy["version"],
        "policy_sha256": sha(policy), "previous_stable_snapshot_id": p["stable_base_snapshot_id"],
        "previous_stable_sha256": previous_sha256, "result_stable_sha256": result_sha256,
        "stable_set_sha256": stable_set_digest(p), "first_seen": {
            "published_at": assessment["first_published_at"],
            "publication_run": assessment["first_publication_run"]},
        "dwell_met": assessment["dwell_met"], "minimum_beta_days": assessment["minimum_beta_days"],
        "evidence_sha256": dict(sorted(evidence.items())), "approval_granted": False,
        "publishable": False,
    }
    return {**body, "proposal_sha256": sha(body)}


def verify_proposal(value):
    if (not isinstance(value, dict) or value.get("scope") != "v3-integrated-proposal-untrusted"
            or value.get("publishable") is not False or value.get("approval_granted") is not False):
        raise PlanningError("invalid integrated proposal authority")
    body = {k: v for k, v in value.items() if k != "proposal_sha256"}
    if (sha(body) != value.get("proposal_sha256") or
            sha(value.get("candidate_identity")) != value.get("candidate_sha256")):
        raise PlanningError("mutable proposal or candidate identity")
    from ro_repo import validate_schema, ContractError
    try:
        validate_schema(value, "integration-proposal-v3")
    except ContractError as exc:
        raise PlanningError("invalid integrated proposal schema") from exc
    identity = value["candidate_identity"]
    policy = identity["policy"]
    if (value["promotion_group"] != identity["promotion_group"] or
            value["policy_sha256"] != sha(policy) or
            value["policy_version"] != policy["version"]):
        raise PlanningError("cross-module policy/candidate mismatch")
    if (value["mode"] not in {"normal", "fast-track"}
            or (value["mode"] == "normal" and value["reason"] is not None)
            or (value["mode"] == "fast-track" and (not isinstance(value["reason"], str) or not value["reason"].strip()))
            or type(value["dwell_met"]) is not bool
            or sha(identity["packages"]) != value["artifact_set_sha256"]):
        raise PlanningError("invalid policy mode, reason or artifact binding")
    if (value["previous_stable_snapshot_id"] is None) != (value["previous_stable_sha256"] is None):
        raise PlanningError("previous stable snapshot/digest mismatch")
    _time(value["first_seen"]["published_at"])
    return value


def acceptance(value, validation=None):
    verify_proposal(value)
    gates = {name: "UNVERIFIED" for name in PRODUCTION_GATES}
    gates["production-activation"] = "BLOCKED"
    gates["dwell"] = "PASS" if value["dwell_met"] else "UNVERIFIED" if value["mode"] == "fast-track" else "FAIL"
    gates["complete-result-digest"] = "PASS" if value["result_stable_sha256"] else "UNVERIFIED"
    gates["component-tests"] = "UNVERIFIED"
    if validation is not None:
        if (validation.get("claim_consistent") is not True or validation.get("publishable") is not False
                or validation.get("candidate_sha256") != value["artifact_set_sha256"]
                or validation.get("stable_set_sha256") != value["stable_set_sha256"]):
            raise PlanningError("mismatched component validation assessment")
        # Consistency of self-reported success is not authenticated execution.
    return {"scope": "v3-integration-acceptance", "proposal_sha256": value["proposal_sha256"],
            "gates": gates, "approval_granted": False, "publishable": False}


def prepare(beta, stable, registry, group, output, *, publications, snapshots,
            collection, metadata_key, metadata_key_sha256, rpm_key, rpm_key_sha256,
            now, mode="normal", reason=None, claim=None, result_snapshot=None):
    """Verify signed inputs, compose exact bytes, link history and test claims."""
    beta = pathlib.Path(beta)
    stable = pathlib.Path(stable) if stable is not None else None
    output = pathlib.Path(output)
    if output.exists() or output.is_symlink():
        raise PlanningError("immutable integration output already exists")
    result_snapshot = None if result_snapshot is None else pathlib.Path(result_snapshot)
    for source in (beta, stable, result_snapshot):
        if source is not None and (source.is_symlink() or not source.is_dir()
                                  or source.resolve() in output.resolve().parents):
            raise PlanningError("unsafe input snapshot/output relationship")
    with tempfile.TemporaryDirectory(prefix="v3-integration-key-") as home:
        ring = _keyring(metadata_key, metadata_key_sha256, home)
        input_trees = {source: tree_inventory(source) for source in (beta, stable, result_snapshot) if source is not None}
        manifest = _signature(beta, "repository-snapshot-v1.json", ring)
        prior = None if stable is None else _signature(stable, "repository-snapshot-v1.json", ring)
        p = plan(manifest, prior, registry, group)
        policy = require_complete(p, registry)
        build = _signature(beta, "snapshot-build-evidence-v1.json", ring)
        if build.get("repository_snapshot_sha256") != _sha256(beta / "repository-snapshot-v1.json"):
            raise PlanningError("build evidence manifest digest mismatch")
        provenance = _provenance(build, manifest, p["selected_group_packages"], policy)
        bridge = verify_evidence(collection, publications, snapshots, registry,
                                 group, metadata_key, metadata_key_sha256, now)
        # Full-set verification uses the *pinned* RPM key rather than keys
        # embedded in an untrusted input tree. Composition rechecks every hash.
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".v3-integrate-", dir=output.parent) as temp:
            stage = pathlib.Path(temp) / "result"
            stage.mkdir()
            compose(beta, stable, registry, group, stage / "composition")
            if _json_file(stage / "composition/promotion-plan-v3.json") != p:
                raise PlanningError("input changed between signature verification and composition")
            preflight = verify_rpms(stage / "composition", rpm_key, rpm_key_sha256)
            validation = None if claim is None else validate_claim(p, registry, claim)
            evidence = {"signed-build": _sha256(beta / "snapshot-build-evidence-v1.json"),
                        "beta-history-api-consistency": sha(bridge), "rpm-preflight": sha(preflight)}
            if claim is not None:
                if _time(claim["tested_at"]) > _time(now):
                    raise PlanningError("future test evidence")
                evidence["group-validation-claim"] = sha(claim)
            result_sha = None
            if result_snapshot is not None:
                result_root = pathlib.Path(temp) / "frozen-result" / result_snapshot.name
                shutil.copytree(result_snapshot, result_root, symlinks=True)
                if tree_inventory(result_root) != input_trees[result_snapshot]:
                    raise PlanningError("signed result changed during freezing")
                from v3_full_set_dnf import _signed_view
                result_manifest = _signed_view(result_root, ring)
                if result_manifest["parent_snapshot"] != p["stable_base_snapshot_id"]:
                    raise PlanningError("signed result parent differs from stable base")
                if sorted(result_manifest["packages"], key=lambda x: x["nevra"]) != sorted(p["resulting_stable_packages"], key=lambda x: x["nevra"]):
                    raise PlanningError("signed result does not match composed full stable set")
                from v3_stable_composer import _file_paths
                for item in p["resulting_stable_packages"]:
                    for _, path in _file_paths(result_root, item):
                        if _sha256(path) != item["published_signed_artifact_sha256"]:
                            raise PlanningError("retained result RPM changed")
                if tree_inventory(result_root) != input_trees[result_snapshot]:
                    raise PlanningError("signed result changed during verification")
                result_sha = sha(input_trees[result_snapshot])
            if any(tree_inventory(source) != expected for source, expected in input_trees.items()):
                raise PlanningError("source snapshot changed during integrated verification")
            value = proposal(p, registry, bridge["candidate_remote_verify_times"], provenance,
                             now=now, mode=mode, reason=reason,
                             previous_sha256=None if stable is None else sha(input_trees[stable]),
                             result_sha256=result_sha, evidence=evidence)
            for name, report in (("proposal-v3.json", value), ("acceptance-v3.json", acceptance(value, validation)),
                                 ("beta-evidence-v3.json", bridge), ("rpm-preflight-v3.json", preflight)):
                (stage / name).write_bytes(canonical(report) + b"\n")
            if output.exists() or output.is_symlink():
                raise PlanningError("integration output appeared concurrently")
            stage.rename(output)
    return value


def prepare_live(pages_checkout, registry, group, output, *, token, request_json,
                 main_sha, pages_sha, metadata_key, metadata_key_sha256,
                 rpm_key, rpm_key_sha256, beta_snapshot_id, stable_snapshot_id,
                 source_receipt_run, download_zip, now, claim=None, result_snapshot=None,
                 mode="normal", reason=None):
    """One read-only acquisition path reusing every existing live trust check.

    Caller pins and API consistency remain untrusted; no successful result
    can satisfy the unavailable production authorization/OIDC assertions.
    """
    from v3_github_source_pins import audit_with_live_pins, verify_registry_pin, _refs_match
    from v3_github_beta_api import collect
    from v3_live_receipt_audit import audit_live_run
    from v3_pages_archive_provenance import verify_checkout, _tracked_bytes, _git
    from v3_stable_composer import SNAPSHOT_ID
    for identifier in (beta_snapshot_id, stable_snapshot_id):
        if identifier is not None and (not isinstance(identifier, str) or not SNAPSHOT_ID.fullmatch(identifier)):
            raise PlanningError("invalid pinned snapshot identity")
    registry_check = verify_registry_pin(request_json, token, main_sha, registry)
    live_audit = audit_with_live_pins(request_json, token, expected_main_sha=main_sha,
                                    expected_pages_sha=pages_sha, expected_key_sha256=metadata_key_sha256,
                                    local_key=metadata_key, pages_checkout=pages_checkout, registry=registry,
                                    promotion_group=group, now=now)
    runtime_audit = audit_live_run(source_receipt_run, token, request_json, download_zip)
    collection = collect("Project-Ro-ASD/Ro-Repo", token, request_json)
    root = verify_checkout(pages_checkout, pages_sha)
    snapshots = root / "snapshots/fedora/44"
    beta = snapshots / beta_snapshot_id
    stable = None if stable_snapshot_id is None else snapshots / stable_snapshot_id
    stable_channel = root / "rpm/fedora/44/stable"
    stable_relative = "rpm/fedora/44/stable"
    pinned_stable = _git(root, "ls-tree", "HEAD", "--", stable_relative)
    stable_bytes = {}
    if stable_snapshot_id is None and (pinned_stable or stable_channel.exists() or stable_channel.is_symlink()):
        raise PlanningError("empty bootstrap would discard existing stable channel")
    if stable_snapshot_id is not None:
        for name in ("publication-v1.json", "publication-v1.json.asc"):
            stable_bytes[name] = _tracked_bytes(root, stable_relative + "/" + name)
        with tempfile.TemporaryDirectory(prefix="v3-live-base-key-") as home:
            ring = _keyring(metadata_key, metadata_key_sha256, home)
            frozen = pathlib.Path(home) / "pinned-stable"
            frozen.mkdir()
            for name, raw in stable_bytes.items():
                (frozen / name).write_bytes(raw)
            publication = _signature(frozen, "publication-v1.json", ring)
            if publication.get("channel") != "stable" or publication.get("snapshot_id") != stable_snapshot_id:
                raise PlanningError("stale signed current stable base")
    # These checks are intentionally separate assertions; there is no
    # coercion of a read-only receipt into protected production authority.
    with tempfile.TemporaryDirectory(prefix="v3-live-integrated-") as temp:
        value = prepare(beta, stable, registry, group, pathlib.Path(temp) / "proposal",
                        publications=root / "publications/fedora/44/beta", snapshots=snapshots,
                        collection=collection, metadata_key=metadata_key, metadata_key_sha256=metadata_key_sha256,
                        rpm_key=rpm_key, rpm_key_sha256=rpm_key_sha256, now=now, mode=mode, reason=reason,
                        claim=claim, result_snapshot=result_snapshot)
        value["evidence_sha256"].update({"live-source-parity": sha(live_audit),
                                         "live-completed-receipt": sha(runtime_audit),
                                         "pinned-registry": sha(registry_check)})
        value["proposal_sha256"] = sha({k: v for k, v in value.items() if k != "proposal_sha256"})
        _refs_match(request_json, token, main_sha, pages_sha)
        verify_checkout(root, pages_sha)
        for name, raw in stable_bytes.items():
            if _tracked_bytes(root, stable_relative + "/" + name) != raw:
                raise PlanningError("pinned stable publication changed during proposal")
        if stable_snapshot_id is None and (stable_channel.exists() or stable_channel.is_symlink()):
            raise PlanningError("stable channel appeared during bootstrap proposal")
        output = pathlib.Path(output)
        if output.exists() or output.is_symlink():
            raise PlanningError("immutable live integration output already exists")
        output.parent.mkdir(parents=True, exist_ok=True)
        stage = pathlib.Path(temp) / "proposal"
        (stage / "proposal-v3.json").write_bytes(canonical(value) + b"\n")
        (stage / "acceptance-v3.json").write_bytes(canonical(acceptance(value)) + b"\n")
        # Use a same-filesystem stage for the final atomic rename.
        with tempfile.TemporaryDirectory(prefix=".v3-live-", dir=output.parent) as final_temp:
            final = pathlib.Path(final_temp) / "proposal"
            shutil.copytree(stage, final)
            if output.exists() or output.is_symlink():
                raise PlanningError("concurrent live integration output")
            final.rename(output)
    return value


def main():
    parser = argparse.ArgumentParser(description="Integrated read-only V3 proposal; production disabled")
    for field in ("beta", "registry", "group", "output", "publications", "snapshots", "collection",
                  "metadata-key", "metadata-key-sha256", "rpm-key", "rpm-key-sha256", "now"):
        parser.add_argument("--" + field, required=True)
    for field in ("stable", "claim", "result-snapshot", "reason"):
        parser.add_argument("--" + field)
    parser.add_argument("--mode", choices=("normal", "fast-track"), default="normal")
    args = parser.parse_args()
    result = prepare(args.beta, args.stable, _json_file(pathlib.Path(args.registry)), args.group, args.output,
                     publications=args.publications, snapshots=args.snapshots,
                     collection=_json_file(pathlib.Path(args.collection)), metadata_key=args.metadata_key,
                     metadata_key_sha256=args.metadata_key_sha256, rpm_key=args.rpm_key,
                     rpm_key_sha256=args.rpm_key_sha256, now=args.now, mode=args.mode, reason=args.reason,
                     claim=None if args.claim is None else _json_file(pathlib.Path(args.claim)),
                     result_snapshot=args.result_snapshot)
    print(json.dumps({"proposal_sha256": result["proposal_sha256"], "publishable": False}))


if __name__ == "__main__":
    main()
