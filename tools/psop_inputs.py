"""Freeze and verify exact signed local inputs using existing V3 verifiers."""
import pathlib
import shutil
import tempfile
import uuid
import datetime as dt

from psop_context import Evidence, SEAL, frozen_tree, require_evidence
from v3_backend_trust import digest
from v3_integration import _provenance
from v3_signed_beta_history import _keyring, _signature
from v3_promotion_planner import plan, PlanningError
from v3_policy_profile import sha, require_complete
from ro_repo import verify_snapshot, verify_signed_rpms, validate_schema


class VerifiedInputs(Evidence):
    def check(self):
        super().check()
        for name, inventory in self._data["trees"].items():
            if frozen_tree(self.paths[name]) != inventory:
                raise PlanningError("verified input bytes changed")
        for role, root in self.data["roots"].items():
            if digest(self.paths[role + "_key"].read_bytes()) != root["sha256"]:
                raise PlanningError("frozen public root changed")


class PublishedStable(Evidence):
    """Verified committed PSOP bytes + an explicitly unsigned composer projection."""
    def check(self):
        super().check()
        self.store.verify_target(self.prepared, historical=True)
        if frozen_tree(self.path) != self.data["projection_inventory"]:
            raise PlanningError("derived Stable input changed")


def committed_stable(gateway, attempt):
    """Read current signed PSOP Stable back from Git after restart, without keys."""
    state = gateway.ledger.inspect(attempt)
    record = state["attempt"]
    p, a = record["prepared"], record["approval"]
    if (record["state"] != "COMPLETE" or state["head"]["digest"] != p["result_sha256"]
            or a["payload"]["writer"] not in {"psop-stable", "v2-stable"}):
        raise PlanningError("only current completed PSOP Stable may seed the next plan")
    store, context = gateway._store, gateway.context
    store.verify_target(p, historical=True)
    def raw(path):
        return store._run(["cat-file", "blob", p["target_files"][path]])
    prefix = "psop/snapshots/" + p["result_sha256"] + "/"
    publication = raw("psop/publications/" + attempt + ".json")
    from v3_backend_trust import strict_json
    envelope = strict_json(publication)
    payload = envelope["payload"]
    fields = {"context", "writer", "result_sha256", "signed_inventory", "approval_sha256", "review",
              "metadata_key", "production_activation", "publishable", "issued_at", "expires_at"}
    if (set(payload) != fields or payload["context"] != context.pin
            or payload["result_sha256"] != p["result_sha256"] or payload["review"] != a["payload"]["review"]
            or payload["writer"] != a["payload"]["writer"] or payload["metadata_key"] != a["payload"]["metadata_key"]
            or payload["production_activation"] != "BLOCKED" or payload["publishable"] is not False):
        raise PlanningError("closed committed PSOP publication contract mismatch")
    expected = {k: v for k, v in payload.items() if k not in {"issued_at", "expires_at"}}
    context.verify(publication, "publication", expected, now=payload["issued_at"])
    if digest(publication) != p["publication_sha256"] or payload["approval_sha256"] != p["approval_sha256"]:
        raise PlanningError("committed publication binding mismatch")
    key = raw(prefix + "test-metadata-public.asc")
    if digest(key) != a["payload"]["metadata_key"]["sha256"]:
        raise PlanningError("published metadata trust pin mismatch")
    parent = context.path("stable-input-" + uuid.uuid4().hex);parent.mkdir()
    frozen = parent / "signed";frozen.mkdir()
    for item in payload["signed_inventory"]:
        if set(item) != {"path", "sha256"}:
            raise PlanningError("unknown signed inventory fields")
        rel = pathlib.PurePosixPath(item["path"])
        if rel.is_absolute() or ".." in rel.parts or rel.as_posix() != item["path"] or "\\" in item["path"]:
            raise PlanningError("unsafe signed Stable member")
        dest = frozen / item["path"];dest.parent.mkdir(parents=True, exist_ok=True)
        data = raw(prefix + item["path"])
        if digest(data) != item["sha256"]:
            raise PlanningError("published signed inventory mismatch")
        dest.write_bytes(data)
    # Verify actual detached metadata signatures using the approval-pinned key.
    with tempfile.TemporaryDirectory(prefix="psop-prior-gpg-") as home:
        keypath = pathlib.Path(home) / "pinned.asc";keypath.write_bytes(key)
        ring = _keyring(keypath, digest(key), home)
        manifest = _signature(frozen, "psop-result-v1.json", ring)
        if (set(manifest) != {"domain", "plan_sha256", "source_sha256", "policy_sha256", "packages",
                "parameters", "previous_stable_sha256", "publishable", "rpm_signing_fingerprint"}
                or manifest["domain"] != "psop-result-test-1" or manifest["publishable"] is not False):
            raise PlanningError("closed PSOP result contract mismatch")
        from v3_signed_beta_history import _verify
        for arch in ("x86_64", "aarch64", "source"):
            path = frozen / "rpm" / arch / "repodata/repomd.xml"
            _verify(["gpgv", "--keyring", str(ring), str(path) + ".asc", str(path)])
    unsigned = [x for x in payload["signed_inventory"] if not x["path"].endswith(".asc")]
    signature_paths = {x["path"] for x in payload["signed_inventory"] if x["path"].endswith(".asc")}
    if signature_paths != {"test-metadata-public.asc", "psop-result-v1.json.asc",
                          *("rpm/" + arch + "/repodata/repomd.xml.asc" for arch in ("x86_64", "aarch64", "source"))}:
        raise PlanningError("unexpected metadata signature paths")
    if sha(unsigned) != p["result_sha256"]:
        raise PlanningError("signed Stable does not preserve approved unsigned result")
    epoch = manifest["parameters"]["source_date_epoch"]
    identifier = "repo-f44-" + dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y%m%d") + "-" + str(int(p["result_sha256"][:8], 16) % 1000).zfill(3)
    projection = parent / identifier;projection.mkdir()
    shutil.copytree(frozen / "rpm", projection / "rpm")
    derived = {"schema_version": 1, "snapshot_id": identifier, "created_at": dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fedora_release": 44, "parent_snapshot": None, "packages": manifest["packages"],
        "rpm_signing_fingerprint": manifest["rpm_signing_fingerprint"],
        "metadata_signing_fingerprint": a["payload"]["metadata_key"]["fingerprint"],
        "creation_provenance": {"tool": "ro-repo-v2", "run": "1"},
        "repositories": {arch: {"repomd_sha256": digest((projection / "rpm" / arch / "repodata/repomd.xml").read_bytes()),
            "repomd_signature_sha256": digest((projection / "rpm" / arch / "repodata/repomd.xml.asc").read_bytes())}
            for arch in ("x86_64", "aarch64", "source")}}
    from v3_policy_profile import canonical
    (projection / "repository-snapshot-v1.json").write_bytes(canonical(derived))
    # No V2 manifest signature/build evidence: this internal projection cannot
    # enter a V2 publisher, and never rewrites the original signed PSOP files.
    value = PublishedStable({"context": context.pin, "result_sha256": p["result_sha256"],
        "manifest": derived, "projection_inventory": frozen_tree(projection), "publishable": False}, SEAL)
    value.path, value.store, value.prepared = projection, store, p
    value.check()
    return value


def source_request(pins, registry, beta_manifest, stable_manifest, roots, build_evidence):
    return {"pins": pins, "registry_sha256": sha(registry), "beta_manifest_sha256": sha(beta_manifest),
            "previous_stable_sha256": None if stable_manifest is None else sha(stable_manifest),
            "build_evidence_sha256": sha(build_evidence),
            "public_roots": roots, "scope": "synthetic-test-source-provenance"}


def acquire(pins, public_roots, archive, *, beta, stable, registry, group, source_evidence, context, now):
    import re
    archive = require_evidence(archive, context)
    if archive["registry_sha256"] != sha(registry) or archive["group"] != group:
        raise PlanningError("archive registry/group mismatch")
    if (set(pins) != {"main_sha", "pages_sha"} or
            any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{40}", v) for v in pins.values())):
        raise PlanningError("exact source SHA pins required")
    if set(public_roots) != {"rpm", "metadata"}:
        raise PlanningError("separate public signing roots required")
    previous = stable if isinstance(stable, PublishedStable) else None
    if previous is not None:
        require_evidence(previous, context)
    paths = {"beta": pathlib.Path(beta)}
    if stable is not None:
        paths["stable"] = previous.path if previous is not None else pathlib.Path(stable)
    original = {n: frozen_tree(p) for n, p in paths.items()}
    workspace = context.path("inputs-" + uuid.uuid4().hex)
    workspace.mkdir()
    for name, path in list(paths.items()):
        target = workspace / name / path.name
        target.parent.mkdir()
        shutil.copytree(path, target)
        if frozen_tree(target) != original[name]:
            raise PlanningError("source changed during freezing")
        paths[name] = target
    roots = {}
    for role, value in public_roots.items():
        if set(value) != {"path", "sha256", "fingerprint"}:
            raise PlanningError("invalid public root contract")
        path = pathlib.Path(value["path"])
        if path.is_symlink() or digest(path.read_bytes()) != value["sha256"]:
            raise PlanningError("public key hash mismatch")
        target = workspace / (role + ".asc")
        target.write_bytes(path.read_bytes())
        roots[role] = {"sha256": value["sha256"], "fingerprint": value["fingerprint"]}
        paths[role + "_key"] = target
    if roots["rpm"]["fingerprint"] == roots["metadata"]["fingerprint"] or roots["rpm"]["sha256"] == roots["metadata"]["sha256"]:
        raise PlanningError("RPM and metadata signing roles must be separate")
    with tempfile.TemporaryDirectory(prefix="psop-input-gpg-") as home:
        ring = _keyring(paths["metadata_key"], roots["metadata"]["sha256"], home)
        import subprocess
        subprocess.run(["gpg", "--no-options", "--homedir", str(pathlib.Path(home) / "gnupg"),
                        "--batch", "--import", str(paths["metadata_key"])], check=True, capture_output=True)
        manifests = {}
        for name in ("beta", "stable"):
            if name not in paths:
                continue
            manifest = previous.data["manifest"] if name == "stable" and previous is not None else _signature(paths[name], "repository-snapshot-v1.json", ring)
            validate_schema(manifest, "repository-snapshot-v1")
            check_roles = ("rpm",) if name == "stable" and previous is not None else roots
            if any(manifest[r + "_signing_fingerprint"] != roots[r]["fingerprint"] for r in check_roles):
                raise PlanningError("snapshot signing role mismatch")
            manifests[name] = manifest
            if not (name == "stable" and previous is not None):
                verify_snapshot(paths[name], pathlib.Path(home) / "gnupg")
            verify_signed_rpms(sorted((paths[name] / "rpm").rglob("*.rpm")), paths["rpm_key"])
        p = plan(manifests["beta"], manifests.get("stable"), registry, group)
        if not any(row["snapshot_id"] == manifests["beta"]["snapshot_id"] for row in archive["signed_records"]):
            raise PlanningError("exact Beta snapshot absent from verified publication history")
        policy = require_complete(p, registry)
        build = _signature(paths["beta"], "snapshot-build-evidence-v1.json", ring)
        if build["repository_snapshot_sha256"] != digest((paths["beta"] / "repository-snapshot-v1.json").read_bytes()):
            raise PlanningError("signed build manifest mismatch")
        provenance = _provenance(build, manifests["beta"], p["selected_group_packages"], policy)
    attestation = context.verify(source_evidence, "source",
        source_request(pins, registry, manifests["beta"], manifests.get("stable"), roots, build), now=now)
    data = {"context": context.pin, "pins": pins, "roots": roots, "registry_sha256": sha(registry),
            "group": group, "manifests": manifests, "provenance": provenance,
            "source_sha256": attestation.sha256, "archive_sha256": archive["archive_sha256"],
            "previous_stable_sha256": previous.data["result_sha256"] if previous is not None else None if stable is None else sha(original["stable"]),
            "trees": original, "publishable": False}
    result = VerifiedInputs(data, SEAL)
    result.paths = paths
    result.check()
    return result
