"""Deterministic unsigned result and local RPM transaction closure; no DNF client."""
import pathlib
import shutil
import tempfile
import uuid

from psop_context import Evidence, SEAL, require_evidence, frozen_tree
from v3_repository_metadata import generate
from v3_policy_profile import sha, canonical
from v3_full_set_dnf import _run
from v3_promotion_planner import PlanningError


class UnsignedResult(Evidence):
    def check(self):
        super().check()
        self.prepared.check()
        if frozen_tree(self.path) != self.data["inventory"]:
            raise PlanningError("result inventory changed")


def build_metadata(composition, deterministic_parameters, *, context):
    p = require_evidence(composition, context)
    if set(deterministic_parameters) != {"source_date_epoch"}:
        raise PlanningError("unknown deterministic metadata parameter")
    root = context.path("result-" + uuid.uuid4().hex)
    root.mkdir()
    closure = {}
    for arch in ("x86_64", "aarch64", "source"):
        repo = root / "rpm" / arch
        source = composition.composition / "rpm" / arch
        if source.exists():
            shutil.copytree(source, repo)
        else:
            repo.mkdir(parents=True)
        # Actual RPM transaction dependency/file conflict checking of the full
        # resulting set, without installing anything or executing scriptlets.
        # Cross-arch headers were checked by V3 preflight; this is NOT a native
        # aarch64 DNF acceptance or a general Fedora upstream solver.
        rpms = sorted(repo.glob("*.rpm"))
        if arch != "source" and rpms:
            with tempfile.TemporaryDirectory(prefix="psop-closure-rpmdb-") as db:
                _run(["rpm", "--dbpath", db, "--initdb"])
                _run(["rpmkeys", "--dbpath", db, "--import", str(composition.inputs.paths["rpm_key"])])
                _run(["rpm", "--dbpath", db, "--test", "--upgrade", "--ignorearch", "--noscripts",
                      *map(str, rpms)])
            closure[arch] = "PASS_LOCAL_RPM_TEST"
        generate(repo, deterministic_parameters["source_date_epoch"])
    manifest = {"domain": "psop-result-test-1", "plan_sha256": sha(p["plan"]),
        "source_sha256": composition.inputs.sha256, "policy_sha256": sha(p["policy"]),
        "packages": p["plan"]["resulting_stable_packages"], "parameters": deterministic_parameters,
        "rpm_signing_fingerprint": composition.inputs.data["roots"]["rpm"]["fingerprint"],
        "previous_stable_sha256": composition.inputs.data["previous_stable_sha256"], "publishable": False}
    (root / "psop-result-v1.json").write_bytes(canonical(manifest))
    result = UnsignedResult({"context": context.pin, "prepared_sha256": composition.sha256,
        "inventory": frozen_tree(root), "closure": closure, "dnf5_client_acceptance": "UNVERIFIED",
        "publishable": False}, SEAL)
    result.path, result.prepared = root, composition
    return result


def verify_result(result, *, context):
    require_evidence(result, context)
    return sha(result.data["inventory"])


def review_bundle(result, *, context):
    from ro_repo import validate_schema
    verify_result(result, context=context)
    p, i = result.prepared.data, result.prepared.inputs.data
    body = {"schema_version": 1, "domain": "psop-review-test-1", "context": context.pin,
        "profile": "psop-pages-stable", "source_pins": i["pins"], "inputs_sha256": p["inputs_sha256"],
        "history_sha256": p["history_sha256"], "genesis_sha256": p["genesis_sha256"],
        "previous_stable_sha256": i["previous_stable_sha256"], "policy_version": p["policy"]["version"],
        "policy_sha256": sha(p["policy"]), "plan_sha256": sha(p["plan"]),
        "evidence_sha256": p["evidence_sha256"], "result_sha256": sha(result.data["inventory"]),
        "publishable": False}
    validate_schema(body, "psop-review-v1")
    return Evidence(body, SEAL)
