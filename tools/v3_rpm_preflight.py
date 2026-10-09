"""Real local RPM byte, header and signature checks for a V3 staged candidate.

This is not an authorization gate: signed snapshots, beta provenance, DNF
transactions, protected CI identity and publication approval are separate.
The caller MUST pin the trusted signing public key hash out of band.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile

from v3_promotion_planner import PlanningError, _parse

HEX = re.compile(r"^[0-9a-f]{64}$")


def _digest(path):
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _load(root, filename):
    path = root / filename
    if path.is_symlink() or not path.is_file():
        raise PlanningError("missing or unsafe composition metadata")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PlanningError("invalid composition metadata") from exc


def _run(args):
    try:
        result = subprocess.run(args, check=False, text=True, capture_output=True, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PlanningError("RPM verification command unavailable or timed out") from exc
    if result.returncode != 0:
        raise PlanningError("RPM command failed: " + str(args[0]) + ": " + result.stderr[-300:])
    return result.stdout + result.stderr


def _manifest_inventory(plan):
    if not isinstance(plan, dict) or plan.get("publishable") is not False or not isinstance(plan.get("resulting_stable_packages"), list):
        raise PlanningError("invalid or publishable V3 plan")
    expected = {}
    sources = set()
    for p in plan["resulting_stable_packages"]:
        name, epoch, version, release, arch = _parse(p)
        filename = f"{name}-{version}-{release}.{arch}.rpm"
        if p["filename"] != filename:
            raise PlanningError("package filename disagrees with NEVRA")
        if arch in {"src", "nosrc"}:
            folders = ("source",)
            sources.add(filename)
        elif arch == "noarch":
            folders = ("x86_64", "aarch64")
        else:
            folders = (arch,)
        for folder in folders:
            path = "rpm/" + folder + "/" + filename
            if path in expected:
                raise PlanningError("duplicate staged RPM")
            expected[path] = (p, (name, epoch, version, release, arch))
    if not expected or not sources:
        raise PlanningError("missing binary or source RPM inventory")
    return expected, sources


def verify(bundle_root, trusted_key_path, expected_key_sha256):
    """Read local bytes, inspect actual RPM headers and verify real GPG signatures.

    It is intentionally impossible to convert this return value directly into
    the V3 group test claim, which requires actual DNF/Plasma/QEMU evidence.
    """
    root = pathlib.Path(bundle_root)
    key = pathlib.Path(trusted_key_path)
    if root.is_symlink() or not root.is_dir() or key.is_symlink() or not key.is_file():
        raise PlanningError("unsafe candidate directory or trusted key")
    if not isinstance(expected_key_sha256, str) or not HEX.fullmatch(expected_key_sha256):
        raise PlanningError("trusted key digest must be explicitly pinned")
    if _digest(key) != expected_key_sha256:
        raise PlanningError("trusted RPM public key hash mismatch")
    plan = _load(root, "promotion-plan-v3.json")
    composition = _load(root, "composition-v3.json")
    if not isinstance(composition, dict) or composition.get("scope") != "offline-v3-untrusted-composition" or composition.get("publishable") is not False:
        raise PlanningError("unexpected composition contract")
    if composition.get("candidate_sha256") != plan.get("candidate_sha256") or composition.get("promotion_group") != plan.get("promotion_group"):
        raise PlanningError("composition and plan refer to different candidate")
    expected, sources = _manifest_inventory(plan)
    inv = composition.get("files")
    if not isinstance(inv, list) or len(inv) != len(expected):
        raise PlanningError("composition inventory incomplete")
    indexed = {}
    for item in inv:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"} or not isinstance(item["path"], str) or not isinstance(item["sha256"], str):
            raise PlanningError("invalid composition inventory entry")
        if item["path"] in indexed or item["path"] not in expected:
            raise PlanningError("unexpected/duplicate composition file")
        indexed[item["path"]] = item["sha256"]
    if set(indexed) != set(expected):
        raise PlanningError("composition inventory does not cover package set")

    # Reject extra RPMs; do not allow hidden packages to become repodata entries.
    observed = {p.relative_to(root).as_posix() for p in root.rglob("*.rpm")}
    if observed != set(expected):
        raise PlanningError("unexpected/missing RPMs on disk")

    checked = []
    with tempfile.TemporaryDirectory(prefix="v3-rpmdb-") as temp:
        _run(["rpmkeys", "--dbpath", temp, "--import", str(key.resolve())])
        for rel in sorted(expected):
            p, fields = expected[rel]
            file = root / rel
            if (file.is_symlink() or any(a.is_symlink() for a in file.parents if a != root.parent and root in a.parents)
                    or not file.is_file() or not stat.S_ISREG(file.stat().st_mode)):
                raise PlanningError("unsafe RPM path: " + rel)
            actual = _digest(file)
            if actual != p["published_signed_artifact_sha256"] or actual != indexed[rel]:
                raise PlanningError("signed RPM bytes differ from plan or composition")
            signature_output = _run(["rpmkeys", "--dbpath", temp, "--checksig", str(file)])
            if (not re.search(r"signature", signature_output, re.I)
                    or not re.search(r"\bOK\b", signature_output)
                    or re.search(r"NOT OK|NOKEY|unsigned", signature_output, re.I)):
                raise PlanningError("RPM signature missing or not trusted")
            output = _run(["rpm", "-qp", "--qf",
                           "%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SOURCEPACKAGE}\\t%{SOURCERPM}\\n",
                           str(file)]).strip().split("\t")
            if len(output) != 7:
                raise PlanningError("RPM metadata header is malformed")
            name, epoch, version, release, arch = fields
            reported_arch = "src" if output[5] == "1" else output[4]
            if (output[:4] != [name, epoch, version, release]
                    or reported_arch != arch or (arch in {"src", "nosrc"}) != (output[5] == "1")):
                raise PlanningError("actual RPM headers mismatch snapshot manifest")
            if arch not in {"src", "nosrc"} and output[6] not in sources:
                raise PlanningError("binary RPM is not linked to selected source RPM: reported " + repr(output[6]) + ", expected " + repr(sorted(sources)))
            checked.append({"path": rel, "signed_rpm_sha256": actual, "header_nevra": p["nevra"]})
    return {
        "scope": "v3-local-rpm-preflight-only",
        "promotion_group": plan["promotion_group"],
        "candidate_sha256": plan["candidate_sha256"],
        "checked_rpm_files": checked,
        "trusted_key_sha256": expected_key_sha256,
        "local_header_checks_passed": True,
        "local_rpm_signature_checks_passed": True,
        "verified_beta_provenance": False,
        "dnf_tests_executed": False,
        "plasma_tests_executed": False,
        "qemu_tests_executed": False,
        "publisher_authorized": False,
        "publishable": False,
    }


def main():
    parser = argparse.ArgumentParser(description="Actual RPM preflight, not stable approval")
    parser.add_argument("--candidate-dir", required=True)
    parser.add_argument("--rpm-public-key", required=True)
    parser.add_argument("--expected-key-sha256", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = verify(args.candidate_dir, args.rpm_public_key, args.expected_key_sha256)
    out = pathlib.Path(args.output)
    if out.exists() or out.is_symlink():
        raise PlanningError("immutable preflight evidence already exists")
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".v3-preflight-", dir=out.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(result, f, sort_keys=True, indent=2)
            f.write("\n")
        os.rename(temp, out)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    print(json.dumps({"result": "pass", "preflight": str(out), "publishable": False}))


if __name__ == "__main__":
    main()
