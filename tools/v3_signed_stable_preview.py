"""Generate a *TEST-ONLY*, locally GPG-signed V3 stable snapshot preview.

An immutable staged repository tree, never a release: it has no production
snapshot-build evidence, authenticated policy, full-set DNF closure, protected
approval, or remote publication. Never connect to live beta/stable channels.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

from v3_promotion_planner import PlanningError
from v3_rpm_preflight import verify as verify_rpms
from ro_repo import (
    _sign_file_exact, require_secret_signing_subkey,
    validate_role_public_key, validate_schema, verify_snapshot,
    timestamp, digest,
)

SNAP = re.compile(r"^repo-f44-[0-9]{8}-[0-9]{3}$")
SHA = re.compile(r"^[0-9a-f]{64}$")
FPR = re.compile(r"^[A-F0-9]{40}$")


def _load(path):
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file():
        raise PlanningError("unsafe/missing V3 plan")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PlanningError("invalid V3 plan JSON") from exc


def _pinned_key(path, expected, label):
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file() or not isinstance(expected, str) or not SHA.fullmatch(expected):
        raise PlanningError("missing or unpinned " + label)
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise PlanningError("wrong " + label + " SHA256")
    return path


def _rpm_role(public_key, expected_fpr):
    """Check caller-pinned exact RPM signing subkey is in the provided key."""
    if not isinstance(expected_fpr, str) or not FPR.fullmatch(expected_fpr):
        raise PlanningError("invalid RPM signing key fingerprint")
    try:
        r = subprocess.run(
            ["gpg", "--batch", "--with-colons", "--show-keys", str(public_key)],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PlanningError("GPG public key inspection failed") from exc
    if r.returncode != 0:
        raise PlanningError("GPG public key inspection failed")
    fingerprints = [line.split(":")[9].upper() for line in r.stdout.splitlines()
                    if line.startswith("fpr:")]
    if expected_fpr not in fingerprints:
        raise PlanningError("RPM signing key fingerprint mismatch")


def create_preview(composition_dir, output_dir, snapshot_id, *,
                   gnupghome, metadata_signing_key, rpm_signing_key,
                   rpm_public_key, rpm_key_sha256,
                   metadata_public_key, metadata_key_sha256,
                   passphrase_file, workflow_run):
    if not isinstance(snapshot_id, str) or not SNAP.fullmatch(snapshot_id):
        raise PlanningError("invalid immutable stable snapshot identifier")
    if not isinstance(workflow_run, str) or not re.fullmatch(r"[1-9][0-9]*", workflow_run):
        raise PlanningError("test workflow run must be a positive numeric ID")
    source = pathlib.Path(composition_dir)
    output = pathlib.Path(output_dir)
    home = pathlib.Path(gnupghome)
    password = pathlib.Path(passphrase_file)
    if (source.is_symlink() or not source.is_dir() or output.is_symlink()
            or output.exists() or not home.is_dir()
            or password.is_symlink() or not password.is_file()):
        raise PlanningError("unsafe source, output, signing home or passphrase")
    if output.resolve() == source.resolve() or source.resolve() in output.resolve().parents:
        raise PlanningError("preview output must not be inside candidate")
    rpm_key = _pinned_key(rpm_public_key, rpm_key_sha256, "RPM public key")
    meta_key = _pinned_key(metadata_public_key, metadata_key_sha256, "metadata public key")
    if not isinstance(metadata_signing_key, str) or not FPR.fullmatch(metadata_signing_key):
        raise PlanningError("invalid metadata signing key fingerprint")
    meta_fpr = require_secret_signing_subkey(home, metadata_signing_key, require_isolated=False)
    if meta_fpr != metadata_signing_key:
        raise PlanningError("wrong metadata signing subkey")
    validate_role_public_key(meta_key, meta_fpr, home)
    _rpm_role(rpm_key, rpm_signing_key)

    # Actual RPM6 signed-byte/header/SRPM checks; NO test stubs here.
    preflight = verify_rpms(source, rpm_key, rpm_key_sha256)
    plan = _load(source / "promotion-plan-v3.json")
    if (plan.get("publishable") is not False or
            plan.get("candidate_sha256") != preflight["candidate_sha256"]):
        raise PlanningError("invalid/offline V3 candidate")
    expected = plan.get("resulting_stable_packages")
    if not isinstance(expected, list) or not expected:
        raise PlanningError("missing stable package set")

    output.parent.mkdir(parents=True, exist_ok=True)
    temp = pathlib.Path(tempfile.mkdtemp(prefix=".v3-test-stable-", dir=output.parent))
    try:
        stage_root = temp / "preview"
        snapshot = stage_root / "snapshots" / "fedora" / "44" / snapshot_id
        repos = {a: snapshot / "rpm" / a for a in ("x86_64", "aarch64", "source")}
        for arch, folder in repos.items():
            folder.mkdir(parents=True)
            source_dir = source / "rpm" / arch
            if source_dir.is_symlink():
                raise PlanningError("symlinked RPM source directory")
            if source_dir.exists():
                for original in sorted(source_dir.glob("*.rpm")):
                    if original.is_symlink() or not original.is_file():
                        raise PlanningError("unsafe RPM source file")
                    target = folder / original.name
                    shutil.copyfile(original, target)
                    if digest(target) != digest(original):
                        raise PlanningError("RPM bytes changed during snapshot staging")
            subprocess.run(["createrepo_c", "--unique-md-filenames", str(folder)],
                           check=True, capture_output=True, text=True)
            _sign_file_exact(folder / "repodata" / "repomd.xml", home, meta_fpr, password)

        keys = snapshot / "keys"
        keys.mkdir()
        shutil.copyfile(rpm_key, keys / "RPM-GPG-KEY-ro-asd-TEST-ONLY")
        shutil.copyfile(meta_key, keys / "REPODATA-GPG-KEY-ro-asd-TEST-ONLY")
        repodata = {}
        for arch, folder in repos.items():
            repomd = folder / "repodata" / "repomd.xml"
            repodata[arch] = {
                "repomd_sha256": digest(repomd),
                "repomd_signature_sha256": digest(str(repomd) + ".asc"),
            }
        manifest = {
            "schema_version": 1,
            "snapshot_id": snapshot_id,
            "created_at": timestamp(),
            "fedora_release": 44,
            "parent_snapshot": plan.get("stable_base_snapshot_id"),
            "packages": sorted(expected, key=lambda e: (e["filename"], e["architecture"])),
            "repositories": repodata,
            "rpm_signing_fingerprint": rpm_signing_key,
            "metadata_signing_fingerprint": meta_fpr,
            "creation_provenance": {"tool": "ro-repo-v2", "run": workflow_run},
        }
        validate_schema(manifest, "repository-snapshot-v1")
        manifest_file = snapshot / "repository-snapshot-v1.json"
        manifest_file.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        _sign_file_exact(manifest_file, home, meta_fpr, password)

        verified = verify_snapshot(snapshot, home)
        if verified != manifest:
            raise PlanningError("signed stable preview verification mismatch")
        # Publication workflow requires signed snapshot-build-evidence-v1.json;
        # a V3 test preview intentionally NEVER creates it.
        if (snapshot / "snapshot-build-evidence-v1.json").exists():
            raise PlanningError("test preview unexpectedly contains release evidence")
        receipt = {
            "schema_version": 1,
            "scope": "v3-test-only-signed-stable-preview",
            "snapshot_id": snapshot_id,
            "promotion_group": plan["promotion_group"],
            "candidate_sha256": plan["candidate_sha256"],
            "previous_stable_snapshot_id": plan.get("stable_base_snapshot_id"),
            "snapshot_manifest_sha256": digest(manifest_file),
            "verified_rpm_files": len(preflight["checked_rpm_files"]),
            "signed_repodata_arches": sorted(repodata),
            "source_rpm_bytes_reused": True,
            "local_rpm_signature_verified": True,
            "local_repodata_signature_verified": True,
            "local_manifest_signature_verified": True,
            "full_set_dnf_dependencies_tested": False,
            "trusted_beta_provenance_verified": False,
            "protected_approval_verified": False,
            "publication_authorized": False,
            "publishable": False,
        }
        (stage_root / "v3-preview-NOT-FOR-PUBLICATION.json").write_text(
            json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        if output.exists() or output.is_symlink():
            raise PlanningError("preview output appeared concurrently")
        os.rename(stage_root, output)
        return receipt
    finally:
        shutil.rmtree(temp, ignore_errors=True)


def main():
    p = argparse.ArgumentParser(description="Test-only V3 signed stable snapshot, no publishing")
    for field in ("composition", "output", "snapshot-id", "gnupghome",
                  "metadata-signing-key", "rpm-signing-key", "rpm-public-key",
                  "rpm-key-sha256", "metadata-public-key", "metadata-key-sha256",
                  "passphrase-file", "workflow-run"):
        p.add_argument("--" + field, required=True)
    p.add_argument("--i-understand-this-is-test-only", action="store_true", required=True)
    args = p.parse_args()
    print(json.dumps(create_preview(args.composition, args.output, args.snapshot_id,
                                   gnupghome=args.gnupghome,
                                   metadata_signing_key=args.metadata_signing_key,
                                   rpm_signing_key=args.rpm_signing_key,
                                   rpm_public_key=args.rpm_public_key,
                                   rpm_key_sha256=args.rpm_key_sha256,
                                   metadata_public_key=args.metadata_public_key,
                                   metadata_key_sha256=args.metadata_key_sha256,
                                   passphrase_file=args.passphrase_file,
                                   workflow_run=args.workflow_run),
                     sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
