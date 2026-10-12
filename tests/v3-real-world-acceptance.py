"""Offline released-RPM acceptance using the existing V3 composition/DNF tools.

Requires previously captured Pages and exact Fedora caches. Only metadata is
signed with a fresh disposable TEST ONLY key; released RPMs are never re-signed.
There is no production authorization, publication or migration.
"""
import datetime as dt
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import os
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from ro_repo import export_role_public_key
from v3_backend_trust import TestSigner, test_workspace, verify_envelope
from v3_full_set_dnf import _signed_view, _rpm_set_preflight, validate
from v3_integration import tree_inventory
from v3_pinned_upstream import verify_upstream
from v3_policy_profile import sha, canonical
from v3_promotion_planner import PlanningError
from v3_promotion_planner import plan as canonical_plan
from v3_policy_profile import require_complete
from v3_rpm_preflight import verify as verify_rpms
from v3_signed_beta_history import _keyring, _signature, signed_archive_bundle
from v3_signed_stable_preview import create_preview
from v3_stable_composer import compose
from v3_repository_metadata import generate


def digest(file):
    return hashlib.sha256(pathlib.Path(file).read_bytes()).hexdigest()


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=180, **kwargs).stdout


def execute(pages, upstream_root, output, tree):
    if {p.name for p in pathlib.Path("/sys/class/net").iterdir()} != {"lo"}:
        raise PlanningError("real transaction acceptance requires a loopback-only network namespace")
    pages, upstream_root, output = map(pathlib.Path, (pages, upstream_root, output))
    if output.exists():
        raise PlanningError("immutable real acceptance output exists")
    output.mkdir()
    repository = pathlib.Path(__file__).parents[1]
    source_inventory = [{"path": p.relative_to(repository).as_posix(), "sha256": digest(p)}
                        for f in ("tools", "tests", "schemas", "config") for p in sorted((repository / f).glob("*"))
                        if p.is_file() and p.suffix in {".py", ".sh", ".json"}]
    tracked = json.loads(pathlib.Path(tree).read_bytes())
    blobs = [p for p in tracked["tree"] if p["type"] == "blob"]
    for item in blobs:
        file = pages / item["path"]
        raw = file.read_bytes()
        if file.is_symlink() or len(raw) != item["size"] or hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != item["sha"]:
            raise PlanningError("captured Pages differs from exact Git blob")
    registry = json.loads((repository / "config/producers-v2.json").read_bytes())
    rpm_key = repository / "keys/production/ro-asd-rpm-signing-public.asc"
    production_metadata = repository / "keys/production/ro-asd-metadata-signing-public.asc"
    snapshots = pages / "snapshots/fedora/44"
    originals = [snapshots / name for name in ("repo-f44-20260920-001", "repo-f44-20260921-001", "repo-f44-20261009-001")]
    observed_trees = {p.name: sha(tree_inventory(p)) for p in snapshots.glob("repo-*")}
    result = {"scope": "v3-released-package-acceptance-test-only", "publishable": False,
              "source_code_sha256": sha(source_inventory), "source_inventory": source_inventory,
              "pages_commit": tracked["sha"], "git_blobs_checked": len(blobs), "snapshots": observed_trees,
              "rpm_key_sha256": digest(rpm_key), "production_metadata_key_sha256": digest(production_metadata),
              "native_architecture": "x86_64", "native_aarch64": "UNVERIFIED", "vm": "UNVERIFIED",
              "production_activation": "BLOCKED", "cases": {}, "inventory": []}
    root = test_workspace()
    try:
        ring = _keyring(production_metadata, digest(production_metadata), root)
        for index, snapshot in enumerate(sorted(snapshots.glob("repo-*"))):
            manifest = _signed_view(snapshot, ring)
            preflight = _rpm_set_preflight(snapshot, manifest, rpm_key, digest(rpm_key), root / ("input-preflight-" + str(index)))
            result["inventory"].append({"snapshot_id": snapshot.name, "packages": manifest["packages"], "preflight_sha256": sha(preflight)})
        publications = []
        for publication in sorted((pages / "publications/fedora/44/beta").iterdir()):
            record = _signature(publication, "publication-v1.json", ring)
            publications.append(record)
        result["signed_publications"] = publications
        try:
            history = signed_archive_bundle(pages / "publications/fedora/44/beta", snapshots, registry,
                          "ro-assist", production_metadata, digest(production_metadata), dt.datetime.now(dt.timezone.utc).isoformat())
            result["history_contract"] = {"status": "PASS", "receipt_sha256": sha(history)}
        except PlanningError as exc:
            result["history_contract"] = {"status": "BLOCKED", "reason": str(exc)}
        result["stable_state"] = "ABSENT_IN_PINNED_GIT_TREE" if not any(p["path"].startswith(("rpm/fedora/44/stable/", "publications/fedora/44/stable/")) for p in blobs) else "UNVERIFIED"
        result["negative_results"] = {}
        import copy
        latest_manifest = json.loads((originals[2] / "repository-snapshot-v1.json").read_bytes())
        for name, group, remove in (("missing-assist-aarch64", "ro-assist", lambda p: p["nevra"].startswith("ro-assist-") and p["architecture"] == "aarch64"),
                                    ("missing-dolphin-libs", "ro-kde-dolphin", lambda p: p["nevra"].startswith("dolphin-libs-"))):
            broken = copy.deepcopy(latest_manifest)
            broken["packages"] = [p for p in broken["packages"] if not remove(p)]
            try:
                require_complete(canonical_plan(broken, None, registry, group), registry)
            except PlanningError as exc:
                result["negative_results"][name] = {"status": "PASS", "rejection": str(exc)}
            else:
                raise PlanningError("incomplete actual group unexpectedly accepted")
        unsigned = root / "unsigned-actual-source"
        compose(originals[2], None, registry, "ro-assist", unsigned)
        srpm = next((unsigned / "rpm/source").glob("ro-assist-*.rpm"))
        run(["rpmsign", "--delsign", str(srpm)])
        unsigned_plan = json.loads((unsigned / "promotion-plan-v3.json").read_bytes())
        unsigned_inventory = json.loads((unsigned / "composition-v3.json").read_bytes())
        for packages in (unsigned_plan["resulting_stable_packages"], unsigned_plan["selected_group_packages"]):
            for p in packages:
                if p["architecture"] == "src":
                    p["published_signed_artifact_sha256"] = digest(srpm)
        for p in unsigned_inventory["files"]:
            if p["path"] == srpm.relative_to(unsigned).as_posix():
                p["sha256"] = digest(srpm)
        (unsigned / "promotion-plan-v3.json").write_bytes(canonical(unsigned_plan))
        (unsigned / "composition-v3.json").write_bytes(canonical(unsigned_inventory))
        try:
            verify_rpms(unsigned, rpm_key, digest(rpm_key))
        except PlanningError as exc:
            if "signature" not in str(exc):
                raise PlanningError("unsigned actual source rejected for unrelated reason: " + str(exc)) from exc
            result["negative_results"]["unsigned-actual-srpm"] = {"status": "PASS", "rejection": str(exc)}
        else:
            raise PlanningError("unsigned actual source unexpectedly accepted")
        cache = json.loads((upstream_root / "acquisition.json").read_bytes())
        fedora_key = root / "fedora44-public.asc"
        fedora_key.write_bytes(pathlib.Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-primary").read_bytes())
        fingerprints = run(["gpg", "--with-colons", "--show-keys", str(fedora_key)])
        if "36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6" not in fingerprints:
            raise PlanningError("official Fedora44 public fingerprint mismatch")
        (output / "fedora44-public.asc").write_bytes(fedora_key.read_bytes())
        pin_signer = TestSigner(root, "upstream-observation")
        upstream = []
        for name, receipt in cache["feeds"].items():
            manifest = {"schema_version": 3, "scope": "v3-pinned-fedora-upstream", "fedora_release": 44,
                    "architecture": "x86_64", "repo_id": "pinned-fedora-" + name,
                    "tree_sha256": sha(tree_inventory(upstream_root / name)), "repomd_sha256": receipt["repomd_sha256"],
                    "metadata_authentication": "signed-pin", "rpm_key_sha256": digest(fedora_key), "packages": receipt["packages"]}
            tick = int(time.time())
            envelope = pin_signer.envelope("upstream-pin", {"manifest": manifest, "issued_at": tick, "expires_at": tick + 3600})
            attestation = verify_envelope(envelope, role="upstream-pin", public_key=pin_signer.public, key_sha256=pin_signer.key_sha256,
                                         expected={"manifest": manifest}, now=tick)
            upstream.append(verify_upstream(upstream_root / name, manifest, attestation,
                             rpm_key=fedora_key, rpm_key_sha256=digest(fedora_key), now=tick))
            (output / ("upstream-" + name + ".json")).write_bytes(canonical({"manifest": manifest,
                  "envelope": json.loads(envelope), "independent_production_attestor": "UNVERIFIED", "publishable": False}) + b"\n")
            print("Verified actual Fedora RPM cache:", name, len(manifest["packages"]), flush=True)
        (output / "upstream-observation-public.pem").write_bytes(pin_signer.public)
        home = root / "test-signing-gnupg"
        home.mkdir(mode=0o700)
        env = dict(os.environ, GNUPGHOME=str(home))
        run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key",
             "REAL ACCEPTANCE TEST ONLY <test@invalid>", "rsa2048", "cert", "1d"], env=env)
        primary = next(line.split(":")[9] for line in run(["gpg", "--with-colons", "--list-keys"], env=env).splitlines() if line.startswith("fpr:"))
        run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", primary, "rsa2048", "sign", "1d"], env=env)
        metadata_fpr = [line.split(":")[9] for line in run(["gpg", "--with-colons", "--list-keys"], env=env).splitlines() if line.startswith("fpr:")][-1]
        metadata = root / "test-metadata.asc"
        metadata.write_text(export_role_public_key(home, metadata_fpr))
        combined = root / "pinned-metadata-ro-and-test.asc"
        combined.write_bytes(production_metadata.read_bytes() + b"\n" + metadata.read_bytes())
        (output / "test-metadata-public.asc").write_bytes(metadata.read_bytes())
        password = root / "empty-passphrase"
        password.write_bytes(b"")
        password.chmod(0o600)
        rpm_fpr = "38CB87F6FBD645309432A6E22E02DEE8828B769B"
        previews = {}
        cases = [("assist-bootstrap", originals[0], None, "ro-assist", "001"),
                 ("keyring-retained", originals[2], "assist-bootstrap", "ro-asd-keyring", "002"),
                 ("assist-upgrade", originals[2], "keyring-retained", "ro-assist", "003"),
                 ("dolphin-full-group", originals[2], "assist-upgrade", "ro-kde-dolphin", "004"),
                 ("installer-full-group", originals[2], "assist-upgrade", "ro-installer", "005"),
                 ("noarch-release", originals[2], "assist-upgrade", "ro-asd-release", "006"),
                 ("noarch-repos", originals[2], "noarch-release", "ro-asd-repos", "007"),
                 ("noarch-defaults", originals[2], "noarch-repos", "ro-asd-defaults", "008"),
                 ("noarch-branding", originals[2], "noarch-defaults", "ro-asd-branding", "009"),
                 ("noarch-desktop", originals[2], "noarch-branding", "ro-asd-desktop-standard", "010"),
                 ("noarch-kernel", originals[2], "noarch-desktop", "ro-asd-kernel-policy", "011")]
        for name, beta, previous, group, suffix in cases:
            baseline = None if previous is None else previews[previous]
            composition = root / (name + "-composition")
            composition_receipt = compose(beta, baseline, registry, group, composition)
            plan = json.loads((composition / "promotion-plan-v3.json").read_bytes())
            identifier = "repo-f44-20261012-" + suffix
            preview = root / (name + "-preview")
            create_preview(composition, preview, identifier, gnupghome=home, metadata_signing_key=metadata_fpr,
                    rpm_signing_key=rpm_fpr, rpm_public_key=rpm_key, rpm_key_sha256=digest(rpm_key),
                    metadata_public_key=metadata, metadata_key_sha256=digest(metadata), passphrase_file=password, workflow_run="1")
            snapshot = preview / "snapshots/fedora/44" / identifier
            previews[name] = snapshot
            record = {"promotion_group": group, "packages": plan["resulting_stable_packages"],
                      "plan_sha256": sha(plan), "result_tree_sha256": sha(tree_inventory(snapshot)),
                      "production_authorization": "BLOCKED", "composition_sha256": sha(composition_receipt)}
            # Observe a real installed binary while validate's installroot is
            # alive. The hook calls the actual RPMDB verifier first; neither
            # transaction results nor GUI observations are mocked into PASS.
            import v3_full_set_dnf
            original_rpmdb = v3_full_set_dnf._rpmdb
            observations = []
            def observed_rpmdb(installroot, targets):
                actual = original_rpmdb(installroot, targets)
                probes = {"assist-bootstrap": ("/usr/bin/ro-assist", "--help"),
                          "assist-upgrade": ("/usr/bin/ro-assist", "--help"),
                          "dolphin-full-group": ("/usr/bin/dolphin", "--version"),
                          "installer-full-group": ("/usr/bin/ro-installer", "--help")}
                if name in probes and installroot.name in {"clean", "upgrade"}:
                    (installroot / "tmp").mkdir(exist_ok=True)
                    environment = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "QT_QPA_PLATFORM": "offscreen", "LANG": "C.UTF-8"}
                    log = output / (name + "-cli-" + str(len(observations)) + ".log")
                    try:
                        with log.open("wb") as stream:
                            process = subprocess.run(["chroot", str(installroot), *probes[name]], env=environment,
                                                     stdout=stream, stderr=subprocess.STDOUT, timeout=8)
                        status = "PASS" if process.returncode == 0 else "UNVERIFIED"
                        outcome = {"status": status, "exit_code": process.returncode}
                    except subprocess.TimeoutExpired:
                        outcome = {"status": "UNVERIFIED", "reason": "CLI probe did not terminate within 8 seconds"}
                    observations.append({**outcome, "kind": "offscreen-cli-only", "gui_acceptance": "UNVERIFIED",
                                         "installed_ro_nevra": actual, "log_sha256": digest(log)})
                return actual
            try:
                with mock.patch.object(v3_full_set_dnf, "_rpmdb", side_effect=observed_rpmdb):
                    receipt = validate(snapshot, baseline, beta, plan, "x86_64", output / name,
                          rpm_key=rpm_key, rpm_key_sha256=digest(rpm_key), metadata_key=combined,
                          metadata_key_sha256=digest(combined), upstream=upstream,
                          config_paths=["/etc/xdg/autostart/ro-assist-autostart.desktop"] if name == "assist-upgrade" else [])
                record.update(status="PASS", dnf_receipt_sha256=sha(receipt))
            except PlanningError as exc:
                record.update(status="FAIL", reason=str(exc))
            record["cli_observations"] = observations
            result["cases"][name] = record
            (output / (name + "-observation.json")).write_bytes(canonical(record) + b"\n")
            print("Released RPM transaction:", name, record["status"], flush=True)
            if record["status"] == "FAIL":
                print(record["reason"], flush=True)
        # Byte and deterministic-metadata checks use actual released artifacts.
        for name in ("assist-bootstrap", "keyring-retained", "assist-upgrade"):
            snapshot = previews[name]
            for file in snapshot.rglob("*.rpm"):
                candidate = next(p for original in originals for p in original.rglob(file.name) if digest(p) == digest(file))
                if file.read_bytes() != candidate.read_bytes():
                    raise PlanningError("released RPM bytes changed")
        deterministic = []
        for index in (1, 2):
            folder = root / ("metadata-" + str(index))
            folder.mkdir()
            for p in (previews["assist-upgrade"] / "rpm/x86_64").glob("*.rpm"):
                shutil.copyfile(p, folder / p.name)
            generate(folder, 1791763200)
            deterministic.append(tree_inventory(folder / "repodata"))
        if deterministic[0] != deterministic[1]:
            raise PlanningError("actual RPM metadata is non-deterministic")
        result["deterministic_metadata"] = "PASS"
        result["retained_released_bytes"] = "PASS"
        if any(sha(tree_inventory(snapshots / name)) != expected for name, expected in observed_trees.items()):
            raise PlanningError("production input copy changed during acceptance")
        after_sources = [{"path": p.relative_to(repository).as_posix(), "sha256": digest(p)}
                         for f in ("tools", "tests", "schemas", "config") for p in sorted((repository / f).glob("*"))
                         if p.is_file() and p.suffix in {".py", ".sh", ".json"}]
        if after_sources != source_inventory:
            raise PlanningError("acceptance implementation changed during execution")
        (output / "acceptance.json").write_bytes(canonical(result) + b"\n")
        print("COMPLETE: actual RPM observations; production BLOCKED", flush=True)
    finally:
        shutil.rmtree(root)


if __name__ == "__main__":
    execute(*sys.argv[1:])
