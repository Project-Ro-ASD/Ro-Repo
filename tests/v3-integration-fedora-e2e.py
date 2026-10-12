"""Real signed RPM + full-set DNF5 integration with synthetic Ro-Assist releases.

These are executable RPM fixtures, NOT tests of real Ro-Assist/Dolphin/Installer
applications. Signed API/history fixtures establish contract consistency only.
"""
import copy
import datetime as dt
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from ro_repo import sign_packages, export_role_public_key, _sign_file_exact
from v3_authorization import request
from v3_full_set_dnf import validate
from v3_integration import prepare, tree_inventory
from v3_policy_profile import sha, canonical
from v3_promotion_planner import plan, PlanningError, version_compare
from v3_signed_stable_preview import create_preview
from v3_stable_composer import compose


def run(argv, env=None):
    result = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=600)
    if result.returncode:
        raise RuntimeError(str(argv[:2]) + " failed:\n" + result.stdout[-2000:] + result.stderr[-3000:])
    return result.stdout


def fail_closed(function, contains=None):
    try:
        function()
    except PlanningError as exc:
        if contains is not None and contains not in str(exc):
            raise AssertionError("unexpected rejection reason: " + str(exc)) from exc
        return str(exc)
    raise AssertionError("security decision unexpectedly accepted unsafe input")


def main(output):
    output = pathlib.Path(output).resolve()
    if output.exists():
        raise RuntimeError("immutable evidence output exists")
    def source_inventory():
        return [{"path": path.relative_to(ROOT).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                for folder in ("tools", "tests", "schemas", "config") for path in sorted((ROOT / folder).glob("*"))
                if path.is_file() and path.suffix in {".py", ".sh", ".json"}]
    tested_sources = source_inventory()
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    utc = lambda value: value.isoformat().replace("+00:00", "Z")
    with tempfile.TemporaryDirectory(prefix="v3-fedora-integration-") as directory:
        work = pathlib.Path(directory)
        home = work / "gnupg"
        home.mkdir(mode=0o700)
        env = dict(os.environ, GNUPGHOME=str(home))
        run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
             "--quick-generate-key", "V3 INTEGRATION TEST ONLY <test@invalid>", "rsa2048", "cert", "1d"], env)
        primary = next(line.split(":")[9] for line in run(["gpg", "--with-colons", "--list-keys"], env).splitlines() if line.startswith("fpr:"))
        for _ in range(2):
            run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", primary, "rsa2048", "sign", "1d"], env)
        keys = [line.split(":")[9] for line in run(["gpg", "--with-colons", "--list-keys"], env).splitlines() if line.startswith("fpr:")]
        rpm_fpr, meta_fpr = keys[1:]
        rpm_key, meta_key = work / "rpm-public.asc", work / "metadata-public.asc"
        rpm_key.write_text(export_role_public_key(home, rpm_fpr))
        meta_key.write_text(export_role_public_key(home, meta_fpr))
        rpm_sha, meta_sha = (hashlib.sha256(p.read_bytes()).hexdigest() for p in (rpm_key, meta_key))
        password = work / "empty-test-passphrase"
        password.write_bytes(b"")
        password.chmod(0o600)
        top = work / "rpmbuild"
        for folder in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"):
            (top / folder).mkdir(parents=True)
        # Real RPM version comparison cross-check for the offline planner.
        for a, b in (("1.9", "1.10"), ("1~rc", "1"), ("1", "1^git"), ("1^git", "1.1"), ("1a", "1.1"), ("1.01", "1.1")):
            actual = int(run(["rpm", "--eval", '%{lua:print(rpm.vercmp("' + a + '","' + b + '"))}']).strip())
            assert actual == version_compare(a, b), (a, b, actual)
        signed = {}
        packages = {}
        registry = json.loads((ROOT / "config/producers-v2.json").read_bytes())
        # Scope the disposable fixture to this actual x86_64 runner. This is
        # not canonical aarch64 acceptance and cannot authorize a real release.
        for producer in registry["producers"]:
            for policy in producer["components"]:
                if policy["promotion_group"] in {"ro-assist", "ro-control"}:
                    policy["architectures"] = ["x86_64"]
        for name, version in (("ro-assist", "1.0"), ("ro-assist", "2.0"), ("ro-control", "1.0"),
                              ("ro-control", "2.0"), ("ro-control", "3.0"), ("ro-installer", "1.0"),
                              ("ro-v3-impossible-dependency", "1.0")):
            spec = top / "SPECS" / (name + "-" + version + ".spec")
            config = f"install -Dm0644 /dev/null %{{buildroot}}/etc/{name}.conf\nprintf 'version={version}\\n' > %{{buildroot}}/etc/{name}.conf"
            spec.write_text(f"""%global debug_package %{{nil}}
Name: {name}
Version: {version}
Release: 1.fc44
Summary: Disposable V3 integration fixture
License: MIT
BuildArch: x86_64
%description
Disposable repository integration fixture. No application code.
%prep
%build
%install
install -Dm0644 /dev/null %{{buildroot}}/usr/share/{name}/fixture
{config}
%files
/usr/share/{name}/fixture
%config(noreplace) /etc/{name}.conf
""")
            if name == "ro-control" and version == "2.0":
                spec.write_text(spec.read_text().replace("License: MIT", "License: MIT\nRequires: ro-v3-impossible-dependency"))
            if name == "ro-control" and version == "3.0":
                spec.write_text(spec.read_text().replace("/usr/share/ro-control/fixture", "/usr/share/ro-assist/fixture"))
            run(["rpmbuild", "-ba", "--define", "_topdir " + str(top), str(spec)])
            source = work / (name + "-" + version + "-unsigned")
            source.mkdir()
            for path in list((top / "RPMS/x86_64").glob(f"{name}-{version}-*.rpm")) + list((top / "SRPMS").glob(f"{name}-{version}-*.rpm")):
                shutil.copyfile(path, source / path.name)
            destination = work / (name + "-" + version + "-signed")
            sign_packages(source, destination, home, rpm_fpr)
            signed[name, version] = destination
            entries = []
            provenance_digest = sha({"fixture": name, "version": version})
            for path in sorted(destination.glob("*.rpm")):
                header = run(["rpm", "-qp", "--qf", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCEPACKAGE}", str(path)]).split("\t")
                n, epoch, v, release, arch, marker = header
                if marker == "1":
                    arch = "src"
                entries.append({"nevra": f"{n}-{epoch}:{v}-{release}.{arch}", "filename": path.name,
                                "architecture": arch, "producer_manifest_digest": provenance_digest,
                                "producer_artifact_sha256": hashlib.sha256((source / path.name).read_bytes()).hexdigest(),
                                "published_signed_artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
            packages[name, version] = entries
        snapshots = work / "snapshots"
        snapshots.mkdir()
        def write_json_signed(root, name, value):
            path = root / name
            path.write_bytes(canonical(value) + b"\n")
            _sign_file_exact(path, home, meta_fpr, password)
        def make_snapshot(identifier, members, parent=None):
            root = snapshots / identifier
            root.mkdir()
            entries = [p for pair in members for p in packages[pair]]
            for arch in ("x86_64", "aarch64", "source"):
                (root / "rpm" / arch).mkdir(parents=True)
            for pair in members:
                for package in packages[pair]:
                    arch = "source" if package["architecture"] == "src" else package["architecture"]
                    shutil.copyfile(signed[pair] / package["filename"], root / "rpm" / arch / package["filename"])
            # Generate a fully signed test preview using the reused composer.
            stub = {"snapshot_id": identifier, "fedora_release": 44, "packages": entries}
            (root / "repository-snapshot-v1.json").write_bytes(canonical(stub))
            # The planner chooses only the requested group; construct the full
            # fixture composition by progressively retaining approved groups.
            composition = work / (identifier + "-composition")
            p = plan(stub, None, registry, "ro-assist" if ("ro-assist", "1.0") in members or ("ro-assist", "2.0") in members else "ro-control")
            p["stable_base_snapshot_id"] = parent
            p["resulting_stable_packages"] = sorted(entries, key=lambda x: (x["nevra"], x["filename"]))
            composition.mkdir()
            shutil.copytree(root / "rpm", composition / "rpm")
            inv = tree_inventory(composition)
            (composition / "promotion-plan-v3.json").write_bytes(canonical(p))
            (composition / "composition-v3.json").write_bytes(canonical({"scope": "offline-v3-untrusted-composition",
                "publishable": False, "promotion_group": p["promotion_group"], "candidate_sha256": p["candidate_sha256"], "files": inv}))
            preview = work / (identifier + "-preview")
            create_preview(composition, preview, identifier, gnupghome=home, metadata_signing_key=meta_fpr,
                           rpm_signing_key=rpm_fpr, rpm_public_key=rpm_key, rpm_key_sha256=rpm_sha,
                           metadata_public_key=meta_key, metadata_key_sha256=meta_sha, passphrase_file=password, workflow_run="456")
            shutil.rmtree(root)
            shutil.copytree(preview / "snapshots/fedora/44" / identifier, root)
            manifest_sha = hashlib.sha256((root / "repository-snapshot-v1.json").read_bytes()).hexdigest()
            components = []
            for index, pair in enumerate(members, start=1):
                producer = next(p for p in registry["producers"] for c in p["components"] if pair[0] in c["package_names"])
                components.append({"signing_run": index, "source_repository": producer["repository"],
                    "source_commit": "a" * 40, "release_tag": "fixture-" + pair[1], "release_id": index,
                    "producer_workflow_run": index, "acceptance_manifest_digest": packages[pair][0]["producer_manifest_digest"]})
            write_json_signed(root, "snapshot-build-evidence-v1.json", {"schema_version": 1,
                "snapshot_id": identifier, "created_at": utc(now), "workflow_run": 456,
                "source_signing_runs": list(range(1, len(members) + 1)), "repository_snapshot_sha256": manifest_sha,
                "rpm_signing_fingerprint": rpm_fpr, "metadata_signing_fingerprint": meta_fpr, "components": components})
            return root
        beta1 = make_snapshot("repo-f44-20261001-001", [("ro-assist", "1.0"), ("ro-installer", "1.0")])
        beta2 = make_snapshot("repo-f44-20261002-002", [("ro-assist", "1.0"), ("ro-installer", "1.0"), ("ro-control", "1.0")])
        beta3 = make_snapshot("repo-f44-20261003-003", [("ro-assist", "2.0"), ("ro-installer", "1.0")])
        publications = work / "publications"
        publications.mkdir()
        collection = {"scope": "v3-github-beta-api-collection-untrusted", "repository": "Project-Ro-ASD/Ro-Repo",
                      "publishable": False, "api_response_immutability_verified": False, "archive_completeness_verified": False,
                      "total_workflow_runs": 3, "successful_runs": 3, "run_details": [], "job_details": []}
        for index, beta in enumerate((beta1, beta2, beta3), start=101):
            timestamp = now - dt.timedelta(days=10 if index != 103 else 1)
            archive = publications / str(index)
            archive.mkdir()
            write_json_signed(archive, "publication-v1.json", {"schema_version": 1, "channel": "beta", "publication_run": str(index),
                "published_at": utc(timestamp + dt.timedelta(minutes=1)), "snapshot_id": beta.name, "store_tree_sha256": "a" * 64})
            collection["run_details"].append({"id": index, "path": ".github/workflows/publish-remote-beta.yml",
                "event": "workflow_dispatch", "status": "completed", "conclusion": "success", "head_branch": "main",
                "head_sha": "a" * 40, "run_attempt": 1, "run_started_at": utc(timestamp), "updated_at": utc(timestamp + dt.timedelta(minutes=6))})
            collection["job_details"].append({"run_id": index, "jobs": [{"name": name, "run_id": index,
                "status": "completed", "conclusion": "success", "started_at": utc(timestamp + dt.timedelta(minutes=minute)),
                "completed_at": utc(timestamp + dt.timedelta(minutes=minute + 1))}
                for minute, name in zip((0, 2, 4), ("sign-beta-publication", "publish-beta", "verify-remote-beta"))]})
        def integrate(beta, stable, identifier, mode="normal"):
            composition = work / (identifier + "-group")
            compose(beta, stable, registry, "ro-assist", composition)
            preview = work / (identifier + "-stable")
            create_preview(composition, preview, identifier, gnupghome=home, metadata_signing_key=meta_fpr,
                           rpm_signing_key=rpm_fpr, rpm_public_key=rpm_key, rpm_key_sha256=rpm_sha,
                           metadata_public_key=meta_key, metadata_key_sha256=meta_sha, passphrase_file=password, workflow_run="789")
            result = preview / "snapshots/fedora/44" / identifier
            value = prepare(beta, stable, registry, "ro-assist", work / (identifier + "-integration"),
                            publications=publications, snapshots=snapshots, collection=collection,
                            metadata_key=meta_key, metadata_key_sha256=meta_sha, rpm_key=rpm_key, rpm_key_sha256=rpm_sha,
                            now=utc(now), mode=mode, reason="fixture security update" if mode == "fast-track" else None,
                            result_snapshot=result)
            return result, value, json.loads((composition / "promotion-plan-v3.json").read_bytes())
        first, first_proposal, first_plan = integrate(beta1, None, "repo-f44-20261011-010")
        later, later_proposal, _ = integrate(beta2, None, "repo-f44-20261011-011")
        assert first_proposal["candidate_sha256"] == later_proposal["candidate_sha256"]
        assert first_proposal["first_seen"] == later_proposal["first_seen"]
        assert not list(first.rglob("ro-installer*.rpm")) and not list(first.rglob("dolphin*.rpm"))
        # Independently approved retained group fixture.
        retained_comp = work / "retained-composition"
        compose(beta2, first, registry, "ro-control", retained_comp)
        retained_preview = work / "retained-preview"
        retained_id = "repo-f44-20261011-012"
        create_preview(retained_comp, retained_preview, retained_id, gnupghome=home, metadata_signing_key=meta_fpr,
                       rpm_signing_key=rpm_fpr, rpm_public_key=rpm_key, rpm_key_sha256=rpm_sha,
                       metadata_public_key=meta_key, metadata_key_sha256=meta_sha, passphrase_file=password, workflow_run="790")
        retained = retained_preview / "snapshots/fedora/44" / retained_id
        second, second_proposal, second_plan = integrate(beta3, retained, "repo-f44-20261011-013", "fast-track")
        for path in retained.rglob("ro-control*.rpm"):
            assert path.read_bytes() == (second / path.relative_to(retained)).read_bytes()
        fail_closed(lambda: request(second_proposal, "unapproved-fast-track"))  # no mandatory test claim
        normal = copy.deepcopy(second_proposal)
        normal["mode"], normal["reason"] = "normal", None
        normal["proposal_sha256"] = sha({k: v for k, v in normal.items() if k != "proposal_sha256"})
        fail_closed(lambda: request(normal, "insufficient-dwell"))
        evidence = work / "evidence"
        evidence.mkdir()
        validate(first, None, beta1, first_plan, "x86_64", evidence / "bootstrap", rpm_key=rpm_key, rpm_key_sha256=rpm_sha,
                 metadata_key=meta_key, metadata_key_sha256=meta_sha)
        # Component promotion adds a genuinely new group to an existing
        # stable set; DNF must upgrade installed names and install new names.
        retained_plan = json.loads((retained_comp / "promotion-plan-v3.json").read_bytes())
        validate(retained, first, beta2, retained_plan, "x86_64", evidence / "new-group-install",
                 rpm_key=rpm_key, rpm_key_sha256=rpm_sha, metadata_key=meta_key, metadata_key_sha256=meta_sha)
        validate(second, retained, beta3, second_plan, "x86_64", evidence / "upgrade", rpm_key=rpm_key, rpm_key_sha256=rpm_sha,
                 metadata_key=meta_key, metadata_key_sha256=meta_sha, config_paths=["/etc/ro-assist.conf"])
        # Exercise the backend's real signing/composition adapter with the same
        # approved payload, rather than a second mock repository implementation.
        from v3_immutable_view import verify_result
        backend_result = verify_result(second, second_proposal, second_plan, beta=beta3, baseline=retained,
                    registry=registry, rpm_key=rpm_key, rpm_key_sha256=rpm_sha,
                    metadata_key=meta_key, metadata_key_sha256=meta_sha)
        assert backend_result.sha256 == sha(tree_inventory(second))
        # Recovery preserves the historical snapshot's original signed parent;
        # its new publication envelope binds the CURRENT base independently.
        recovery_plan = copy.deepcopy(first_plan)
        recovery_plan["stable_base_snapshot_id"] = second.name
        recovery_proposal = copy.deepcopy(first_proposal)
        recovery_proposal["previous_stable_snapshot_id"] = second.name
        recovery_proposal["previous_stable_sha256"] = sha(tree_inventory(second))
        recovery_proposal["proposal_sha256"] = sha({k: v for k, v in recovery_proposal.items() if k != "proposal_sha256"})
        recovered = verify_result(first, recovery_proposal, recovery_plan, beta=beta1, baseline=second,
                    registry=registry, rpm_key=rpm_key, rpm_key_sha256=rpm_sha,
                    metadata_key=meta_key, metadata_key_sha256=meta_sha, operation="recover")
        assert recovered.sha256 == first_proposal["result_stable_sha256"]
        from v3_migration import rehearse
        migration = rehearse(retained, registry, metadata_key=meta_key, metadata_key_sha256=meta_sha,
                    rpm_key=rpm_key, rpm_key_sha256=rpm_sha, storage_commit="a" * 40,
                    workflow=ROOT / ".github/workflows/promote-remote-stable.yml")
        assert migration["canonical_closure"] == "PASS" and migration["activation"] == "BLOCKED"
        (evidence / "migration-fixture.json").write_bytes(canonical(migration) + b"\n")
        # A metadata signature cannot replace the independent RPM signing role.
        unsigned_root = work / "unsigned-source" / first.name
        shutil.copytree(first, unsigned_root)
        unsigned_source = next((unsigned_root / "rpm/source").glob("*.rpm"))
        run(["rpmsign", "--delsign", str(unsigned_source)])
        unsigned_manifest = json.loads((unsigned_root / "repository-snapshot-v1.json").read_bytes())
        unsigned_plan = copy.deepcopy(first_plan)
        new_digest = hashlib.sha256(unsigned_source.read_bytes()).hexdigest()
        for members in (unsigned_manifest["packages"], unsigned_plan["resulting_stable_packages"], unsigned_plan["selected_group_packages"]):
            for item in members:
                if item["architecture"] == "src":
                    item["published_signed_artifact_sha256"] = new_digest
        (unsigned_root / "repository-snapshot-v1.json").write_bytes(canonical(unsigned_manifest))
        _sign_file_exact(unsigned_root / "repository-snapshot-v1.json", home, meta_fpr, password)
        unsigned_reason = fail_closed(lambda: validate(unsigned_root, None, beta1, unsigned_plan, "x86_64",
                                      work / "unsigned-source-observation", rpm_key=rpm_key, rpm_key_sha256=rpm_sha,
                                      metadata_key=meta_key, metadata_key_sha256=meta_sha), "signature")
        negative_results = {}
        for version, identifier, expected in (("2.0", "repo-f44-20261011-020", "real transaction failed"),
                                               ("3.0", "repo-f44-20261011-021", "full-set file conflict")):
            broken = make_snapshot(identifier, [("ro-assist", "2.0"), ("ro-control", version)], parent=second.name)
            broken_plan = plan(json.loads((broken / "repository-snapshot-v1.json").read_bytes()),
                               json.loads((second / "repository-snapshot-v1.json").read_bytes()), registry, "ro-control")
            reason = fail_closed(lambda: validate(broken, second, broken, broken_plan, "x86_64", work / ("negative-" + version),
                                 rpm_key=rpm_key, rpm_key_sha256=rpm_sha, metadata_key=meta_key, metadata_key_sha256=meta_sha), expected)
            negative_results[version] = {"status": "PASS", "rejection": reason, "snapshot_tree_sha256": sha(tree_inventory(broken))}
            if version == "2.0":
                dependency_snapshot, dependency_plan = broken, broken_plan
        # Metadata reproducibility excludes GPG signatures whose creation time
        # is intentionally separate; compare all unsigned repodata bytes.
        from v3_repository_metadata import generate
        copies = []
        for index in range(2):
            copyroot = work / ("repro-" + str(index))
            copyroot.mkdir()
            for rpm in (second / "rpm/x86_64").glob("*.rpm"):
                shutil.copyfile(rpm, copyroot / rpm.name)
            generate(copyroot, 1791676800)
            copies.append(tree_inventory(copyroot / "repodata"))
        assert copies[0] == copies[1], "non-reproducible unsigned metadata"
        # Actual RPM/header/signature/repodata verification for the independently
        # signed cache contract. This is a fixture upstream, not Fedora's feed.
        from v3_backend_trust import TestSigner, test_workspace, verify_envelope
        from v3_pinned_upstream import verify_upstream
        test_root = test_workspace()
        try:
            cache = test_root / "upstream"
            cache.mkdir()
            binary = next(p for p in packages["ro-v3-impossible-dependency", "1.0"] if p["architecture"] == "x86_64")
            shutil.copyfile(signed["ro-v3-impossible-dependency", "1.0"] / binary["filename"], cache / binary["filename"])
            generate(cache, 1791676800)
            upstream_manifest = {"schema_version": 3, "scope": "v3-pinned-fedora-upstream", "fedora_release": 44,
                "architecture": "x86_64", "repo_id": "pinned-fedora-fixture", "tree_sha256": sha(tree_inventory(cache)),
                "repomd_sha256": hashlib.sha256((cache / "repodata/repomd.xml").read_bytes()).hexdigest(),
                "metadata_authentication": "signed-pin", "rpm_key_sha256": rpm_sha,
                "packages": [{"path": binary["filename"], "nevra": binary["nevra"], "sha256": binary["published_signed_artifact_sha256"]}]}
            pin_signer = TestSigner(test_root, "upstream-pin")
            tick = int(now.timestamp())
            raw = pin_signer.envelope("upstream-pin", {"manifest": upstream_manifest, "issued_at": tick, "expires_at": tick+300})
            pin = verify_envelope(raw, role="upstream-pin", public_key=pin_signer.public, key_sha256=pin_signer.key_sha256,
                                  expected={"manifest": upstream_manifest}, now=tick)
            upstream = verify_upstream(cache, upstream_manifest, pin, rpm_key=rpm_key, rpm_key_sha256=rpm_sha, now=tick)
            upstream.check()
            closure = validate(dependency_snapshot, second, dependency_snapshot, dependency_plan, "x86_64",
                     evidence / "pinned-dependency-closure", rpm_key=rpm_key, rpm_key_sha256=rpm_sha,
                     metadata_key=meta_key, metadata_key_sha256=meta_sha, upstream=[upstream])
            assert binary["nevra"] in closure["installed_dependency_closure"]
            (evidence / "upstream-fixture.json").write_bytes(canonical({"manifest": upstream_manifest,
                  "signature_and_metadata": "PASS", "official_fedora_upstream": "UNVERIFIED", "publishable": False}) + b"\n")
        finally:
            shutil.rmtree(test_root)
        if source_inventory() != tested_sources:
            raise RuntimeError("tested source tree changed during acceptance run")
        from v3_client_native_support import exercise as exercise_client
        exercise_client(first, second, rpm_key, meta_key, work, evidence)
        (evidence / "acceptance.json").write_bytes(canonical({"scope": "v3-fedora44-fixture-acceptance",
            "source_code_sha256": sha(tested_sources),
            "gates": {"signed-bootstrap": "PASS", "unchanged-candidate-dwell": "PASS", "retained-signed-bytes": "PASS",
                      "backend-real-rpm-adapter": "PASS", "migration-fixture": "PASS", "pinned-upstream-fixture": "PASS",
                      "recovery-historical-signed-parent": "PASS",
                      "https-client-discovery-dnf-fixture": "PASS",
                      "unapproved-group-exclusion": "PASS", "full-set-upgrade": "PASS", "rpmnew": "PASS", "reproducible-metadata": "PASS",
                      "missing-dependency-rejection": "PASS", "retained-group-conflict-rejection": "PASS",
                      "aarch64": "UNVERIFIED", "real-producer-applications": "UNVERIFIED", "plasma-login": "UNVERIFIED",
                      "boot-recovery-qemu": "UNVERIFIED", "ro-store-application": "UNVERIFIED", "production-activation": "BLOCKED"},
            "negative_results": {**negative_results, "unsigned-source": {"status": "PASS", "rejection": unsigned_reason}},
            "first_proposal": first_proposal, "second_proposal": second_proposal, "publishable": False}) + b"\n")
        shutil.copyfile(rpm_key, evidence / "ephemeral-rpm-public.asc")
        shutil.copyfile(meta_key, evidence / "ephemeral-metadata-public.asc")
        shutil.copytree(evidence, output)
        run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"])
    print("PASS: Fedora 44 real signed fixture bootstrap/full-set upgrade/channel isolation/rpmnew/reproducible metadata; production BLOCKED")


if __name__ == "__main__":
    main(sys.argv[1])
