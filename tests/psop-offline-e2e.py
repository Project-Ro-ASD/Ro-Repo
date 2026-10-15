#!/usr/bin/env python3
"""Actual local Fedora RPM/GPG/metadata/SQLite/Git pipeline; no DNF or network.

The fixture alone builds/signs synthetic RPMs. PSOP only verifies/reuses their
exact bytes. Synthetic identity/availability/model-test evidence is never actual
application, DNF5, GUI, external Pages or production acceptance.
"""
import copy
import datetime as dt
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from psop_context import Context, frozen_tree
from psop_history import read_archive, assess_history, availability_request
from psop_inputs import acquire, source_request, committed_stable
from psop_genesis import verify_genesis, genesis_request
from psop_plan import prepare
from psop_result import build_metadata, review_bundle
from psop_authorization import approval_request, verify_approval
from psop_signing import MetadataSigner, sign_result
from psop_ledger import Ledger
from psop_storage_gateway import Gateway
from v3_policy_profile import canonical, sha, BASE
from v3_backend_trust import digest
from v3_promotion_planner import plan, PlanningError
from v3_stable_composer import compose
from v3_rpm_preflight import verify as verify_rpms
from v3_repository_metadata import generate
from ro_repo import sign_packages, export_role_public_key, _sign_file_exact, ContractError


def run(argv):
    p = subprocess.run(list(map(str, argv)), capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(str(argv[:2]) + "\n" + p.stderr[-2000:] + p.stdout[-1000:])
    return p.stdout


def reject(call, contains=None):
    try:
        call()
    except (PlanningError, ContractError, subprocess.CalledProcessError) as error:
        if contains is not None and contains not in str(error):
            raise AssertionError("unexpected rejection reason: " + str(error)) from error
        return "PASS_REJECTION"
    raise AssertionError("unsafe input accepted")


def main(output):
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    utc = lambda n: dt.datetime.fromtimestamp(n, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with tempfile.TemporaryDirectory(prefix="psop-rpm-fixtures-") as directory:
        work = pathlib.Path(directory)
        home = work / "keys"; home.mkdir(mode=0o700)
        gpg = ["gpg", "--no-options", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        run([*gpg, "--quick-generate-key", "PSOP INPUT FIXTURE ONLY <test@invalid>", "rsa2048", "cert", "1d"])
        fprs = lambda: [l.split(":")[9] for l in run([*gpg, "--with-colons", "--list-keys"]).splitlines() if l.startswith("fpr:")]
        primary = fprs()[0]
        for _ in range(2):run([*gpg, "--quick-add-key", primary, "rsa2048", "sign", "1d"])
        rpm_fpr, meta_fpr = fprs()[1:]
        roots = {}
        for role, fpr in (("rpm", rpm_fpr), ("metadata", meta_fpr)):
            key = work / (role + ".asc"); key.write_text(export_role_public_key(home, fpr))
            roots[role] = {"path": str(key), "sha256": digest(key.read_bytes()), "fingerprint": fpr}
        password = work / "password";password.write_bytes(b"");password.chmod(0o600)
        top = work / "build"
        for p in ("BUILD", "BUILDROOT", "RPMS", "SRPMS", "SPECS", "SOURCES"):(top / p).mkdir(parents=True)
        packages, signed, unsigned = {}, {}, {}
        for name, version, dependency in (("ro-control", "1.0", ""), ("ro-control", "2.0", ""),
                                           ("ro-assist", "2.0", "Requires: ro-control = 1.0\n")):
            spec = top / "SPECS" / (name + version + ".spec")
            spec.write_text(f"""%global debug_package %{{nil}}
Name: {name}
Version: {version}
Release: 1.fc44
Summary: Synthetic PSOP test RPM
License: MIT
BuildArch: noarch
{dependency}%description
No real application. Disposable only.
%prep
%build
%install
install -Dm0644 /dev/null %{{buildroot}}/usr/share/{name}/fixture
%files
/usr/share/{name}/fixture
""")
            run(["rpmbuild", "-ba", "--define", "_topdir " + str(top), spec])
            raw = work / (name + version + "-unsigned"); raw.mkdir()
            for p in list((top / "RPMS/noarch").glob(f"{name}-{version}-*.rpm")) + list((top / "SRPMS").glob(f"{name}-{version}-*.rpm")):
                shutil.copyfile(p, raw / p.name)
            dest = work / (name + version + "-signed")
            sign_packages(raw, dest, home, rpm_fpr)
            signed[name, version], unsigned[name, version] = dest, raw
            entries = []
            for p in sorted(dest.glob("*.rpm")):
                arch = "src" if p.name.endswith(".src.rpm") else "noarch"
                entries.append({"nevra": f"{name}-0:{version}-1.fc44.{arch}", "filename": p.name,
                    "architecture": arch, "producer_manifest_digest": sha([name, version]),
                    "producer_artifact_sha256": digest((raw / p.name).read_bytes()),
                    "published_signed_artifact_sha256": digest(p.read_bytes())})
            packages[name, version] = entries
        registry = {"fedora_release": 44, "producers": [{"repository": "psop-fixture/source", "components": [
            {"component": n, "promotion_group": n, "package_names": [n], "architectures": ["noarch"],
             "risk_class": "normal-app", "required_tests": sorted(BASE), "trusted_signer_workflow": "psop-fixture/release"}
             for n in ("ro-control", "ro-assist")]}]}
        snapshots = work / "snapshots";snapshots.mkdir()
        def write_signed(root, name, value):
            path = root / name;path.write_bytes(canonical(value));_sign_file_exact(path, home, meta_fpr, password)
        def snapshot(identifier, members):
            root = snapshots / identifier;root.mkdir()
            entries = [e for pair in members for e in packages[pair]]
            repos = {}
            for arch in ("x86_64", "aarch64", "source"):
                folder = root / "rpm" / arch;folder.mkdir(parents=True)
                for pair in members:
                    for e in packages[pair]:
                        if (e["architecture"] == "src") == (arch == "source"):
                            shutil.copyfile(signed[pair] / e["filename"], folder / e["filename"])
                generate(folder, now - 10 * 86400)
                _sign_file_exact(folder / "repodata/repomd.xml", home, meta_fpr, password)
                repos[arch] = {"repomd_sha256": digest((folder / "repodata/repomd.xml").read_bytes()),
                    "repomd_signature_sha256": digest((folder / "repodata/repomd.xml.asc").read_bytes())}
            (root / "keys").mkdir()
            for role, filename in (("rpm", "RPM-GPG-KEY-test"), ("metadata", "REPODATA-GPG-KEY-test")):
                shutil.copyfile(roots[role]["path"], root / "keys" / filename)
            m = {"schema_version": 1, "snapshot_id": identifier, "created_at": utc(now - 10 * 86400),
                "fedora_release": 44, "parent_snapshot": None, "packages": entries, "repositories": repos,
                "rpm_signing_fingerprint": rpm_fpr, "metadata_signing_fingerprint": meta_fpr,
                "creation_provenance": {"tool": "ro-repo-v2", "run": "456"}}
            write_signed(root, "repository-snapshot-v1.json", m)
            write_signed(root, "snapshot-build-evidence-v1.json", {"schema_version": 1, "snapshot_id": identifier,
                "created_at": utc(now), "workflow_run": 456, "source_signing_runs": list(range(1, len(members) + 1)),
                "repository_snapshot_sha256": digest((root / "repository-snapshot-v1.json").read_bytes()),
                "rpm_signing_fingerprint": rpm_fpr, "metadata_signing_fingerprint": meta_fpr,
                "components": [{"signing_run": idx, "source_repository": "psop-fixture/source", "source_commit": "a" * 40,
                    "release_tag": pair[0] + pair[1], "release_id": idx, "producer_workflow_run": idx,
                    "acceptance_manifest_digest": sha(list(pair))} for idx, pair in enumerate(members, 1)]})
            return root
        beta1 = snapshot("repo-f44-20261001-001", [("ro-control", "1.0")])
        beta2 = snapshot("repo-f44-20261002-002", [("ro-control", "2.0"), ("ro-assist", "2.0")])
        publications = work / "publications";publications.mkdir()
        for idx, beta in enumerate((beta1, beta2), 101):
            folder = publications / str(idx);folder.mkdir()
            # Explicit legacy format, retaining original signed bytes.
            write_signed(folder, "publication-v1.json", {"schema_version": 1, "channel": "beta",
                "publication_run": str(idx), "snapshot_id": beta.name, "published_at": utc(now - 10 * 86400)})
        cases = []
        for beta, stable, group in ((beta1, None, "ro-control"), (beta2, beta1, "ro-assist")):
            context = Context.create()
            try:
                archive = read_archive(publications, snapshots, registry, group, roots["metadata"]["path"],
                    roots["metadata"]["sha256"], utc(now), context=context)
                bm = json.loads((beta / "repository-snapshot-v1.json").read_bytes())
                sm = None if stable is None else json.loads((stable / "repository-snapshot-v1.json").read_bytes())
                pins = {"main_sha": "a" * 40, "pages_sha": "b" * 40}
                public = {r: {k: v for k, v in p.items() if k != "path"} for r, p in roots.items()}
                build = json.loads((beta / "snapshot-build-evidence-v1.json").read_bytes())
                source = context.envelope("source", source_request(pins, registry, bm, sm, public, build), now=now)
                inputs = acquire(pins, roots, archive, beta=beta, stable=stable, registry=registry, group=group,
                                 source_evidence=source, context=context, now=now)
                bad_roots = copy.deepcopy(roots);bad_roots["rpm"]["sha256"] = "f" * 64
                negatives = {"wrong_public_root_hash": reject(lambda: acquire(pins, bad_roots, archive,
                    beta=beta, stable=stable, registry=registry, group=group, source_evidence=source, context=context, now=now))}
                p = plan(bm, sm, registry, group)
                first = {"publication_run": "101" if stable is None else "102", "published_at": utc(now - 9 * 86400)}
                missing = assess_history(archive, [], None, context=context, candidate=p["candidate_sha256"], now=utc(now))
                assert missing.data["status"] == "BLOCKED"
                availability = context.envelope("availability", availability_request(archive, p["candidate_sha256"], first), now=now)
                history = assess_history(archive, [], availability, context=context, candidate=p["candidate_sha256"], now=utc(now))
                genesis = None
                if stable is None:
                    genesis = verify_genesis(inputs, history, context.envelope("genesis", genesis_request(inputs, history), now=now), context=context, now=now)
                from test_v3_group_validation import mkclaim
                claim = mkclaim({**p, "selected_group_packages": [{"architecture": a} for a in ("x86_64", "aarch64")]}, BASE)
                claim.update(candidate_sha256=p["candidate_sha256"], stable_base_snapshot_id=p["stable_base_snapshot_id"], tested_at=utc(now))
                for check in claim["checks"]:check["candidate_sha256"] = p["candidate_sha256"]
                attestation = context.envelope("tests", {"claim_sha256": sha(claim), "plan_sha256": sha(p),
                    "scope": "synthetic-model-only", "required_tests": sorted(BASE), "architectures": ["aarch64", "x86_64"],
                    "production_test_authority": False}, now=now)
                prepared = prepare(inputs, group, registry, {"claim": claim, "attestation": attestation},
                    history=history, genesis=genesis, context=context, now=utc(now))
                negatives["missing_availability"] = reject(lambda: prepare(inputs, group, registry,
                    {"claim": claim, "attestation": attestation}, history=missing, genesis=genesis, context=context, now=utc(now)))
                if stable is not None:
                    recent_first = {**first, "published_at": utc(now - 86400)}
                    recent = assess_history(archive, [], context.envelope("availability",
                        availability_request(archive, p["candidate_sha256"], recent_first), now=now),
                        context=context, candidate=p["candidate_sha256"], now=utc(now))
                    negatives["short_canonical_dwell"] = reject(lambda: prepare(inputs, group, registry,
                        {"claim": claim, "attestation": attestation}, history=recent, genesis=None, context=context, now=utc(now)))
                result = build_metadata(prepared, {"source_date_epoch": now - 10 * 86400}, context=context)
                repeat = build_metadata(prepared, {"source_date_epoch": now - 10 * 86400}, context=context)
                assert result.data["inventory"] == repeat.data["inventory"]
                if stable is not None:
                    assert {e["nevra"] for e in prepared.data["plan"]["resulting_stable_packages"]} == {
                        "ro-control-0:1.0-1.fc44.noarch", "ro-control-0:1.0-1.fc44.src",
                        "ro-assist-0:2.0-1.fc44.noarch", "ro-assist-0:2.0-1.fc44.src"}
                review = review_bundle(result, context=context)
                signer = MetadataSigner.create(context)
                wrong_signer = copy.copy(signer);wrong_signer.fingerprint = "1715DDA529B9ADB46D47CB389A62B8F9026E75E5"
                negatives["production_signing_role"] = reject(wrong_signer.check)
                identity = {"issuer": context.descriptor["origin"] + "/issuer", "repository": context.descriptor["repository"],
                    "actor": "42", "run_id": "101", "run_attempt": "1"}
                request = approval_request(review, identity, attempt="local-1", nonce="nonce-1", writer="psop-stable", expected_git=None,
                    metadata_key={"sha256": signer.pin, "fingerprint": signer.fingerprint})
                approval = verify_approval(context.envelope("approval", request, now=now), identity, review,
                    prepared.data["policy"], now, context=context)
                signed_result = sign_result(result, approval, signer, context=context, now=now)
                ledger = Ledger(context, clock=lambda: now)
                if stable is not None:
                    proof = context.envelope("genesis", {"scope": "synthetic-test-base-import", "inputs_sha256": inputs.sha256,
                        "history_sha256": history.sha256, "previous_stable_sha256": inputs.data["previous_stable_sha256"]}, now=now)
                    ledger.adopt_test_base(inputs, history, proof)
                gateway = Gateway(ledger, context)
                intent = gateway.prepare(signed_result, approval)
                gateway.admit(intent, approval)
                receipt = gateway.apply("local-1")
                assert receipt["status"] == "COMPLETE" and receipt["production_activation"] == "BLOCKED"
                reopened = Gateway(Ledger(context, clock=lambda: now), context)
                assert reopened.apply("local-1") == receipt
                # Attack recomputes all plan/inventory hashes for an unsigned
                # binary. Actual rpmkeys, not hash self-consistency, must reject.
                tampered = context.path("unsigned-negative");shutil.copytree(prepared.composition, tampered)
                plan_path, comp_path = tampered / "promotion-plan-v3.json", tampered / "composition-v3.json"
                altered_plan, altered_comp = json.loads(plan_path.read_bytes()), json.loads(comp_path.read_bytes())
                pair = ("ro-control", "1.0") if stable is None else ("ro-assist", "2.0")
                entry = next(e for e in packages[pair] if e["architecture"] == "noarch")
                raw_bytes = (unsigned[pair] / entry["filename"]).read_bytes();raw_sha = digest(raw_bytes)
                for arch in ("x86_64", "aarch64"):(tampered / "rpm" / arch / entry["filename"]).write_bytes(raw_bytes)
                for field in ("selected_group_packages", "resulting_stable_packages"):
                    for e in altered_plan[field]:
                        if e["filename"] == entry["filename"]:e["published_signed_artifact_sha256"] = raw_sha
                for f in altered_comp["files"]:
                    if f["path"].endswith("/" + entry["filename"]):f["sha256"] = raw_sha
                altered_comp["plan_sha256"] = sha(altered_plan)
                plan_path.write_bytes(canonical(altered_plan));comp_path.write_bytes(canonical(altered_comp))
                negatives["unsigned_rehashed_rpm"] = reject(lambda: verify_rpms(tampered, roots["rpm"]["path"], roots["rpm"]["sha256"]))
                negatives["wrong_rpm_signing_role"] = reject(lambda: verify_rpms(prepared.composition,
                    roots["metadata"]["path"], roots["metadata"]["sha256"]))
                bad_registry = copy.deepcopy(registry)
                next(c for c in bad_registry["producers"][0]["components"] if c["promotion_group"] == group)["package_names"].append("missing-member")
                negatives["partial_group"] = reject(lambda: plan(bm, sm, bad_registry, group), "incomplete")
                wrong_arch = context.path("wrong-arch-negative");shutil.copytree(prepared.composition, wrong_arch)
                wp, wc = wrong_arch / "promotion-plan-v3.json", wrong_arch / "composition-v3.json"
                wplan, wcomp = json.loads(wp.read_bytes()), json.loads(wc.read_bytes())
                oldname = entry["filename"];newname = oldname.replace(".noarch.rpm", ".x86_64.rpm")
                (wrong_arch / "rpm/x86_64" / oldname).rename(wrong_arch / "rpm/x86_64" / newname)
                (wrong_arch / "rpm/aarch64" / oldname).unlink()
                for field in ("selected_group_packages", "resulting_stable_packages"):
                    for e in wplan[field]:
                        if e["filename"] == oldname:
                            e.update(filename=newname, architecture="x86_64", nevra=e["nevra"].replace(".noarch", ".x86_64"))
                wcomp["files"] = [f for f in wcomp["files"] if f["path"] != "rpm/aarch64/" + oldname]
                for f in wcomp["files"]:
                    if f["path"] == "rpm/x86_64/" + oldname:f["path"] = "rpm/x86_64/" + newname
                wcomp["plan_sha256"] = sha(wplan)
                wp.write_bytes(canonical(wplan));wc.write_bytes(canonical(wcomp))
                negatives["actual_wrong_arch_header"] = reject(lambda: verify_rpms(wrong_arch, roots["rpm"]["path"], roots["rpm"]["sha256"]), "headers mismatch")
                if stable is not None:
                    # An independently verified empty-base candidate omits the
                    # retained dependency; the real local RPM solver rejects it.
                    source0 = context.envelope("source", source_request(pins, registry, bm, None, public, build), now=now)
                    i0 = acquire(pins, roots, archive, beta=beta, stable=None, registry=registry, group=group,
                                 source_evidence=source0, context=context, now=now)
                    p0 = plan(bm, None, registry, group)
                    g0 = verify_genesis(i0, history, context.envelope("genesis", genesis_request(i0, history), now=now), context=context, now=now)
                    c0 = mkclaim({**p0, "selected_group_packages": [{"architecture": a} for a in ("x86_64", "aarch64")]}, BASE)
                    c0.update(candidate_sha256=p0["candidate_sha256"], tested_at=utc(now))
                    for check in c0["checks"]:check["candidate_sha256"] = p0["candidate_sha256"]
                    a0 = context.envelope("tests", {"claim_sha256": sha(c0), "plan_sha256": sha(p0), "scope": "synthetic-model-only",
                        "required_tests": sorted(BASE), "architectures": ["aarch64", "x86_64"], "production_test_authority": False}, now=now)
                    prep0 = prepare(i0, group, registry, {"claim": c0, "attestation": a0}, history=history, genesis=g0, context=context, now=utc(now))
                    negatives["missing_retained_dependency"] = reject(lambda: build_metadata(prep0, {"source_date_epoch": now - 10 * 86400}, context=context))
                cases.append({"case": "genesis" if stable is None else "selected-plus-retained", "status": "PASS",
                    "receipt": receipt, "deterministic_unsigned_result": True, "rpm_paths": len(prepared.data["preflight"]["checked_rpm_files"]),
                    "closure": result.data["closure"], "production_dwell": history.data["production_dwell"], "negatives": negatives})
                if stable is None:
                    # Consume our own committed signed result after restart,
                    # rather than treating a V2 Beta snapshot as a PSOP base.
                    prior = committed_stable(reopened, "local-1")
                    bm2 = json.loads((beta2 / "repository-snapshot-v1.json").read_bytes())
                    build2 = json.loads((beta2 / "snapshot-build-evidence-v1.json").read_bytes())
                    archive2 = read_archive(publications, snapshots, registry, "ro-assist", roots["metadata"]["path"],
                        roots["metadata"]["sha256"], utc(now), context=context)
                    source2 = context.envelope("source", source_request(pins, registry, bm2, prior.data["manifest"], public, build2), now=now)
                    i2 = acquire(pins, roots, archive2, beta=beta2, stable=prior, registry=registry, group="ro-assist",
                        source_evidence=source2, context=context, now=now)
                    p2 = plan(bm2, prior.data["manifest"], registry, "ro-assist")
                    f2 = {"publication_run": "102", "published_at": utc(now - 9 * 86400)}
                    h2 = assess_history(archive2, [], context.envelope("availability", availability_request(archive2, p2["candidate_sha256"], f2), now=now),
                        context=context, candidate=p2["candidate_sha256"], now=utc(now))
                    c2 = mkclaim({**p2, "selected_group_packages": [{"architecture": a} for a in ("x86_64", "aarch64")]}, BASE)
                    c2.update(candidate_sha256=p2["candidate_sha256"], stable_base_snapshot_id=p2["stable_base_snapshot_id"], tested_at=utc(now))
                    for check in c2["checks"]:check["candidate_sha256"] = p2["candidate_sha256"]
                    att2 = context.envelope("tests", {"claim_sha256": sha(c2), "plan_sha256": sha(p2), "scope": "synthetic-model-only",
                        "required_tests": sorted(BASE), "architectures": ["aarch64", "x86_64"], "production_test_authority": False}, now=now)
                    prep2 = prepare(i2, "ro-assist", registry, {"claim": c2, "attestation": att2}, history=h2, genesis=None, context=context, now=utc(now))
                    r2 = build_metadata(prep2, {"source_date_epoch": now - 10 * 86400}, context=context)
                    review2 = review_bundle(r2, context=context)
                    request2 = approval_request(review2, identity, attempt="local-2", nonce="nonce-2", writer="psop-stable",
                        expected_git=reopened._store.head(), metadata_key={"sha256": signer.pin, "fingerprint": signer.fingerprint})
                    approval2 = verify_approval(context.envelope("approval", request2, now=now), identity, review2, prep2.data["policy"], now, context=context)
                    s2 = sign_result(r2, approval2, signer, context=context, now=now)
                    intent2 = reopened.prepare(s2, approval2);reopened.admit(intent2, approval2)
                    receipt2 = reopened.apply("local-2")
                    assert receipt2["status"] == "COMPLETE"
                    assert {p["nevra"] for p in prep2.data["plan"]["resulting_stable_packages"]} == {
                        "ro-control-0:1.0-1.fc44.noarch", "ro-control-0:1.0-1.fc44.src",
                        "ro-assist-0:2.0-1.fc44.noarch", "ro-assist-0:2.0-1.fc44.src"}
                    assert reopened.apply("local-1") == receipt
                    cases.append({"case": "successor-from-committed-psop-stable-after-restart", "status": "PASS",
                        "receipt": receipt2, "old_immutable_bytes_preserved": True, "closure": r2.data["closure"]})
                subprocess.run(["gpgconf", "--homedir", str(signer.home), "--kill", "gpg-agent"], capture_output=True)
            finally:
                context.close()
        report = {"scope": "psop-local-disposable-rpm-gpg-sqlite-git-e2e", "cases": cases,
            "dnf5_client_acceptance": "UNVERIFIED", "external_pages_https": "UNVERIFIED", "gui": "UNVERIFIED",
            "production_activation": "BLOCKED", "publishable": False}
        pathlib.Path(output).write_bytes(canonical(report) + b"\n")
        print(json.dumps(report, indent=2))
        subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"], capture_output=True)


if __name__ == "__main__":
    main(sys.argv[1])
