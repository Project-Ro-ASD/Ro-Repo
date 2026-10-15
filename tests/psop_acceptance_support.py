"""Real PR-B publisher -> PSOP HTTPS/client -> disposable Fedora DNF5 harness."""
import datetime as dt
import importlib.util
import json
import pathlib
import platform
import shutil
import subprocess
import tempfile
import time
import uuid

from psop_client_support import TLSFixture
from psop_context import Context
from psop_client import Client, issue_descriptor
from psop_inputs import acquire, source_request, committed_stable
from psop_history import read_archive, assess_history, availability_request
from psop_genesis import verify_genesis, genesis_request
from psop_plan import prepare
from psop_result import build_metadata, review_bundle
from psop_authorization import approval_request, verify_approval
from psop_signing import MetadataSigner, sign_result
from psop_ledger import Ledger
from psop_storage_gateway import Gateway
from v3_backend_trust import digest, strict_json, test_workspace, canonical
from v3_policy_profile import BASE, sha
from v3_promotion_planner import plan, PlanningError
from test_v3_group_validation import mkclaim
from ro_repo import ContractError
from ro_repo import _sign_file_exact
from v3_repository_metadata import generate
from psop_evidence import capture, source_inventory

ROOT = pathlib.Path(__file__).parents[1]


def reject(call, contains=None):
    try:
        call()
    except (PlanningError, ContractError, OSError, subprocess.CalledProcessError) as error:
        if contains and contains not in str(error):
            raise AssertionError("wrong rejection: " + str(error)) from error
        return "PASS_REJECTION"
    raise AssertionError("negative scenario unexpectedly accepted")


def public_roots(source, signer, root):
    path = root / "pinned-test-metadata.asc";path.write_bytes(signer.public)
    return {"rpm": source["rpm"], "metadata": {"path": str(path), "sha256": signer.pin, "fingerprint": signer.fingerprint}}


def new_client(context, origin, roots, ca):
    root = test_workspace();key = context.signer("publication")
    return Client(root, origin=origin, context=context.pin, publication_key=key.public, publication_pin=key.key_sha256,
        roots=roots, clock=lambda: int(time.time()), ca=ca)


def next_publication(source, context, signer, gateway, beta, *, previous=None, attempt):
    """One plumbing adapter, reusing actual verified PR-B source/plan/sign APIs."""
    now = int(time.time());utc = lambda n: dt.datetime.fromtimestamp(n, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    registry, roots = source["registry"], source["roots"]
    bm = json.loads((beta / "repository-snapshot-v1.json").read_bytes())
    stable = None if previous is None else committed_stable(gateway, previous)
    sm = None if stable is None else stable.data["manifest"]
    archive = read_archive(source["publications"], source["snapshots"], registry, "ro-control", roots["metadata"]["path"],
        roots["metadata"]["sha256"], utc(now), context=context)
    build = json.loads((beta / "snapshot-build-evidence-v1.json").read_bytes())
    pins = {"main_sha": "9284bdc04b7ed7f0b2c1ec6a34942eb7e36317c3", "pages_sha": "097ba6ba7ab73d87c36f7ec9829b017b083b1883"}
    root_ids = {r: {k: v for k, v in p.items() if k != "path"} for r, p in roots.items()}
    source_raw = context.envelope("source", source_request(pins, registry, bm, sm, root_ids, build), now=now)
    inputs = acquire(pins, roots, archive, beta=beta, stable=stable, registry=registry, group="ro-control",
        source_evidence=source_raw, context=context, now=now)
    p = plan(bm, sm, registry, "ro-control")
    first = {"publication_run": "101" if beta == source["beta1"] else "102", "published_at": utc(source["now"] - 9 * 86400)}
    history = assess_history(archive, [], context.envelope("availability", availability_request(archive, p["candidate_sha256"], first), now=now),
        context=context, candidate=p["candidate_sha256"], now=utc(now))
    genesis = None if stable is not None else verify_genesis(inputs, history, context.envelope("genesis", genesis_request(inputs, history), now=now), context=context, now=now)
    claim = mkclaim({**p, "selected_group_packages": [{"architecture": a} for a in ("x86_64", "aarch64")]}, BASE)
    claim.update(candidate_sha256=p["candidate_sha256"], stable_base_snapshot_id=p["stable_base_snapshot_id"], tested_at=utc(now))
    for check in claim["checks"]:check["candidate_sha256"] = p["candidate_sha256"]
    att = context.envelope("tests", {"claim_sha256": sha(claim), "plan_sha256": sha(p), "scope": "synthetic-model-only",
        "required_tests": sorted(BASE), "architectures": ["aarch64", "x86_64"], "production_test_authority": False}, now=now)
    prepared = prepare(inputs, "ro-control", registry, {"claim": claim, "attestation": att}, history=history, genesis=genesis, context=context, now=utc(now))
    result = build_metadata(prepared, {"source_date_epoch": source["now"] - 10 * 86400}, context=context)
    review = review_bundle(result, context=context)
    identity = {"issuer": context.descriptor["origin"] + "/issuer", "repository": context.descriptor["repository"], "actor": "42", "run_id": "101", "run_attempt": "1"}
    request = approval_request(review, identity, attempt=attempt, nonce=uuid.uuid4().hex, writer="psop-stable", expected_git=gateway._store.head(),
        metadata_key={"sha256": signer.pin, "fingerprint": signer.fingerprint})
    approval = verify_approval(context.envelope("approval", request, now=now), identity, review, prepared.data["policy"], now, context=context)
    signed = sign_result(result, approval, signer, context=context, now=now)
    intent = gateway.prepare(signed, approval);gateway.admit(intent, approval);gateway.apply(attempt)
    return signed, approval


def runtime_identity():
    if not any(pathlib.Path(p).is_file() for p in ("/run/.containerenv", "/.dockerenv")):
        raise PlanningError("native DNF acceptance requires a disposable container; host writes forbidden")
    release = pathlib.Path("/etc/os-release").read_text()
    if 'VERSION_ID=44' not in release and 'VERSION_ID="44"' not in release:
        raise PlanningError("Fedora 44 runtime required")
    if platform.machine() != "x86_64":
        raise PlanningError("this acceptance is native x86_64; aarch64 UNVERIFIED")
    return {"os_release_sha256": digest(release.encode()), "machine": platform.machine(),
        "dnf5": subprocess.check_output(["dnf5", "--version"], text=True).splitlines()[0],
        "rpm": subprocess.check_output(["rpm", "--version"], text=True).strip()}


def dnf_defense_negatives(values, signed, roots, work):
    """Actual DNF defenses on deliberately invalid fixtures, outside Client API.

    These repositories cannot receive a valid PSOP descriptor. No success
    receipt is manufactured for them. Each gets an independent empty RPMDB.
    """
    report = {}
    for fault in ("wrong-metadata-key", "wrong-rpm-key", "broken-metadata-signature", "unsigned-rpm", "missing-dependency"):
        case = work / ("dnf-negative-" + fault);case.mkdir()
        repo = case / "repo";shutil.copytree(signed.path / "rpm/x86_64", repo)
        if fault == "unsigned-rpm":
            entry = next((repo).glob("ro-control-*.rpm"))
            shutil.copyfile(values["unsigned"]["ro-control", "1.0"] / entry.name, entry)
        if fault == "missing-dependency":
            for path in repo.glob("ro-control-*.rpm"):path.unlink()
        if fault in {"unsigned-rpm", "missing-dependency"}:
            shutil.rmtree(repo / "repodata");generate(repo, values["now"])
            _sign_file_exact(repo / "repodata/repomd.xml", values["signer"].home, values["signer"].fingerprint, values["signer"].password)
        if fault == "broken-metadata-signature":
            (repo / "repodata/repomd.xml.asc").write_bytes(b"invalid signature")
        key = case / "roots.asc"
        key.write_bytes(pathlib.Path(values["roots"]["metadata"]["path"] if fault == "wrong-rpm-key" else roots["rpm"]["path"]).read_bytes() + b"\n" + pathlib.Path(
            values["roots"]["metadata"]["path"] if fault == "wrong-metadata-key" else roots["metadata"]["path"]).read_bytes())
        repos = case / "repos";repos.mkdir()
        (repos / "negative.repo").write_text("[negative]\nname=deliberately invalid disposable repo\nbaseurl=file://" + str(repo) +
            "\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\nsslverify=1\nskip_if_unavailable=0\ngpgkey=file://" + str(key) + "\n")
        installroot = case / "installroot";installroot.mkdir()
        cmd = ["dnf5", "-y", "--no-plugins", "--config=/dev/null", "--installroot=" + str(installroot), "--releasever=44",
            "--setopt=reposdir=" + str(repos), "--setopt=cachedir=" + str(case / "cache"), "--setopt=logdir=" + str(case / "logs"),
            "--disable-repo=*", "--enable-repo=negative", "install", "ro-assist"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if result.returncode == 0:
            raise AssertionError("DNF accepted unsafe fixture: " + fault)
        reason = result.stdout + result.stderr
        expected = {"wrong-metadata-key": ("signature", "signing", "public key"), "wrong-rpm-key": ("signature", "signing", "public key", "gpg"), "broken-metadata-signature": ("signature", "signing"),
            "unsigned-rpm": ("signature", "signing", "not signed", "gpg"), "missing-dependency": ("nothing provides", "requires", "conflicting requests")}
        if not any(word in reason.lower() for word in expected[fault]):
            raise AssertionError("unrelated DNF failure for " + fault + ": " + reason[-1200:])
        installed = subprocess.run(["rpm", "--root", str(installroot), "-q", "ro-assist"], capture_output=True)
        assert installed.returncode != 0
        report[fault] = {"status": "PASS_REJECTION", "returncode": result.returncode,
            "stdout_stderr_sha256": digest(reason.encode()), "diagnostic": reason[-3000:], "ro_assist_installed": False}
    return report


def official_fedora_base(client):
    """Read Fedora's public repository; install only in this client test root.

    Records exact observed RPM/repomd/root bytes. This is a runtime upstream
    observation, not an independently attested production upstream snapshot.
    PSOP itself still uses its preverified frozen signed result exclusively.
    """
    root = client.root / "dnf-root";root.mkdir()
    cache, logs = client.root / "fedora-cache", client.root / "fedora-logs"
    repo = pathlib.Path("/etc/yum.repos.d/fedora.repo")
    if not repo.is_file():raise PlanningError("official Fedora repository config unavailable")
    keys = {str(p): digest(p.read_bytes()) for p in pathlib.Path("/etc/pki/rpm-gpg").glob("RPM-GPG-KEY-fedora-44-*") if p.is_file()}
    if not keys:raise PlanningError("preinstalled Fedora 44 public roots unavailable")
    command = ["dnf5", "-y", "--no-plugins", "--config=/dev/null", "--installroot=" + str(root), "--releasever=44",
        "--setopt=reposdir=/etc/yum.repos.d", "--setopt=cachedir=" + str(cache), "--setopt=logdir=" + str(logs),
        "--setopt=keepcache=True", "--disable-repo=*", "--enable-repo=fedora", "--setopt=fedora.gpgcheck=1",
        "--setopt=fedora.sslverify=1", "--setopt=fedora.skip_if_unavailable=0", "--setopt=install_weak_deps=False", "install", "gzip"]
    p = subprocess.run(command, capture_output=True, text=True, timeout=600)
    if p.returncode:
        raise PlanningError("required real Fedora upstream test failed: " + (p.stdout + p.stderr)[-2500:])
    installed = subprocess.check_output(["rpm", "--root", str(root), "-qa", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n"], text=True).splitlines()
    if not any(x.startswith("gzip-") for x in installed):raise AssertionError("upstream DNF did not install gzip")
    files = {str(p.relative_to(cache)): digest(p.read_bytes()) for p in cache.rglob("*") if p.is_file() and (p.suffix == ".rpm" or p.name == "repomd.xml")}
    if not any(p.endswith(".rpm") for p in files):raise AssertionError("upstream RPM byte evidence missing")
    return {"status": "PASS_OBSERVATION", "packages": sorted(installed), "observed_files": files,
        "runtime_fedora_public_roots": keys, "repository_config_sha256": digest(repo.read_bytes()),
        "stdout_stderr_sha256": digest((p.stdout + p.stderr).encode()),
        "scope": "official-Fedora-gzip-dependency-base-before-PSOP-overlay", "repo_gpgcheck_for_psop": 1,
        "fedora_metadata_openpgp_signature": "UNVERIFIED_FEDORA_DEFAULT_METALINK_MODEL",
        "independent_production_upstream_authority": "UNVERIFIED"}


def exercise(output, *, dnf, official_upstream=False):
    execution = capture()
    runtime = runtime_identity() if dnf else {"machine": platform.machine(), "dnf5": "NOT_RUN_IN_HTTPS_ONLY_MODE"}
    before_host = subprocess.check_output(["rpm", "-qa", "--qf", "%{NEVRA}\\n"], text=True) if dnf else None
    observations, clients, extra_contexts = [], [], []
    upstream = {"status": "UNVERIFIED_OFFLINE_RUN"}
    test_root = test_workspace();server = TLSFixture(test_root)
    descriptors = {}
    spec = importlib.util.spec_from_file_location("psop_baseline_rpm_fixture", ROOT / "tests/psop-offline-e2e.py")
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

    def observer(stage, values):
        context, gateway = values["context"], values["reopened"]
        if stage == "genesis":
            signed, approval, attempt = values["signed_result"], values["approval"], "local-1"
            roots = public_roots(values["roots"], values["signer"], test_root)
            client = new_client(context, server.origin, roots, server.ca);clients.append(client)
            descriptors["client"], descriptors["roots"] = client, roots
            previous = None
        else:
            signed, approval, attempt = values["s2"], values["approval2"], "local-2"
            client, roots, previous = descriptors["client"], descriptors["roots"], descriptors["first"]
        server.expose(gateway, signed, attempt)
        raw = issue_descriptor(gateway, signed, approval, attempt, origin=server.origin, now=int(time.time()), previous=previous, seconds=200)
        if stage == "genesis":descriptors["first"] = raw
        verification = client.verify(raw);shutil.rmtree(verification.path)
        negative = {}
        payload = server.public / "psop/snapshots" / signed.data["result_sha256"]
        victim = payload / "rpm/aarch64/repodata/repomd.xml"
        original = victim.read_bytes()
        victim.unlink();negative["missing_member"] = reject(lambda: client.verify(raw));victim.write_bytes(original)
        victim.write_bytes(original + b"tampered");negative["wrong_hash"] = reject(lambda: client.verify(raw));victim.write_bytes(original)
        bad_tls_client = new_client(context, server.origin, roots, None);clients.append(bad_tls_client)
        negative["untrusted_tls_ca"] = reject(lambda: bad_tls_client.verify(raw))
        wrong_tls_root = test_root / ("wrong-tls-" + stage);wrong_tls_root.mkdir()
        wrong_tls = TLSFixture(wrong_tls_root, certificate_hostname="wrong.invalid")
        try:
            wrong_client = new_client(context, wrong_tls.origin, roots, wrong_tls.ca);clients.append(wrong_client)
            d0 = strict_json(raw)["payload"]
            wrong_origin_descriptor = context.envelope("publication", {**{k: v for k, v in d0.items() if k not in {"issued_at", "expires_at"}},
                "origin": wrong_tls.origin}, now=int(time.time()), seconds=60)
            negative["trusted_wrong_hostname_certificate"] = reject(lambda: wrong_client.verify(wrong_origin_descriptor))
        finally:
            wrong_tls.close()
        if previous is not None:
            path = payload / "psop-result-v1.json";before = path.read_bytes()
            first_id = strict_json(previous)["payload"]["result_sha256"]
            path.write_bytes((server.public / "psop/snapshots" / first_id / "psop-result-v1.json").read_bytes())
            negative["mixed_generation"] = reject(lambda: client.verify(raw));path.write_bytes(before)
        # A deliberately expired, genuinely signed descriptor must fail.
        d = strict_json(raw)["payload"]
        expired = context.envelope("publication", {k: v for k, v in d.items() if k not in {"issued_at", "expires_at"}}, now=int(time.time()) - 20, seconds=10)
        negative["expired_descriptor"] = reject(lambda: client.verify(expired))
        wrong = context.envelope("publication", {**{k: v for k, v in d.items() if k not in {"issued_at", "expires_at"}}, "result_sha256": "f" * 64}, now=int(time.time()), seconds=60)
        negative["signed_wrong_result"] = reject(lambda: client.verify(wrong))
        operation = "install" if dnf else None
        packages = ["ro-control"] if stage == "genesis" else ["ro-assist", "ro-control"]
        result = client.update(raw, operation=operation, packages=packages if dnf else ())
        negative["replayed_descriptor"] = reject(lambda: client.update(raw))
        installed = None
        if dnf:
            installed = subprocess.check_output(["rpm", "--root", str(client.root / "dnf-root"), "-q", *packages,
                "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n"], text=True).splitlines()
        observations.append({"case": stage, "status": "PASS", "descriptor_sha256": digest(raw), "client": result,
            "installed_nevra": installed, "https_negatives": negative, "receipt": gateway.receipt(attempt)})
        if stage == "selected-plus-retained-successor":
            nonlocal upstream
            if dnf:
                failed_client = new_client(context, server.origin, roots, server.ca);clients.append(failed_client)
                failed_client.update(descriptors["first"])
                before = failed_client.active()
                negative["actual_dnf_transaction_failure"] = reject(lambda: failed_client.update(raw, operation="upgrade", packages=["ro-assist"]))
                assert failed_client.active() == before and (failed_client.root / "pending.json").is_file()
                negative["failed_transaction_old_view_fallback"] = reject(lambda: failed_client.update(descriptors["first"]))
                observations[-1]["dnf_defense_negatives"] = dnf_defense_negatives(values, signed, roots, test_root)
            # Reuse the same real signed source fixtures for an independent
            # contiguous PSOP chain whose installed package really upgrades.
            other = Context.create();extra_contexts.append(other)
            signer = MetadataSigner.create(other)
            extra_contexts.append(signer)
            ledger = Ledger(other, clock=lambda: int(time.time()));writer = Gateway(ledger, other)
            extra_roots = public_roots(values["roots"], signer, other.root)
            native = new_client(other, server.origin, extra_roots, server.ca);clients.append(native)
            if dnf and official_upstream:
                upstream = official_fedora_base(native)
            prev = None;prior_attempt = None
            for index, beta in enumerate((values["beta1"], values["beta2"]), 1):
                name = "native-upgrade-" + str(index)
                s, a = next_publication(values, other, signer, writer, beta, previous=prior_attempt, attempt=name)
                server.expose(writer, s, name)
                desc = issue_descriptor(writer, s, a, name, origin=server.origin, now=int(time.time()), previous=prev, seconds=200)
                result = native.update(desc, operation=("install" if index == 1 else "upgrade") if dnf else None, packages=["ro-control"] if dnf else ())
                installed = subprocess.check_output(["rpm", "--root", str(native.root / "dnf-root"), "-q", "ro-control", "--qf", "%{VERSION}"], text=True) if dnf else None
                if dnf:assert installed == str(index) + ".0"
                observations.append({"case": "native-install" if index == 1 else "native-upgrade", "status": "PASS", "client": result,
                    "installed_version": installed, "descriptor_sha256": digest(desc), "receipt": writer.receipt(name)})
                prev, prior_attempt = desc, name
    try:
        baseline = test_root / "baseline.json"
        module.main(str(baseline), observer=observer)
        if dnf:
            after_host = subprocess.check_output(["rpm", "-qa", "--qf", "%{NEVRA}\\n"], text=True)
            assert before_host == after_host, "container parent RPMDB changed outside client installroots"
        report = {"scope": "psop-fedora44-native-dnf5" if dnf else "psop-local-https-full-client", "status": "PASS",
            "runtime": runtime, "execution": execution, "cases": observations, "baseline_e2e": strict_json(baseline.read_bytes()),
            "dnf_transport": "verified-frozen-file-view-after-full-HTTPS-acquisition" if dnf else "NOT_RUN",
            "container_parent_rpmdb_preserved": "PASS" if dnf else "NOT_RUN", "aarch64_native": "UNVERIFIED",
            "official_fedora_upstream": upstream, "external_pages_https": "BLOCKED_NO_AUTHORIZED_TEST_TARGET",
            "global_cdn_freshness": "UNVERIFIED", "pages_build_ordering": "UNVERIFIED", "provider_deadline_fencing": "UNVERIFIED",
            "production_activation": "BLOCKED", "publishable": False}
        if source_inventory() != execution["source_inventory"]:
            raise AssertionError("tested source changed during acceptance")
        pathlib.Path(output).write_bytes(canonical(report) + b"\n")
        print(json.dumps(report, indent=2))
        return report
    finally:
        server.close()
        for client in clients:shutil.rmtree(client.root)
        for value in reversed(extra_contexts):
            if isinstance(value, MetadataSigner):
                subprocess.run(["gpgconf", "--homedir", str(value.home), "--kill", "gpg-agent"], capture_output=True)
            else:value.close()
        shutil.rmtree(test_root)
