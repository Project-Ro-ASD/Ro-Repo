"""Execute real DNF5 transactions against a complete, signed Fedora 44 view.

Only disposable installroots are written. Observed logs/RPMDB are bound to the
full stable result, its baseline and the actual environment. This local receipt
does not authenticate a runner, attest evidence or authorize production.
"""
import argparse
import hashlib
import json
import pathlib
import platform
import shutil
import subprocess
import tempfile

from v3_group_validation import stable_set_digest
from v3_integration import tree_inventory
from v3_policy_profile import canonical, sha
from v3_promotion_planner import PlanningError, _parse
from v3_signed_beta_history import _keyring, _signature, _verify, _json_file
from v3_stable_composer import _file_paths, _sha256
from v3_rpm_preflight import verify as verify_rpm_set


def _run(argv, *, log=None):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=600)
    if log is not None:
        log.write_text(result.stdout + result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise PlanningError("real transaction failed: " + argv[0] + ": " + result.stderr[-800:])
    return result.stdout


def _targets(packages, arch):
    relevant = [p for p in packages if p["architecture"] in {arch, "noarch"}]
    targets = {}
    for item in relevant:
        name, epoch, version, release, rpmarch = _parse(item)
        if name in targets:
            raise PlanningError("duplicate name in complete architecture view")
        targets[name] = {"target": item["nevra"], "evra": f"{epoch}:{version}-{release}.{rpmarch}"}
    if not targets:
        raise PlanningError("complete resulting view has no packages for target architecture")
    return targets


def _rpmdb(root, targets):
    actual = {}
    for name, item in sorted(targets.items()):
        actual[name] = _run(["rpm", "--root", str(root), "-q", "--qf",
                             "%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}", name]).strip()
        if actual[name] != item["evra"]:
            raise PlanningError("full-set installed EVR/architecture mismatch: " + name)
    return actual


def _config_result(config, baseline_sha256, target_sha256):
    rpmnew = pathlib.Path(str(config) + ".rpmnew")
    if rpmnew.is_symlink():
        raise PlanningError("unsafe configuration rpmnew")
    if rpmnew.is_file():
        if _sha256(rpmnew) != target_sha256:
            raise PlanningError("rpmnew differs from installed signed package header")
        return {"rpmnew_sha256": target_sha256}
    if baseline_sha256 == target_sha256:
        # RPM preserves a locally modified config without .rpmnew when the
        # packaged file itself did not change between released versions.
        return {"rpmnew_not_required_unchanged_packaged_file": True}
    raise PlanningError("changed packaged configuration missing rpmnew")


def _signed_view(root, ring):
    root = pathlib.Path(root)
    tree_inventory(root)
    manifest = _signature(root, "repository-snapshot-v1.json", ring)
    if manifest["snapshot_id"] != root.name or manifest["fedora_release"] != 44:
        raise PlanningError("signed snapshot identity mismatch")
    from ro_repo import validate_schema
    validate_schema(manifest, "repository-snapshot-v1")
    expected = set()
    for item in manifest["packages"]:
        for _, path in _file_paths(root, item):
            if _sha256(path) != item["published_signed_artifact_sha256"]:
                raise PlanningError("signed snapshot RPM byte mismatch")
            expected.add(path.relative_to(root).as_posix())
    if {p.relative_to(root).as_posix() for p in root.rglob("*.rpm")} != expected:
        raise PlanningError("unexpected RPM in complete repository view")
    for arch, info in manifest["repositories"].items():
        file = root / "rpm" / arch / "repodata/repomd.xml"
        if _sha256(file) != info["repomd_sha256"] or _sha256(pathlib.Path(str(file) + ".asc")) != info["repomd_signature_sha256"]:
            raise PlanningError("signed repodata byte mismatch")
        _verify(["gpgv", "--keyring", str(ring), str(file) + ".asc", str(file)])
    return manifest


def _rpm_set_preflight(root, manifest, key, key_sha256, output):
    """Reuse complete header/signature/SRPM-linkage checks, including sources."""
    output.mkdir()
    shutil.copytree(root / "rpm", output / "rpm")
    packages = manifest["packages"]
    candidate = sha(packages)
    group = "full-set-observation"
    files = [{"path": path.relative_to(root).as_posix(), "sha256": item["published_signed_artifact_sha256"]}
             for item in packages for _, path in _file_paths(root, item)]
    (output / "promotion-plan-v3.json").write_bytes(canonical({
        "publishable": False, "promotion_group": group, "candidate_sha256": candidate,
        "resulting_stable_packages": packages}))
    (output / "composition-v3.json").write_bytes(canonical({
        "scope": "offline-v3-untrusted-composition", "publishable": False,
        "promotion_group": group, "candidate_sha256": candidate, "files": files}))
    return verify_rpm_set(output, key, key_sha256)


def validate(snapshot, baseline, beta, plan, arch, output, *, rpm_key, rpm_key_sha256,
             metadata_key, metadata_key_sha256, config_paths=(), upstream=()):
    distro = pathlib.Path("/etc/os-release").read_text()
    if 'ID=fedora\n' not in distro or 'VERSION_ID=44\n' not in distro:
        raise PlanningError("real Fedora 44 environment required")
    if platform.machine() != arch:
        raise PlanningError("actual environment architecture mismatch")
    dnf_version = _run(["dnf", "--version"])
    if "dnf5" not in dnf_version.lower():
        raise PlanningError("real DNF5 required")
    from v3_pinned_upstream import PinnedUpstream
    upstream = tuple(upstream)
    if any(not isinstance(repo, PinnedUpstream) or repo.manifest["architecture"] != arch for repo in upstream):
        raise PlanningError("independently verified architecture-specific upstream required")
    if len({repo.manifest["repo_id"] for repo in upstream}) != len(upstream):
        raise PlanningError("duplicate pinned upstream repository identity")
    for repo in upstream:
        repo.check()
    for source in (snapshot, beta, baseline, rpm_key, metadata_key):
        if source is not None and pathlib.Path(source).is_symlink():
            raise PlanningError("symlinked DNF trust input")
    snapshot, beta = pathlib.Path(snapshot).resolve(), pathlib.Path(beta).resolve()
    baseline = None if baseline is None else pathlib.Path(baseline).resolve()
    output = pathlib.Path(output)
    if output.exists() or output.is_symlink():
        raise PlanningError("immutable DNF evidence output already exists")
    rpm_key, metadata_key = pathlib.Path(rpm_key).resolve(), pathlib.Path(metadata_key).resolve()
    rpm_bytes, metadata_bytes = rpm_key.read_bytes(), metadata_key.read_bytes()
    if hashlib.sha256(rpm_bytes).hexdigest() != rpm_key_sha256:
        raise PlanningError("unpinned RPM signing public key")
    if hashlib.sha256(metadata_bytes).hexdigest() != metadata_key_sha256:
        raise PlanningError("unpinned metadata signing public key")
    input_trees = {source: tree_inventory(source) for source in (snapshot, beta, baseline) if source is not None}
    if any(source in output.resolve().parents for source in input_trees):
        raise PlanningError("DNF evidence cannot be placed inside an input repository")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".v3-full-dnf-", dir=output.parent) as workdir:
        work = pathlib.Path(workdir)
        frozen = {}
        for index, (source, inventory) in enumerate(input_trees.items()):
            target = work / "frozen" / str(index) / source.name
            shutil.copytree(source, target, symlinks=True)
            if tree_inventory(target) != inventory:
                raise PlanningError("DNF input changed during freezing")
            frozen[source] = target
        snapshot, beta = frozen[snapshot], frozen[beta]
        baseline = None if baseline is None else frozen[baseline]
        rpm_key, metadata_key = work / "pinned-rpm-public.asc", work / "pinned-metadata-public.asc"
        rpm_key.write_bytes(rpm_bytes)
        metadata_key.write_bytes(metadata_bytes)
        ring = _keyring(metadata_key, metadata_key_sha256, work)
        manifest = _signed_view(snapshot, ring)
        beta_manifest = _signed_view(beta, ring)
        prior = None if baseline is None else _signed_view(baseline, ring)
        if plan.get("stable_base_snapshot_id") != (None if prior is None else prior["snapshot_id"]):
            raise PlanningError("DNF baseline differs from plan stable base")
        if manifest.get("parent_snapshot") != plan.get("stable_base_snapshot_id"):
            raise PlanningError("DNF result parent differs from plan stable base")
        if sorted(manifest["packages"], key=lambda x: x["nevra"]) != sorted(plan["resulting_stable_packages"], key=lambda x: x["nevra"]):
            raise PlanningError("DNF view differs from exact resulting stable set")
        targets, beta_targets = _targets(manifest["packages"], arch), _targets(beta_manifest["packages"], arch)
        from ro_repo import file_conflict_check
        rpm_paths = sorted((snapshot / "rpm" / arch).glob("*.rpm"))
        # DNF/librepo can deduplicate keys by primary fingerprint and ignore
        # the second isolated role's subkey. Enforce roles independently first,
        # then give DNF one merged *public* key with exactly the pinned roles.
        preflights = {"stable": _rpm_set_preflight(snapshot, manifest, rpm_key, rpm_key_sha256, work / "stable-preflight"),
                      "beta": _rpm_set_preflight(beta, beta_manifest, rpm_key, rpm_key_sha256, work / "beta-preflight")}
        if prior is not None:
            preflights["baseline"] = _rpm_set_preflight(baseline, prior, rpm_key, rpm_key_sha256, work / "baseline-preflight")
        merged_home = work / "dnf-public-keys"
        merged_home.mkdir(mode=0o700)
        _run(["gpg", "--no-options", "--homedir", str(merged_home), "--batch", "--import", str(rpm_key), str(metadata_key)])
        merged_key = work / "dnf-merged-public.asc"
        merged_key.write_text(_run(["gpg", "--no-options", "--homedir", str(merged_home), "--batch", "--armor", "--export"]))
        ok, conflicts = file_conflict_check(rpm_paths)
        if not ok:
            raise PlanningError("full-set file conflict: " + repr(conflicts))
        logs = work / "evidence"
        logs.mkdir()
        repos = work / "repos"
        repos.mkdir()
        upstream_ids = []
        for index, repo in enumerate(upstream):
            frozen_upstream = work / ("upstream-" + str(index))
            shutil.copytree(repo.root, frozen_upstream, symlinks=True)
            if sha(tree_inventory(frozen_upstream)) != repo.manifest["tree_sha256"]:
                raise PlanningError("upstream changed during transaction freezing")
            pinned_key = work / ("upstream-key-" + str(index) + ".asc")
            pinned_key.write_bytes(repo.public_key)
            identifier = repo.manifest["repo_id"]
            upstream_ids.append(identifier)
            (repos / (identifier + ".repo")).write_text(
                f"[{identifier}]\nname=Pinned upstream\nbaseurl=file://{frozen_upstream}\n"
                f"enabled=0\ngpgcheck=1\nrepo_gpgcheck={int(repo.manifest['metadata_authentication'] == 'gpg')}\n"
                f"skip_if_unavailable=0\ngpgkey=file://{pinned_key}\n")
        for channel, root in (("stable", snapshot), ("beta", beta), ("baseline", baseline)):
            if root is None:
                continue
            (repos / (channel + ".repo")).write_text(
                f"[ro-{channel}]\nname=V3 isolated {channel}\nbaseurl=file://{root}/rpm/{arch}\n"
                f"enabled=0\ngpgcheck=1\nrepo_gpgcheck=1\nskip_if_unavailable=0\n"
                f"gpgkey=file://{merged_key}\n")
        common = ["dnf", "-y", "--use-host-config", "--releasever=44",
                  "--setopt=reposdir=" + str(repos), "--setopt=install_weak_deps=False",
                  "--setopt=cachedir=" + str(work / "cache"), "--setopt=persistdir=" + str(work / "persist")]
        def dnf(channel, root, args, name, *, dependencies=True):
            allowed = upstream_ids if dependencies else []
            return _run(common + ["--installroot", str(root), "--repo=ro-" + channel,
                                 *["--repo=" + identifier for identifier in allowed], *args], log=logs / name)
        for channel, expected in (("stable", targets), ("beta", beta_targets)):
            result = dnf(channel, work / (channel + "-query"), ["repoquery", "--qf", "%{name}\\n"], channel + "-only.log", dependencies=False)
            if set(result.splitlines()) != set(expected):
                raise PlanningError("effective " + channel + "-only package view mismatch: " + repr(result) + " expected " + repr(sorted(expected)))
        dnf("stable", work / "clean", ["install", *[x["target"] for x in targets.values()]], "clean-install.log")
        clean = _rpmdb(work / "clean", targets)
        def dependency_inventory(installroot):
            installed = sorted(_run(["rpm", "--root", str(installroot), "-qa", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n"]).splitlines())
            approved = {p["nevra"] for repo in upstream for p in repo.manifest["packages"]} | {p["target"] for p in targets.values()}
            if any(n not in approved and not n.startswith("gpg-pubkey-") for n in installed):
                raise PlanningError("installed dependency outside independently pinned closure")
            return [n for n in installed if not n.startswith("gpg-pubkey-")]
        installed_closure = dependency_inventory(work / "clean")
        upgraded = None
        config_evidence = {}
        if prior is not None:
            old = _targets(prior["packages"], arch)
            dnf("baseline", work / "upgrade", ["install", *[x["target"] for x in old.values()]], "baseline-install.log")
            _rpmdb(work / "upgrade", old)
            for path in config_paths:
                relative = pathlib.PurePosixPath(path)
                if (not relative.is_absolute() or ".." in relative.parts or
                        not path.startswith("/etc/")):
                    raise PlanningError("unsafe configuration test path")
                config = work / "upgrade" / path.lstrip("/")
                if (config.is_symlink() or not config.is_file()
                        or not config.resolve().is_relative_to((work / "upgrade").resolve())):
                    raise PlanningError("missing baseline configuration")
                # Explicitly modify the disposable baseline's configuration
                # before DNF upgrades, then require RPM's .rpmnew behavior.
                packaged_before = _sha256(config)
                config.write_bytes(b"# locally modified V3 fixture configuration\n")
                config_evidence[path] = {"modified_sha256": _sha256(config), "baseline_packaged_sha256": packaged_before}
            # Newly approved groups are installed below; DNF5 rejects an
            # explicit upgrade argument that is available but not installed.
            installed_names = sorted(set(targets) & set(old))
            if installed_names:
                dnf("stable", work / "upgrade", ["upgrade", *[targets[n]["target"] for n in installed_names]], "upgrade.log")
            # Install genuinely new groups as well as upgrading existing ones.
            additions = set(targets) - set(old)
            if additions:
                dnf("stable", work / "upgrade", ["install", *[targets[n]["target"] for n in sorted(additions)]], "new-groups.log")
            upgraded = _rpmdb(work / "upgrade", targets)
            dependency_inventory(work / "upgrade")
            for path, evidence in config_evidence.items():
                config = work / "upgrade" / path.lstrip("/")
                if config.is_symlink() or _sha256(config) != evidence["modified_sha256"]:
                    raise PlanningError("configuration preservation/.rpmnew upgrade regression")
                declared = _run(["rpm", "--root", str(work / "upgrade"), "-qf", path,
                                 "--qf", "[%{FILENAMES}\\t%{FILEDIGESTS}\\n]"])
                matching = [line.split("\t", 1)[1] for line in declared.splitlines() if line.startswith(path + "\t")]
                if len(matching) != 1 or not __import__("re").fullmatch(r"[0-9a-f]{64}", matching[0]):
                    raise PlanningError("unambiguous installed configuration digest required")
                evidence.update(_config_result(config, evidence["baseline_packaged_sha256"], matching[0]))
        if any(tree_inventory(source) != expected or tree_inventory(frozen[source]) != expected
               for source, expected in input_trees.items()):
            raise PlanningError("DNF input changed during validation")
        for repo in upstream:
            repo.check()
        receipt = {
            "schema_version": 3, "scope": "v3-full-set-dnf-observation-test-only",
            "stable_set_sha256": stable_set_digest(plan), "result_tree_sha256": sha(tree_inventory(snapshot)),
            "baseline_tree_sha256": None if baseline is None else sha(tree_inventory(baseline)),
            "architecture": arch, "os_release_sha256": hashlib.sha256(distro.encode()).hexdigest(),
            "runtime_package_set_sha256": sha(sorted(_run(["rpm", "-qa", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n"]).splitlines())),
            "dnf_version": dnf_version.strip(), "rpmdb_clean": clean, "rpmdb_upgrade": upgraded,
            "configuration_upgrade": config_evidence,
            "upstream_manifest_sha256": {repo.manifest["repo_id"]: sha(repo.manifest) for repo in upstream},
            "installed_dependency_closure": installed_closure,
            "rpm_preflight_sha256": {name: sha(value) for name, value in preflights.items()},
            "logs_sha256": {p.name: _sha256(p) for p in logs.iterdir()},
            "checks": {"dependency-solve": "PASS", "clean-install": "PASS",
                       "upgrade": "UNVERIFIED" if prior is None else "PASS",
                       "stable-only": "PASS", "beta-only": "PASS", "file-conflict": "PASS",
                       "configuration-preservation": "PASS" if config_evidence else "UNVERIFIED",
                       "rpmnew": "PASS" if any("rpmnew_sha256" in e for e in config_evidence.values()) else "UNVERIFIED"},
            "runner_attestation": "UNVERIFIED", "publishable": False,
        }
        (logs / "full-set-dnf-v3.json").write_bytes(canonical(receipt) + b"\n")
        logs.rename(output)
    return receipt


def main():
    parser = argparse.ArgumentParser(description="Real full-set DNF5 validation in disposable Fedora 44 roots")
    for field in ("snapshot", "beta", "plan", "arch", "output", "rpm-key", "rpm-key-sha256",
                  "metadata-key", "metadata-key-sha256"):
        parser.add_argument("--" + field, required=True)
    parser.add_argument("--baseline")
    parser.add_argument("--config-path", action="append", default=[])
    a = parser.parse_args()
    print(json.dumps(validate(a.snapshot, a.baseline, a.beta, _json_file(pathlib.Path(a.plan)), a.arch, a.output,
                              rpm_key=a.rpm_key, rpm_key_sha256=a.rpm_key_sha256,
                              metadata_key=a.metadata_key, metadata_key_sha256=a.metadata_key_sha256,
                              config_paths=a.config_path), sort_keys=True))


if __name__ == "__main__":
    main()
