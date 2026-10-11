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
import subprocess
import tempfile

from v3_group_validation import stable_set_digest
from v3_integration import tree_inventory
from v3_policy_profile import canonical, sha
from v3_promotion_planner import PlanningError, _parse
from v3_signed_beta_history import _keyring, _signature, _verify, _json_file
from v3_stable_composer import _file_paths, _sha256


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


def validate(snapshot, baseline, beta, plan, arch, output, *, rpm_key, rpm_key_sha256,
             metadata_key, metadata_key_sha256, config_paths=()):
    distro = pathlib.Path("/etc/os-release").read_text()
    if 'ID=fedora\n' not in distro or 'VERSION_ID=44\n' not in distro:
        raise PlanningError("real Fedora 44 environment required")
    if platform.machine() != arch:
        raise PlanningError("actual environment architecture mismatch")
    dnf_version = _run(["dnf", "--version"])
    if "dnf5" not in dnf_version.lower():
        raise PlanningError("real DNF5 required")
    for source in (snapshot, beta, baseline, rpm_key, metadata_key):
        if source is not None and pathlib.Path(source).is_symlink():
            raise PlanningError("symlinked DNF trust input")
    snapshot, beta = pathlib.Path(snapshot).resolve(), pathlib.Path(beta).resolve()
    baseline = None if baseline is None else pathlib.Path(baseline).resolve()
    output = pathlib.Path(output)
    if output.exists() or output.is_symlink():
        raise PlanningError("immutable DNF evidence output already exists")
    rpm_key, metadata_key = pathlib.Path(rpm_key).resolve(), pathlib.Path(metadata_key).resolve()
    if _sha256(rpm_key) != rpm_key_sha256:
        raise PlanningError("unpinned RPM signing public key")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".v3-full-dnf-", dir=output.parent) as workdir:
        work = pathlib.Path(workdir)
        ring = _keyring(metadata_key, metadata_key_sha256, work)
        manifest = _signed_view(snapshot, ring)
        beta_manifest = _signed_view(beta, ring)
        prior = None if baseline is None else _signed_view(baseline, ring)
        if sorted(manifest["packages"], key=lambda x: x["nevra"]) != sorted(plan["resulting_stable_packages"], key=lambda x: x["nevra"]):
            raise PlanningError("DNF view differs from exact resulting stable set")
        targets, beta_targets = _targets(manifest["packages"], arch), _targets(beta_manifest["packages"], arch)
        from ro_repo import file_conflict_check, verify_signed_rpms
        rpm_paths = sorted((snapshot / "rpm" / arch).glob("*.rpm"))
        # DNF/librepo can deduplicate keys by primary fingerprint and ignore
        # the second isolated role's subkey. Enforce roles independently first,
        # then give DNF one merged *public* key with exactly the pinned roles.
        verify_signed_rpms(rpm_paths, rpm_key)
        verify_signed_rpms(sorted((beta / "rpm" / arch).glob("*.rpm")), rpm_key)
        if baseline is not None:
            verify_signed_rpms(sorted((baseline / "rpm" / arch).glob("*.rpm")), rpm_key)
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
        def dnf(channel, root, args, name):
            return _run(common + ["--installroot", str(root), "--repo=ro-" + channel, *args], log=logs / name)
        for channel, expected in (("stable", targets), ("beta", beta_targets)):
            result = dnf(channel, work / (channel + "-query"), ["repoquery", "--qf", "%{name}\\n"], channel + "-only.log")
            if set(result.splitlines()) != set(expected):
                raise PlanningError("effective " + channel + "-only package view mismatch: " + repr(result) + " expected " + repr(sorted(expected)))
        dnf("stable", work / "clean", ["install", *[x["target"] for x in targets.values()]], "clean-install.log")
        clean = _rpmdb(work / "clean", targets)
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
                config.write_bytes(b"# locally modified V3 fixture configuration\n")
                config_evidence[path] = {"modified_sha256": _sha256(config)}
            dnf("stable", work / "upgrade", ["upgrade", *sorted(targets)], "upgrade.log")
            # Install genuinely new groups as well as upgrading existing ones.
            additions = set(targets) - set(old)
            if additions:
                dnf("stable", work / "upgrade", ["install", *sorted(additions)], "new-groups.log")
            upgraded = _rpmdb(work / "upgrade", targets)
            for path, evidence in config_evidence.items():
                config = work / "upgrade" / path.lstrip("/")
                rpmnew = pathlib.Path(str(config) + ".rpmnew")
                if _sha256(config) != evidence["modified_sha256"] or not rpmnew.is_file():
                    raise PlanningError("configuration preservation/.rpmnew upgrade regression")
                evidence["rpmnew_sha256"] = _sha256(rpmnew)
        receipt = {
            "schema_version": 3, "scope": "v3-full-set-dnf-observation-test-only",
            "stable_set_sha256": stable_set_digest(plan), "result_tree_sha256": sha(tree_inventory(snapshot)),
            "baseline_tree_sha256": None if baseline is None else sha(tree_inventory(baseline)),
            "architecture": arch, "os_release_sha256": hashlib.sha256(distro.encode()).hexdigest(),
            "runtime_package_set_sha256": sha(sorted(_run(["rpm", "-qa", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n"]).splitlines())),
            "dnf_version": dnf_version.strip(), "rpmdb_clean": clean, "rpmdb_upgrade": upgraded,
            "configuration_upgrade": config_evidence,
            "logs_sha256": {p.name: _sha256(p) for p in logs.iterdir()},
            "checks": {"dependency-solve": "PASS", "clean-install": "PASS",
                       "upgrade": "UNVERIFIED" if prior is None else "PASS",
                       "stable-only": "PASS", "beta-only": "PASS", "file-conflict": "PASS",
                       "rpmnew": "PASS" if config_evidence else "UNVERIFIED"},
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
