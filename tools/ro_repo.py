#!/usr/bin/env python3
"""Ro-Repo V2 acceptance, signing, snapshot and local publication CLI."""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, pathlib, shutil, subprocess, sys, tempfile, uuid
import jsonschema

ROOT = pathlib.Path(__file__).resolve().parents[1]

class ContractError(RuntimeError): pass

def validate_schema(data, schema_name):
    schema_path = ROOT / "schemas" / f"{schema_name}.schema.json"
    schema = load(schema_path)
    try:
        jsonschema.validate(instance=data, schema=schema, format_checker=jsonschema.FormatChecker())
    except jsonschema.ValidationError as exc:
        raise ContractError(f"schema validation failed ({schema_name}): {exc.message}") from exc

def rpmlint_check(path):
    """Run rpmlint on an RPM if available. Advisory only, never blocks acceptance."""
    try:
        result = subprocess.run(["rpmlint", str(path)], capture_output=True, text=True, timeout=60)
        return (result.returncode == 0, result.stdout.strip() or result.stderr.strip())
    except (OSError, subprocess.TimeoutExpired):
        return (True, "rpmlint not available")

def file_conflict_check(rpm_paths):
    """Check for file path conflicts across non-src RPMs in the same manifest."""
    file_owners = {}
    conflicts = []
    for path in rpm_paths:
        try:
            files = subprocess.check_output(["rpm", "-qpl", str(path)], text=True, stderr=subprocess.PIPE).strip().splitlines()
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ContractError(f"failed to query rpm contents for {path.name}: {exc}") from exc
        for f in files:
            if f in file_owners and file_owners[f] != path.name:
                conflicts.append(f"{f} owned by both {file_owners[f]} and {path.name}")
            file_owners[f] = path.name
    return (len(conflicts) == 0, conflicts)


def digest(path):
    h = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): h.update(block)
    return h.hexdigest()

def timestamp(): return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def load(path):
    try: return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc: raise ContractError(f"cannot read JSON {path}: {exc}") from exc

def save(path, value):
    path = pathlib.Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def run(argv, env=None):
    try: return subprocess.run(argv, check=True, text=True, capture_output=True, env=env)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ContractError(f"command failed: {' '.join(map(str, argv))}: {(getattr(exc, 'stderr', '') or '').strip()}") from exc

def require(obj, fields, where):
    missing = sorted(set(fields) - set(obj))
    if missing: raise ContractError(f"{where} missing fields: {', '.join(missing)}")

def verify_attestations(manifest, artifacts_dir, attestations_dir, manifest_path, trusted_workflow):
    attestations = pathlib.Path(attestations_dir)
    targets = {item["filename"]: pathlib.Path(artifacts_dir) / item["filename"] for item in manifest["artifacts"]}
    if (pathlib.Path(artifacts_dir) / "SHA256SUMS").is_file():
        targets["SHA256SUMS"] = pathlib.Path(artifacts_dir) / "SHA256SUMS"
    targets[pathlib.Path(manifest_path).name] = pathlib.Path(manifest_path)
    verified = {}
    repo = manifest["source_repository"]
    commit = manifest["source_commit"]
    for name, path in sorted(targets.items()):
        attest_path = attestations / f"{name}.json"
        if not attest_path.is_file():
            raise ContractError(f"missing attestation evidence: {name}")
        data = load(attest_path)
        if not isinstance(data, list): data = [data]
        artifact_digest = digest(path)
        
        found_valid = False
        for entry in data:
            if not isinstance(entry, dict): continue
            vr = entry.get("verificationResult", {})
            stmt = vr.get("statement", {})
            subjects = stmt.get("subject", [])
            subject_digests = [s.get("digest", {}).get("sha256") for s in subjects if isinstance(s, dict)]
            if artifact_digest not in subject_digests: continue
            
            pred = stmt.get("predicate", {})
            inv = pred.get("invocation", {})
            cs = inv.get("configSource", {})
            actual_commit = cs.get("digest", {}).get("sha1")
            
            bd = pred.get("buildDefinition", {})
            ep = bd.get("externalParameters", {})
            actual_repo = ep.get("sourceURI", "") or ep.get("repository", "")
            actual_workflow = ep.get("workflow", "")
            
            if actual_repo not in (repo, f"https://github.com/{repo}"): continue
            if actual_commit != commit: continue
            if trusted_workflow not in actual_workflow: continue
            
            found_valid = True
            break
            
        if not found_valid:
            raise ContractError(f"attestation validation failed (wrong subject, repo, commit, or workflow): {name}")
            
        verified[name] = {
            "artifact_sha256": artifact_digest,
            "source_repository": repo,
            "source_commit": commit,
            "workflow_identity": trusted_workflow,
        }
    return verified

def rpm_header(path):
    query = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%|SOURCEPACKAGE?{true}:{false}|"
    values = run(["rpm", "-qp", "--qf", query, str(path)]).stdout.split("\t")
    if len(values) != 7: raise ContractError(f"unexpected RPM header: {path}")
    name, epoch, version, release, arch, source_rpm, is_source = values
    arch = "src" if is_source == "true" else arch
    return {"name":name,"epoch":int(epoch or 0),"version":version,"release":release,"architecture":arch,
            "source_rpm":None if is_source == "true" else source_rpm,"nevra":f"{name}-{int(epoch or 0)}:{version}-{release}.{arch}"}

def verify_component(manifest_path, artifacts_dir, config_path, fedora_names=None):
    manifest, config = load(manifest_path), load(config_path)
    validate_schema(manifest, "component-artifact-manifest-v1")
    if manifest["fedora_release"] != 44: raise ContractError("only manifest v1 for Fedora 44 is accepted")
    sha = manifest["source_commit"]
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha): raise ContractError("source_commit must be an exact lowercase 40-character SHA")
    if str(manifest["release_id"]).lower() in {"", "latest", "none", "null"}: raise ContractError("exact release_id is required; latest is forbidden")
    producers = [p for p in config["producers"] if p["repository"] == manifest["source_repository"]]
    if len(producers) != 1: raise ContractError(f"producer is not allowlisted: {manifest['source_repository']}")
    producer = producers[0]; source_names=set(); headers=[]; seen=set()
    
    manifest_rpms = {item["filename"] for item in manifest["artifacts"]}
    actual_rpms = {path.name for path in pathlib.Path(artifacts_dir).glob("*.rpm")}
    if manifest_rpms != actual_rpms:
        raise ContractError(f"RPM set mismatch. Manifest has: {manifest_rpms}. Directory has: {actual_rpms}.")

    sha256sums_path = pathlib.Path(artifacts_dir) / "SHA256SUMS"
    if sha256sums_path.is_file():
        sums = {}
        for line in sha256sums_path.read_text().splitlines():
            if not line.strip(): continue
            parts = line.strip().split(maxsplit=1)
            if len(parts) == 2: sums[parts[1].strip("*")] = parts[0]
        for item in manifest["artifacts"]:
            if item["filename"] not in sums: raise ContractError(f"SHA256SUMS missing entry for {item['filename']}")
            if sums[item["filename"]] != item["producer_artifact_sha256"]: raise ContractError(f"SHA256SUMS digest mismatch for {item['filename']}")
        extra_sums = {k for k in sums.keys() if k.endswith('.rpm')} - manifest_rpms
        if extra_sums: raise ContractError(f"SHA256SUMS contains unknown RPMs: {extra_sums}")

    for item in manifest["artifacts"]:
        filename=item["filename"]
        if pathlib.PurePath(filename).name != filename or filename in seen: raise ContractError(f"unsafe or duplicate filename: {filename}")
        seen.add(filename); path=pathlib.Path(artifacts_dir)/filename
        if not path.is_file() or digest(path) != item["producer_artifact_sha256"]: raise ContractError(f"producer digest mismatch: {filename}")
        header=rpm_header(path)
        for field in ("name","epoch","version","release","architecture","source_rpm"):
            if header[field] != item[field]: raise ContractError(f"RPM header mismatch for {filename}: {field}")
        if item["name"] not in producer["allowed_package_names"]: raise ContractError(f"package name denied: {item['name']}")
        if not item["release"].endswith(".fc44"): raise ContractError(f"not a Fedora 44 build: {filename}")
        if item["architecture"] not in {"src","nosrc"} and item["architecture"] not in producer["architectures"]: raise ContractError(f"architecture denied: {item['architecture']}")
        if item["architecture"] in {"src","nosrc"}: source_names.add(filename)
        headers.append(header)
    if producer.get("srpm_required"):
        for item in manifest["artifacts"]:
            if item["architecture"] not in {"src","nosrc"} and item["source_rpm"] not in source_names: raise ContractError(f"missing matching SRPM: {item['source_rpm']}")
    if producer.get("sbom_required") and not manifest.get("sbom"): raise ContractError("SBOM required")
    names_path=pathlib.Path(fedora_names) if fedora_names else ROOT/config["fedora_package_names_file"]
    fedora=set(line.strip() for line in names_path.read_text().splitlines() if line.strip() and not line.startswith("#"))
    collision=set(producer["allowed_package_names"]) & fedora
    if collision and not producer.get("allow_fedora_override"): raise ContractError(f"Fedora package collision denied: {', '.join(sorted(collision))}")
    # --- advisory diagnostics ---
    diagnostics = {"rpmlint": [], "file_conflicts": []}
    binary_rpms = [pathlib.Path(artifacts_dir)/item["filename"] for item in manifest["artifacts"] if item["architecture"] not in {"src","nosrc"}]
    for rpm_path in binary_rpms:
        ok, output = rpmlint_check(rpm_path)
        diagnostics["rpmlint"].append({"file": rpm_path.name, "ok": ok, "output": output})
    if len(binary_rpms) > 1:
        ok, conflicts = file_conflict_check(binary_rpms)
        if not ok: raise ContractError(f"file conflicts between packages: {'; '.join(conflicts)}")
        diagnostics["file_conflicts"] = conflicts
    return manifest, headers, diagnostics

def accept(manifest_path, artifacts_dir, accepted_dir, config_path, fedora_names=None, attestations_dir=None, test_only_allow_unattested=False):
    manifest,_,diagnostics=verify_component(manifest_path,artifacts_dir,config_path,fedora_names); key=digest(manifest_path); target=pathlib.Path(accepted_dir)/key
    if target.exists(): raise ContractError(f"acceptance object exists: {key}")
    
    if not attestations_dir and not test_only_allow_unattested:
        raise ContractError("attestations are strictly required unless --test-only-allow-unattested is given")
        
    (target/"artifacts").mkdir(parents=True); shutil.copy2(manifest_path,target/"component-artifact-manifest-v1.json")
    for item in manifest["artifacts"]: shutil.copy2(pathlib.Path(artifacts_dir)/item["filename"],target/"artifacts"/item["filename"])

    verified_attestation = {}
    if attestations_dir:
        config = load(config_path)
        producers = [p for p in config["producers"] if p["repository"] == manifest["source_repository"]]
        trusted_workflow = producers[0].get("trusted_signer_workflow")
        if not trusted_workflow: raise ContractError("producer missing trusted_signer_workflow")
        verified_attestation = verify_attestations(manifest, artifacts_dir, attestations_dir, manifest_path, trusted_workflow)

    save(target/"acceptance-evidence-v1.json",{
        "schema_version":1,
        "accepted_at":timestamp(),
        "manifest_digest":key,
        "source_repository":manifest["source_repository"],
        "source_commit":manifest["source_commit"],
        "release_tag":manifest["release_tag"],
        "release_id":manifest["release_id"],
        "workflow_run":manifest["workflow_run"],
        "verified_provenance": "github_attestation_exact_match" if verified_attestation else "unattested_test_only_override",
        "verified_attestation": verified_attestation,
        "checks":["allowlist","manifest","sha256","rpm-header","fedora-release","architecture","srpm-parity","collision","provenance-exact-match","rpmlint","file-conflict"],
        "diagnostics":diagnostics
    })

def sign_packages(input_dir, output_dir, gnupghome, key_id):
    output_dir=pathlib.Path(output_dir)
    if output_dir.exists(): raise ContractError(f"output exists: {output_dir}")
    output_dir.mkdir(parents=True); env=os.environ.copy(); env["GNUPGHOME"]=str(gnupghome)
    with tempfile.TemporaryDirectory() as verify_dir:
        verify_root=pathlib.Path(verify_dir); rpmdb=verify_root/"rpmdb"; rpmdb.mkdir(); public_key=verify_root/"test-public-key.asc"
        exported=run(["gpg","--batch","--armor","--export",key_id],env).stdout
        public_key.write_text(exported,encoding="ascii"); run(["rpmkeys","--dbpath",str(rpmdb),"--import",str(public_key)])
        for source in sorted(pathlib.Path(input_dir).rglob("*.rpm")):
            target=output_dir/source.name
            if target.exists(): raise ContractError(f"duplicate RPM filename: {source.name}")
            signer=os.getenv("RO_RPMSIGN") or shutil.which("rpmsign") or "/usr/bin/rpmsign"
            shutil.copy2(source,target); run([signer,"--define",f"_gpg_name {key_id}","--define","__gpg /usr/bin/gpg","--addsign",str(target)],env); run(["rpmkeys","--dbpath",str(rpmdb),"--checksig",str(target)])
    if not list(output_dir.glob("*.rpm")): raise ContractError("no RPMs to sign")

def fingerprint(gnupghome,key_id):
    env=os.environ.copy(); env["GNUPGHOME"]=str(gnupghome)
    lines=run(["gpg","--batch","--with-colons","--fingerprint",key_id],env).stdout.splitlines(); values=[x.split(":")[9] for x in lines if x.startswith("fpr:")]
    if not values: raise ContractError("GPG fingerprint not found")
    return values[0]

def sign_file(path,gnupghome,key_id):
    env=os.environ.copy(); env["GNUPGHOME"]=str(gnupghome)
    run(["gpg","--batch","--yes","--armor","--local-user",key_id,"--detach-sign","--output",str(path)+".asc",str(path)],env)

def build_snapshot(signed_dir,manifests_dir,output,snapshot_id,gnupghome,metadata_key_id,rpm_key_id,parent=None):
    if not __import__("re").fullmatch(r"repo-f44-[0-9]{8}-[0-9]{3}",snapshot_id): raise ContractError("invalid snapshot ID")
    output=pathlib.Path(output); final=output/"snapshots/fedora/44"/snapshot_id
    if final.exists(): raise ContractError("immutable snapshot already exists")
    entries={}
    for mp in pathlib.Path(manifests_dir).rglob("component-artifact-manifest-v1.json"):
        m=load(mp)
        for item in m["artifacts"]:
            if item["filename"] in entries: raise ContractError(f"duplicate filename across manifests: {item['filename']}")
            entries[item["filename"]]=(item,digest(mp))
    if not entries: raise ContractError("no producer manifests")
    output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output) as tmp:
        stage=pathlib.Path(tmp)/snapshot_id; repos={a:stage/"rpm"/a for a in ("x86_64","aarch64","source")}
        for path in repos.values(): path.mkdir(parents=True)
        packages=[]; nevras={}
        historical={}
        for old_manifest in (output/"snapshots/fedora/44").glob("*/repository-snapshot-v1.json"):
            for old in load(old_manifest).get("packages",[]): historical[old["nevra"]]=old["producer_artifact_sha256"]
        processed_files = set()
        
        env=os.environ.copy(); env["GNUPGHOME"]=str(gnupghome)
        rpmdb=stage/"rpmdb"; rpmdb.mkdir()
        public_key=stage/"test-public-key.asc"
        exported=run(["gpg","--batch","--armor","--export",rpm_key_id],env).stdout
        public_key.write_text(exported,encoding="ascii")
        run(["rpmkeys","--dbpath",str(rpmdb),"--import",str(public_key)])
        
        for rpm in sorted(pathlib.Path(signed_dir).glob("*.rpm")):
            if rpm.name not in entries: raise ContractError(f"signed RPM absent from producer manifest: {rpm.name}")
            
            try:
                run(["rpmkeys","--dbpath",str(rpmdb),"--checksig",str(rpm)])
            except ContractError:
                raise ContractError(f"unsigned or invalid signature on RPM: {rpm.name}")

            processed_files.add(rpm.name)
            item,manifest_digest=entries[rpm.name]; header=rpm_header(rpm); signed_hash=digest(rpm)
            if header["nevra"] in historical and historical[header["nevra"]] != item["producer_artifact_sha256"]: raise ContractError(f"historical NEVRA reuse with different content: {header['nevra']}")
            if header["nevra"] in nevras and nevras[header["nevra"]] != signed_hash: raise ContractError(f"same NEVRA has different content: {header['nevra']}")
            nevras[header["nevra"]]=signed_hash
            targets=[repos["source"]] if header["architecture"]=="src" else ([repos["x86_64"],repos["aarch64"]] if header["architecture"]=="noarch" else [repos[header["architecture"]]])
            for target in targets: shutil.copy2(rpm,target/rpm.name)
            packages.append({"nevra":header["nevra"],"architecture":header["architecture"],"filename":rpm.name,"producer_artifact_sha256":item["producer_artifact_sha256"],"published_signed_artifact_sha256":signed_hash,"producer_manifest_digest":manifest_digest})
        missing = set(entries.keys()) - processed_files
        if missing: raise ContractError(f"manifest artifacts missing from signed_dir: {', '.join(sorted(missing))}")
        repodata={}
        for arch,repo in repos.items():
            run(["createrepo_c","--unique-md-filenames",str(repo)]); repomd=repo/"repodata/repomd.xml"; sign_file(repomd,gnupghome,metadata_key_id)
            repodata[arch]={"repomd_sha256":digest(repomd),"repomd_signature_sha256":digest(str(repomd)+".asc")}
        keys=stage/"keys"; keys.mkdir()
        (keys/"RPM-GPG-KEY-ro-asd-TEST-ONLY").write_text(exported,encoding="ascii")
        exported_meta = run(["gpg","--batch","--armor","--export",metadata_key_id],env).stdout
        (keys/"REPODATA-GPG-KEY-ro-asd-TEST-ONLY").write_text(exported_meta,encoding="ascii")
        rpm_fpr=fingerprint(gnupghome,rpm_key_id)
        meta_fpr=fingerprint(gnupghome,metadata_key_id)
        manifest={"schema_version":1,"snapshot_id":snapshot_id,"created_at":timestamp(),"fedora_release":44,"parent_snapshot":parent,"packages":packages,"repositories":repodata,"rpm_signing_fingerprint":rpm_fpr,"metadata_signing_fingerprint":meta_fpr,"creation_provenance":{"tool":"ro-repo-v2","run":os.getenv("GITHUB_RUN_ID","local")}}
        validate_schema(manifest, "repository-snapshot-v1")
        save(stage/"repository-snapshot-v1.json",manifest); sign_file(stage/"repository-snapshot-v1.json",gnupghome,metadata_key_id); final.parent.mkdir(parents=True,exist_ok=True); os.rename(stage,final)

def verify_snapshot(snapshot,gnupghome=None):
    snapshot=pathlib.Path(snapshot); mp=snapshot/"repository-snapshot-v1.json"; manifest=load(mp)
    validate_schema(manifest, "repository-snapshot-v1")
    if manifest["snapshot_id"] != snapshot.name or "target_channel" in manifest: raise ContractError("snapshot identity/lifecycle separation invalid")
    env=os.environ.copy()
    if gnupghome: env["GNUPGHOME"]=str(gnupghome)
    def verify_gpg_signature(file_path, asc_path, expected_fingerprint, env):
        out = run(["gpg", "--status-fd", "1", "--verify", str(asc_path), str(file_path)], env).stdout
        for line in out.splitlines():
            if line.startswith("[GNUPG:] VALIDSIG "):
                if line.split()[2] == expected_fingerprint:
                    return
        raise ContractError(f"GPG signature verification error: wrong key used for {file_path}")

    verify_gpg_signature(mp, str(mp)+".asc", manifest["metadata_signing_fingerprint"], env)
    
    with tempfile.TemporaryDirectory() as tmp:
        rpmdb=pathlib.Path(tmp)/"rpmdb"; rpmdb.mkdir()
        keys = list((snapshot/"keys").glob("RPM-GPG-KEY-*"))
        for k in keys: run(["rpmkeys","--dbpath",str(rpmdb),"--import",str(k)])
        
        noarch_x86 = {}
        
        for arch,info in manifest["repositories"].items():
            repomd=snapshot/"rpm"/arch/"repodata/repomd.xml"
            if digest(repomd)!=info["repomd_sha256"] or digest(str(repomd)+".asc")!=info["repomd_signature_sha256"]: raise ContractError(f"repodata digest mismatch: {arch}")
            verify_gpg_signature(repomd, str(repomd)+".asc", manifest["metadata_signing_fingerprint"], env)
        for item in manifest["packages"]:
            arch="source" if item["architecture"]=="src" else ("x86_64" if item["architecture"]=="noarch" else item["architecture"])
            rpm=snapshot/"rpm"/arch/item["filename"]
            d = digest(rpm)
            if d!=item["published_signed_artifact_sha256"]: raise ContractError(f"signed RPM digest mismatch: {item['filename']}")
            
            try:
                run(["rpmkeys","--dbpath",str(rpmdb),"--checksig",str(rpm)])
            except ContractError:
                raise ContractError(f"RPM signature validation failed: {rpm.name}")
                
            if item["architecture"] == "noarch":
                noarch_x86[item["filename"]] = d
                
        for filename, d in noarch_x86.items():
            aarch_rpm=snapshot/"rpm/aarch64"/filename
            if not aarch_rpm.is_file() or digest(aarch_rpm)!=d:
                raise ContractError(f"noarch aarch64 copy mismatch: {filename}")
            
    return manifest

def publish(output,snapshot_id,channel,run_id="local",gnupghome=None):
    if channel not in {"beta","stable"}: raise ContractError("only beta/stable channels exist")
    if not __import__("re").fullmatch(r"repo-f44-[0-9]{8}-[0-9]{3}",snapshot_id): raise ContractError("invalid snapshot ID schema")
    output=pathlib.Path(output); snapshot=output/"snapshots/fedora/44"/snapshot_id; verify_snapshot(snapshot,gnupghome)
    base=output/"publication/rpm/fedora/44"; target=base/channel; stage=base/f".data-{uuid.uuid4().hex}"; stage.mkdir(parents=True)
    for arch in ("x86_64","aarch64","source"):
        source=snapshot/"rpm"/arch; dest=stage/arch; shutil.copytree(source,dest)
        repomd=dest/"repodata/repomd.xml"; sig=dest/"repodata/repomd.xml.asc"; repomd_bytes=repomd.read_bytes(); sig_bytes=sig.read_bytes(); repomd.unlink(); sig.unlink(); sig.write_bytes(sig_bytes); repomd.write_bytes(repomd_bytes)
    pub_manifest = {"schema_version":1,"channel":channel,"snapshot_id":snapshot_id,"published_at":timestamp(),"publication_run":run_id}
    validate_schema(pub_manifest, "publication-v1")
    save(stage/"publication-v1.json", pub_manifest)
    if gnupghome:
        sign_file(stage/"publication-v1.json", gnupghome, load(snapshot/"repository-snapshot-v1.json")["metadata_signing_fingerprint"])
    
    # Atomic symlink swap
    previous = base/f".{channel}-previous"
    if target.is_symlink():
        current_target = target.resolve()
        tmp_prev = base/f".tmp-prev-{uuid.uuid4().hex}"
        tmp_prev.symlink_to(current_target.name)
        os.replace(tmp_prev, previous)
        
    symlink_target = stage.name
    tmp_link = base/f".tmp-link-{uuid.uuid4().hex}"
    tmp_link.symlink_to(symlink_target)
    os.replace(tmp_link, target)


def promote(output,promotion_path,run_id,gnupghome=None):
    p=load(promotion_path)
    validate_schema(p, "promotion-manifest-v1")
    if p["from"]!="beta" or p["to"]!="stable" or not p["evidence"]: raise ContractError("invalid or evidence-free promotion")
    if p["emergency"] and not str(p.get("reason", "")).strip(): raise ContractError("emergency promotion requires a non-empty reason")

    beta_path = pathlib.Path(output)/"publication/rpm/fedora/44/beta/publication-v1.json"
    if not beta_path.is_file(): raise ContractError("no beta publication exists")
    if gnupghome:
        env=os.environ.copy(); env["GNUPGHOME"]=str(gnupghome)
        run(["gpg","--verify",str(beta_path)+".asc",str(beta_path)],env)
    beta = load(beta_path)
    if beta["snapshot_id"] != p["snapshot_id"]: raise ContractError("snapshot is not the current beta publication")

    age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(beta["published_at"].replace("Z", "+00:00"))

    snapshot_path = pathlib.Path(output) / "snapshots/fedora/44" / p["snapshot_id"] / "repository-snapshot-v1.json"
    snapshot_manifest = load(snapshot_path)
    config = load(ROOT / "config/producers-v1.yaml")

    risk_map = {}
    group_map = {}
    for prod in config["producers"]:
        for pkg in prod["allowed_package_names"]:
            risk_map[pkg] = prod["risk_class"]
            if "promotion_group" in prod:
                group_map[pkg] = prod["promotion_group"]

    highest_risk = "normal-app"
    expected_groups = set()
    for pkg in snapshot_manifest["packages"]:
        name = pkg["nevra"].rsplit("-", 2)[0]
        pkg_risk = risk_map.get(name, "normal-app")
        if pkg_risk == "critical-system":
            highest_risk = "critical-system"
        elif pkg_risk == "critical-desktop" and highest_risk != "critical-system":
            highest_risk = "critical-desktop"
        if name in group_map:
            expected_groups.add(group_map[name])

    if p["risk_class"] != highest_risk: raise ContractError(f"spoofed risk_class: claimed {p['risk_class']}, actual is {highest_risk}")

    if not expected_groups:
        raise ContractError("no promotion_group found in producer config")
        
    expected_groups_sorted = sorted(list(expected_groups))
    claimed_groups = p.get("promotion_groups", [p.get("promotion_group")] if p.get("promotion_group") else [])
    if sorted(claimed_groups) != expected_groups_sorted:
        raise ContractError(f"spoofed promotion_groups: claimed {claimed_groups}, actual expected exactly {expected_groups_sorted}")

    minimum = 14 if highest_risk == "critical-system" else 7
    if not p["emergency"] and age < dt.timedelta(days=minimum): raise ContractError(f"minimum beta duration is {minimum} days")

    required_tests = {"dependency-solve", "clean-install", "upgrade", "file-conflict", "rpmlint", "smoke"}
    if highest_risk == "critical-desktop": required_tests.update({"plasma-integration", "login-session"})
    if highest_risk == "critical-system": required_tests.update({"boot", "reboot", "recovery", "qemu"})

    provided_evidence = set()
    for ev in p["evidence"]:
        if not isinstance(ev, dict) or "name" not in ev or "result" not in ev or "snapshot_id" not in ev:
            raise ContractError("evidence must be detailed records, not just strings")
        if "reference" not in ev or "digest" not in ev:
            raise ContractError("evidence must include reference and digest")
        
        ref_path = (pathlib.Path(output) / ev["reference"]).resolve()
        evidence_root = (pathlib.Path(output) / "evidence").resolve()
        try:
            ref_path.relative_to(evidence_root)
        except ValueError:
            raise ContractError("path traversal in evidence reference")
        if not ref_path.is_file(): raise ContractError("evidence reference file missing")
        if digest(ref_path) != ev["digest"]: raise ContractError("evidence reference digest mismatch")
        
        ref_data = load(ref_path)
        if ref_data.get("snapshot_id") != p["snapshot_id"]: raise ContractError("evidence content snapshot mismatch")
        if ref_data.get("result") != "pass": raise ContractError("evidence content result not pass")
        
        if ev["result"] != "pass": raise ContractError(f"evidence {ev['name']} did not pass")
        if ev["snapshot_id"] != p["snapshot_id"]: raise ContractError(f"evidence {ev['name']} is for wrong snapshot")
        provided_evidence.add(ev["name"])

    missing = required_tests - provided_evidence
    if missing and not p["emergency"]: raise ContractError(f"promotion evidence missing: {', '.join(sorted(missing))}")

    evidence_dir = pathlib.Path(output) / "evidence/promotions" / p["snapshot_id"]
    evidence_dir.mkdir(parents=True, exist_ok=True)
    groups_str = "-".join(sorted(p["promotion_groups"]))
    shutil.copy2(promotion_path, evidence_dir / f"{groups_str}.json")
    publish(output, p["snapshot_id"], "stable", run_id, gnupghome)

def rollback(output,channel):
    if channel not in {"beta","stable"}: raise ContractError("only beta/stable channels exist")
    base=pathlib.Path(output)/"publication/rpm/fedora/44"; target=base/channel; previous=base/f".{channel}-previous"
    if not target.is_symlink() or not previous.is_symlink(): raise ContractError(f"no previous {channel} publication or not symlink")
    
    current_target = target.resolve()
    previous_target = previous.resolve()
    
    # Swap pointers
    tmp_link = base/f".tmp-link-{uuid.uuid4().hex}"
    tmp_link.symlink_to(previous_target.name)
    os.replace(tmp_link, target)
    
    tmp_link_prev = base/f".tmp-link-{uuid.uuid4().hex}"
    tmp_link_prev.symlink_to(current_target.name)
    os.replace(tmp_link_prev, previous)
    
    return load(target/"publication-v1.json")["snapshot_id"]

def catalog(snapshot,editorial,out,gnupghome):
    manifest=verify_snapshot(snapshot,gnupghome); metadata=load(editorial) if editorial else {"apps":{}}; grouped={}
    for item in manifest["packages"]:
        if item["architecture"]!="src": grouped.setdefault(item["nevra"].split("-0:",1)[0],[]).append(item)
    apps=[]
    for name,items in sorted(grouped.items()):
        value=dict(metadata.get("apps",{}).get(name,{})); nevra=items[0]["nevra"]; value.update({"packageName":name,"latestVersion":nevra.split(":",1)[1].rsplit("-",1)[0],"architectures":sorted({x["architecture"] for x in items})}); apps.append(value)
    save(out,{"schemaVersion":2,"snapshotId":manifest["snapshot_id"],"apps":apps})

def cli():
    p=argparse.ArgumentParser(); s=p.add_subparsers(dest="command",required=True)
    def component(name):
        x=s.add_parser(name); x.add_argument("--manifest",type=pathlib.Path,required=True); x.add_argument("--artifacts",type=pathlib.Path,required=True); x.add_argument("--config",type=pathlib.Path,default=ROOT/"config/producers-v1.yaml"); x.add_argument("--fedora-names",type=pathlib.Path); return x
    component("verify-component"); x=component("accept-package"); x.add_argument("--accepted",type=pathlib.Path,required=True); x.add_argument("--attestations",type=pathlib.Path); x.add_argument("--test-only-allow-unattested",action="store_true")
    x=s.add_parser("sign-package"); x.add_argument("--input",type=pathlib.Path,required=True); x.add_argument("--output",type=pathlib.Path,required=True); x.add_argument("--gnupghome",type=pathlib.Path,required=True); x.add_argument("--key-id",required=True)
    x=s.add_parser("build-snapshot"); x.add_argument("--signed",type=pathlib.Path,required=True); x.add_argument("--manifests",type=pathlib.Path,required=True); x.add_argument("--output",type=pathlib.Path,required=True); x.add_argument("--snapshot-id",required=True); x.add_argument("--gnupghome",type=pathlib.Path,required=True); x.add_argument("--rpm-key-id",required=True); x.add_argument("--metadata-key-id",required=True); x.add_argument("--parent")
    x=s.add_parser("verify-snapshot"); x.add_argument("--snapshot",type=pathlib.Path,required=True); x.add_argument("--gnupghome",type=pathlib.Path)
    x=s.add_parser("publish-local"); x.add_argument("--output",type=pathlib.Path,required=True); x.add_argument("--snapshot-id",required=True); x.add_argument("--channel",choices=["beta","stable"],required=True); x.add_argument("--publication-run",default="local"); x.add_argument("--gnupghome",type=pathlib.Path,required=True)
    x=s.add_parser("promote-snapshot"); x.add_argument("--output",type=pathlib.Path,required=True); x.add_argument("--promotion",type=pathlib.Path,required=True); x.add_argument("--publication-run",default="local"); x.add_argument("--gnupghome",type=pathlib.Path,required=True)
    x=s.add_parser("rollback-publication"); x.add_argument("--output",type=pathlib.Path,required=True); x.add_argument("--channel",choices=["beta","stable"],required=True)
    x=s.add_parser("generate-catalog"); x.add_argument("--snapshot",type=pathlib.Path,required=True); x.add_argument("--editorial",type=pathlib.Path); x.add_argument("--output",type=pathlib.Path,required=True); x.add_argument("--gnupghome",type=pathlib.Path,required=True)
    return p.parse_args()

def main():
    a=cli()
    try:
        if a.command=="verify-component": verify_component(a.manifest,a.artifacts,a.config,a.fedora_names)
        elif a.command=="accept-package": accept(a.manifest,a.artifacts,a.accepted,a.config,a.fedora_names,a.attestations,a.test_only_allow_unattested)
        elif a.command=="sign-package": sign_packages(a.input,a.output,a.gnupghome,a.key_id)
        elif a.command=="build-snapshot": build_snapshot(a.signed,a.manifests,a.output,a.snapshot_id,a.gnupghome,a.metadata_key_id,a.rpm_key_id,a.parent)
        elif a.command=="verify-snapshot": verify_snapshot(a.snapshot,a.gnupghome)
        elif a.command=="publish-local": publish(a.output,a.snapshot_id,a.channel,a.publication_run,a.gnupghome)
        elif a.command=="promote-snapshot": promote(a.output,a.promotion,a.publication_run,a.gnupghome)
        elif a.command=="rollback-publication": print(f"rolled back to: {rollback(a.output,a.channel)}")
        elif a.command=="generate-catalog": catalog(a.snapshot,a.editorial,a.output,a.gnupghome)
        print(f"ok: {a.command}"); return 0
    except ContractError as exc: print(f"error: {exc}",file=sys.stderr); return 2

if __name__=="__main__": raise SystemExit(main())
