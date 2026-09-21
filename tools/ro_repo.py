#!/usr/bin/env python3
"""Ro-Repo V2 acceptance, signing, snapshot and local publication CLI."""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, pathlib, re, shlex, shutil, stat, subprocess, sys, tempfile, uuid
import jsonschema

ROOT = pathlib.Path(__file__).resolve().parents[1]

class ContractError(RuntimeError):
    """Fail-closed contract violation with safe diagnostic metadata."""

    def __init__(self, message, *, code="INTERNAL_ACCEPTANCE_ERROR", stage="acceptance",
                 expected=None, received=None, hint=None):
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.expected = expected
        self.received = received
        self.hint = hint


REPORT_IDENTITY_FIELDS = (
    "source_repository", "release_tag", "source_commit", "release_id", "workflow_run"
)
CALLER_IDENTITY_FIELDS = (
    "source_repository", "release_tag", "source_commit", "release_id"
)


def _normalize_numeric_identity(value):
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value):
        return int(value)
    return None


def normalize_acceptance_identity(values):
    """Return schema-safe release identity values without trusting input types."""
    if not isinstance(values, dict):
        values = {}
    identity = {
        field: values.get(field) if isinstance(values.get(field), str) else None
        for field in ("source_repository", "release_tag", "source_commit")
    }
    identity["release_id"] = _normalize_numeric_identity(values.get("release_id"))
    identity["workflow_run"] = _normalize_numeric_identity(values.get("workflow_run"))
    return identity


def acceptance_identity(manifest_path):
    """Read only the non-secret identity fields needed by an acceptance report."""
    try:
        data = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {field: None for field in REPORT_IDENTITY_FIELDS}
    return normalize_acceptance_identity(data)


def acceptance_report_identity(manifest_path, expected=None):
    """Prefer caller-verified release identity while safely reading workflow_run."""
    identity = acceptance_identity(manifest_path)
    normalized_expected = normalize_acceptance_identity(expected)
    if isinstance(expected, dict):
        for field in CALLER_IDENTITY_FIELDS:
            if expected.get(field) is not None:
                identity[field] = normalized_expected[field]
    return identity


def _redact_report_value(value):
    """Defence in depth: remove secret environment values from diagnostic text."""
    if value is None or isinstance(value, (int, bool)):
        return value
    if isinstance(value, list):
        return [_redact_report_value(item) for item in value]
    text = str(value)
    for name, secret in os.environ.items():
        if secret and len(secret) >= 4 and re.search(r"TOKEN|SECRET|PASS|PASSWORD|KEY|CREDENTIAL|AUTH", name, re.I):
            text = text.replace(secret, "[REDACTED]")
    return text


def write_acceptance_report(path, result, identity, error=None):
    identity = normalize_acceptance_identity(identity)
    report = {
        "schema_version": 1,
        "result": result,
        "timestamp": timestamp(),
        "producer_repository": _redact_report_value(identity.get("source_repository")),
        "release_tag": _redact_report_value(identity.get("release_tag")),
        "source_commit": _redact_report_value(identity.get("source_commit")),
        "release_id": _redact_report_value(identity.get("release_id")),
        "workflow_run": _redact_report_value(identity.get("workflow_run")),
        "failed_stage": error.stage if error else None,
        "error_code": error.code if error else None,
        "error_message": _redact_report_value(str(error)) if error else None,
        "expected": _redact_report_value(error.expected) if error else None,
        "received": _redact_report_value(error.received) if error else None,
        "remediation_hint": _redact_report_value(error.hint) if error else None,
    }
    validate_schema(report, "acceptance-report-v1")
    save(path, report)
    return report


def verify_expected_identity(manifest_path, expected):
    """Bind the producer manifest to caller-verified release identity values."""
    if not expected:
        return
    identity = acceptance_identity(manifest_path)
    comparisons = (
        ("source_repository", "MANIFEST_IDENTITY_MISMATCH", "manifest-identity"),
        ("release_tag", "MANIFEST_IDENTITY_MISMATCH", "manifest-identity"),
        ("source_commit", "TAG_COMMIT_MISMATCH", "tag-commit"),
        ("release_id", "RELEASE_ID_MISMATCH", "release-id"),
    )
    for field, code, stage in comparisons:
        wanted = expected.get(field)
        actual = identity.get(field)
        if wanted is not None and str(actual) != str(wanted):
            raise ContractError(
                f"manifest {field} mismatch", code=code, stage=stage,
                expected=wanted, received=actual,
                hint="Verify the exact tag, commit, and numeric release ID, then publish a corrected immutable release.",
            )

def write_snapshot_input(path, signing_runs):
    """Write a schema-valid exact signing-run input without shell JSON assembly."""
    if not isinstance(signing_runs, str):
        raise ContractError("snapshot signing runs must be a comma-separated string")

    run_ids = []
    seen = set()
    for raw in signing_runs.split(","):
        token = raw.strip()
        run_id = _normalize_numeric_identity(token)
        if run_id is None:
            raise ContractError(f"invalid signing workflow run ID: {token!r}")
        if run_id in seen:
            raise ContractError(f"duplicate signing workflow run ID: {run_id}")
        seen.add(run_id)
        run_ids.append(run_id)

    if not run_ids:
        raise ContractError("snapshot input contains no signing workflow runs")

    data = {
        "schema_version": 1,
        "runs": [{"run_id": run_id} for run_id in run_ids],
    }
    validate_schema(data, "snapshot-input-v1")
    save(path, data)
    return data


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
    """Check for file path conflicts among RPMs that can coexist in one repo."""
    file_owners = {}
    conflicts = []
    for path in rpm_paths:
        try:
            files = subprocess.check_output(["rpm", "-qpl", str(path)], text=True, stderr=subprocess.PIPE).strip().splitlines()
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ContractError(
                f"failed to query rpm contents for {path.name}: {exc}",
                code="RPM_HEADER_MISMATCH", stage="rpm-content", received=path.name,
                hint="Publish a readable, valid RPM artifact.",
            ) from exc
        for f in files:
            if f in file_owners and file_owners[f] != path.name:
                conflicts.append(f"{f} owned by both {file_owners[f]} and {path.name}")
            file_owners[f] = path.name
    return (len(conflicts) == 0, conflicts)


def repository_file_conflict_check(rpm_entries):
    """Check only RPM combinations that can coexist in the same binary repository.

    x86_64 and aarch64 packages are published to separate repositories, while
    noarch packages are copied into both. Cross-architecture variants therefore
    must not be treated as conflicting with one another.
    """
    repo_rpms = {"x86_64": [], "aarch64": []}
    for path, architecture in rpm_entries:
        if architecture == "noarch":
            for paths in repo_rpms.values():
                paths.append(path)
        elif architecture in repo_rpms:
            repo_rpms[architecture].append(path)

    conflicts = []
    for architecture, paths in sorted(repo_rpms.items()):
        if len(paths) < 2:
            continue
        ok, repo_conflicts = file_conflict_check(paths)
        if not ok:
            conflicts.extend(f"{architecture}: {conflict}" for conflict in repo_conflicts)
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

def verify_attestations(manifest, artifacts_dir, manifest_path, trusted_workflow):
    targets = {item["filename"]: pathlib.Path(artifacts_dir) / item["filename"] for item in manifest["artifacts"]}
    if (pathlib.Path(artifacts_dir) / "SHA256SUMS").is_file():
        targets["SHA256SUMS"] = pathlib.Path(artifacts_dir) / "SHA256SUMS"
    targets[pathlib.Path(manifest_path).name] = pathlib.Path(manifest_path)
    verified = {}
    repo = manifest["source_repository"]
    commit = manifest["source_commit"]
    for name, path in sorted(targets.items()):
        try:
            run(["gh", "attestation", "verify", str(path), "--repo", repo, "--source-digest", commit, "--signer-workflow", trusted_workflow, "--deny-self-hosted-runners"])
        except Exception:
            raise ContractError(
                f"attestation validation failed (gh cli rejection): {name}",
                code="PROVENANCE_MISMATCH", stage="provenance",
                hint="Regenerate the release asset and GitHub attestation from the trusted workflow.",
            )
        verified[name] = {
            "artifact_sha256": digest(path),
            "source_repository": repo,
            "source_commit": commit,
            "workflow_identity": trusted_workflow,
        }
    return verified

def rpm_header(path):
    query = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%|SOURCEPACKAGE?{true}:{false}|"
    try:
        values = run(["rpm", "-qp", "--qf", query, str(path)]).stdout.split("\t")
    except ContractError as exc:
        raise ContractError(
            f"failed to read RPM header: {path}", code="RPM_HEADER_MISMATCH",
            stage="rpm-header", received=pathlib.Path(path).name,
            hint="Publish a readable RPM with headers matching the manifest.",
        ) from exc
    if len(values) != 7: raise ContractError(f"unexpected RPM header: {path}", code="RPM_HEADER_MISMATCH", stage="rpm-header", received=pathlib.Path(path).name, hint="Publish a valid RPM with complete headers.")
    name, epoch, version, release, arch, source_rpm, is_source = values
    arch = "src" if is_source == "true" else arch
    return {"name":name,"epoch":int(epoch or 0),"version":version,"release":release,"architecture":arch,
            "source_rpm":None if is_source == "true" else source_rpm,"nevra":f"{name}-{int(epoch or 0)}:{version}-{release}.{arch}"}

def verify_component(manifest_path, artifacts_dir, config_path, fedora_names_path=None, test_only_allow_empty_fedora=False, test_only_allow_missing_sha256sums=False):
    try:
        manifest = load(manifest_path)
    except ContractError as exc:
        raise ContractError(
            str(exc), code="MANIFEST_IDENTITY_MISMATCH", stage="manifest-schema",
            hint="Publish valid JSON matching the versioned component manifest schema.",
        ) from exc
    config = load(config_path)
    source_commit = manifest.get("source_commit") if isinstance(manifest, dict) else None
    if not isinstance(source_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ContractError(
            "source_commit must be an exact lowercase 40-character SHA",
            code="TAG_COMMIT_MISMATCH", stage="tag-commit",
            expected="exact lowercase 40-character commit SHA", received=source_commit,
            hint="Publish the manifest with the exact commit referenced by the immutable release tag.",
        )
    release_id = manifest.get("release_id") if isinstance(manifest, dict) else None
    if _normalize_numeric_identity(release_id) is None:
        raise ContractError(
            "exact positive numeric release_id is required; latest is forbidden",
            code="RELEASE_ID_MISMATCH", stage="release-id",
            expected="exact numeric GitHub release ID", received=release_id,
            hint="Use the numeric ID of the exact immutable GitHub release.",
        )
    if isinstance(manifest, dict) and manifest.get("fedora_release") != 44:
        raise ContractError(
            "only manifest v1 for Fedora 44 is accepted", code="FEDORA_RELEASE_MISMATCH",
            stage="fedora-release", expected=44, received=manifest.get("fedora_release"),
            hint="Build and publish the component for Fedora 44.",
        )
    try:
        validate_schema(manifest, "component-artifact-manifest-v1")
    except ContractError as exc:
        raise ContractError(
            str(exc), code="MANIFEST_IDENTITY_MISMATCH", stage="manifest-schema",
            hint="Regenerate the component manifest from the versioned v1 schema.",
        ) from exc
    producers = [p for p in config["producers"] if p["repository"] == manifest["source_repository"]]
    if len(producers) != 1:
        raise ContractError(
            f"producer is not allowlisted: {manifest['source_repository']}",
            code="PRODUCER_NOT_ALLOWLISTED", stage="allowlist",
            received=manifest["source_repository"],
            hint="Add the producer through the reviewed producer-registry process before retrying.",
        )
    producer = producers[0]; source_names=set(); headers=[]; seen=set()
    
    manifest_rpms = {item["filename"] for item in manifest["artifacts"]}
    actual_rpms = {path.name for path in pathlib.Path(artifacts_dir).glob("*.rpm")}
    if manifest_rpms != actual_rpms:
        raise ContractError(
            f"RPM set mismatch. Manifest has: {manifest_rpms}. Directory has: {actual_rpms}.",
            code="ARTIFACT_SET_MISMATCH", stage="artifact-set",
            expected=sorted(manifest_rpms), received=sorted(actual_rpms),
            hint="Publish exactly the RPM set declared by the manifest.",
        )

    sha256sums_path = pathlib.Path(artifacts_dir) / "SHA256SUMS"
    if not sha256sums_path.is_file() and not test_only_allow_missing_sha256sums:
        raise ContractError(
            "SHA256SUMS file is strictly required in production", code="SHA256SUMS_INVALID",
            stage="sha256sums", expected="SHA256SUMS", received=None,
            hint="Publish a strict SHA256SUMS file for every declared RPM.",
        )
    
    if sha256sums_path.is_file():
        sums = {}
        for line in sha256sums_path.read_text().splitlines():
            if not line.strip(): continue
            parts = line.strip().split(maxsplit=1)
            if len(parts) != 2: raise ContractError(f"malformed line in SHA256SUMS: {line}", code="SHA256SUMS_INVALID", stage="sha256sums", hint="Regenerate SHA256SUMS in the producer release workflow.")
            h, fname = parts[0], parts[1].strip("*")
            if not __import__("re").fullmatch(r"^[a-f0-9]{64}$", h): raise ContractError(f"malformed SHA256 hash: {h}", code="SHA256SUMS_INVALID", stage="sha256sums", received=h, hint="Regenerate SHA256SUMS with lowercase SHA-256 digests.")
            if fname in sums: raise ContractError(f"duplicate filename in SHA256SUMS: {fname}", code="SHA256SUMS_INVALID", stage="sha256sums", received=fname, hint="List every artifact exactly once in SHA256SUMS.")
            sums[fname] = h
        for item in manifest["artifacts"]:
            if item["filename"] not in sums: raise ContractError(f"SHA256SUMS missing entry for {item['filename']}", code="SHA256SUMS_INVALID", stage="sha256sums", expected=item["filename"], hint="Regenerate SHA256SUMS for the complete artifact set.")
            if sums[item["filename"]] != item["producer_artifact_sha256"]: raise ContractError(f"SHA256SUMS digest mismatch for {item['filename']}", code="SHA256SUMS_INVALID", stage="sha256sums", expected=item["producer_artifact_sha256"], received=sums[item["filename"]], hint="Rebuild the immutable release with matching manifest and checksum data.")
        extra_sums = {k for k in sums.keys() if k.endswith('.rpm')} - manifest_rpms
        if extra_sums: raise ContractError(f"SHA256SUMS contains unknown RPMs: {extra_sums}", code="SHA256SUMS_INVALID", stage="sha256sums", received=sorted(extra_sums), hint="Remove undeclared RPM entries by publishing a corrected immutable release.")

    for item in manifest["artifacts"]:
        filename=item["filename"]
        if pathlib.PurePath(filename).name != filename or filename in seen: raise ContractError(f"unsafe or duplicate filename: {filename}", code="ARTIFACT_SET_MISMATCH", stage="artifact-set", received=filename, hint="Publish unique, basename-only artifact filenames.")
        seen.add(filename); path=pathlib.Path(artifacts_dir)/filename
        actual_digest = digest(path) if path.is_file() else None
        if actual_digest != item["producer_artifact_sha256"]: raise ContractError(f"producer digest mismatch: {filename}", code="ARTIFACT_DIGEST_MISMATCH", stage="artifact-digest", expected=item["producer_artifact_sha256"], received=actual_digest, hint="Publish a new immutable release whose artifact bytes match the manifest.")
        header=rpm_header(path)
        for field in ("name","epoch","version","release","architecture","source_rpm"):
            if header[field] != item[field]: raise ContractError(f"RPM header mismatch for {filename}: {field}", code="RPM_HEADER_MISMATCH", stage="rpm-header", expected=item[field], received=header[field], hint="Regenerate the manifest from the final RPM headers.")
        if item["name"] not in producer["allowed_package_names"]: raise ContractError(f"package name denied: {item['name']}", code="PACKAGE_NAME_DENIED", stage="package-policy", expected=producer["allowed_package_names"], received=item["name"], hint="Publish only package names allowed by the producer registry.")
        if not item["release"].endswith(".fc44"): raise ContractError(f"not a Fedora 44 build: {filename}", code="FEDORA_RELEASE_MISMATCH", stage="fedora-release", expected="release suffix .fc44", received=item["release"], hint="Rebuild the RPM for Fedora 44.")
        if item["architecture"] not in {"src","nosrc"} and item["architecture"] not in producer["architectures"]: raise ContractError(f"architecture denied: {item['architecture']}", code="ARCHITECTURE_DENIED", stage="architecture", expected=producer["architectures"], received=item["architecture"], hint="Publish only an architecture allowed by the producer registry.")
        if item["architecture"] in {"src","nosrc"}: source_names.add(filename)
        headers.append(header)
    if producer.get("srpm_required"):
        for item in manifest["artifacts"]:
            if item["architecture"] not in {"src","nosrc"} and item["source_rpm"] not in source_names: raise ContractError(f"missing matching SRPM: {item['source_rpm']}", code="SRPM_MISSING", stage="srpm-parity", expected=item["source_rpm"], received=sorted(source_names), hint="Publish the matching source RPM in the same immutable release.")
    if producer.get("sbom_required") and not manifest.get("sbom"): raise ContractError("SBOM required", code="ARTIFACT_SET_MISMATCH", stage="artifact-set", expected="SBOM", hint="Publish the required SBOM with the immutable release.")
    names_path=pathlib.Path(fedora_names_path) if fedora_names_path else ROOT/config["fedora_package_names_file"]
    fedora=set(line.strip() for line in names_path.read_text().splitlines() if line.strip() and not line.startswith("#"))
    if not fedora and not test_only_allow_empty_fedora:
        raise ContractError("empty Fedora package list is not allowed in production")
    collision=set(producer["allowed_package_names"]) & fedora
    if collision and not producer.get("allow_fedora_override"): raise ContractError(f"Fedora package collision denied: {', '.join(sorted(collision))}", code="FEDORA_PACKAGE_COLLISION", stage="fedora-collision", received=sorted(collision), hint="Rename the package or obtain an explicitly reviewed Fedora override policy.")
    # --- advisory diagnostics ---
    diagnostics = {"rpmlint": [], "file_conflicts": []}
    binary_entries = [
        (pathlib.Path(artifacts_dir)/item["filename"], item["architecture"])
        for item in manifest["artifacts"]
        if item["architecture"] not in {"src","nosrc"}
    ]
    for rpm_path, _architecture in binary_entries:
        ok, output = rpmlint_check(rpm_path)
        diagnostics["rpmlint"].append({"file": rpm_path.name, "ok": ok, "output": output})
    if len(binary_entries) > 1:
        ok, conflicts = repository_file_conflict_check(binary_entries)
        if not ok: raise ContractError(f"file conflicts between packages: {'; '.join(conflicts)}", code="ARTIFACT_SET_MISMATCH", stage="file-conflict", received=conflicts, hint="Resolve package file ownership conflicts and publish a new release.")
        diagnostics["file_conflicts"] = conflicts
    return manifest, headers, diagnostics

def accept(manifest_path, artifacts_dir, accepted_dir, config_path, fedora_names=None, test_only_allow_unattested=False, test_only_allow_empty_fedora=False, test_only_allow_missing_sha256sums=False, expected_identity=None):
    verify_expected_identity(manifest_path, expected_identity)
    manifest,_,diagnostics=verify_component(manifest_path,artifacts_dir,config_path,fedora_names,test_only_allow_empty_fedora,test_only_allow_missing_sha256sums); key=digest(manifest_path); target=pathlib.Path(accepted_dir)/key
    if target.exists(): raise ContractError(f"acceptance object exists: {key}", code="ACCEPTANCE_OBJECT_EXISTS", stage="acceptance-object", received=key, hint="Use the existing immutable acceptance object or submit a new release.")
    
    verified_attestation = {}
    if not test_only_allow_unattested:
        config = load(config_path)
        producers = [p for p in config["producers"] if p["repository"] == manifest["source_repository"]]
        trusted_workflow = producers[0].get("trusted_signer_workflow")
        if not trusted_workflow: raise ContractError("producer missing trusted_signer_workflow")
        verified_attestation = verify_attestations(manifest, artifacts_dir, manifest_path, trusted_workflow)
        
    accepted_root = pathlib.Path(accepted_dir)
    accepted_root.mkdir(parents=True, exist_ok=True)
    stage = pathlib.Path(tempfile.mkdtemp(prefix=".acceptance-", dir=accepted_root))
    try:
        (stage/"artifacts").mkdir(); shutil.copy2(manifest_path,stage/"component-artifact-manifest-v1.json")
        for item in manifest["artifacts"]: shutil.copy2(pathlib.Path(artifacts_dir)/item["filename"],stage/"artifacts"/item["filename"])

        save(stage/"acceptance-evidence-v1.json",{
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
        stage.rename(target)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return target


def resolve_accepted_object(accepted_path):
    accepted_path = pathlib.Path(accepted_path)
    direct = accepted_path / "acceptance-evidence-v1.json"
    if direct.is_file():
        return accepted_path
    candidates = sorted(accepted_path.rglob("acceptance-evidence-v1.json")) if accepted_path.is_dir() else []
    if len(candidates) != 1:
        raise ContractError(f"expected exactly one accepted object, found {len(candidates)}")
    return candidates[0].parent


def verify_accepted_object(accepted_path, test_only_allow_unattested=False):
    """Revalidate immutable acceptance evidence and RPM bytes before signing."""
    accepted_object = resolve_accepted_object(accepted_path)
    evidence_path = accepted_object / "acceptance-evidence-v1.json"
    manifest_path = accepted_object / "component-artifact-manifest-v1.json"
    artifacts_dir = accepted_object / "artifacts"
    if not evidence_path.is_file():
        raise ContractError("acceptance evidence missing")
    if not manifest_path.is_file():
        raise ContractError("accepted component manifest missing")
    evidence = load(evidence_path)
    manifest = load(manifest_path)
    if not isinstance(evidence, dict):
        raise ContractError("acceptance evidence must be a JSON object")
    validate_schema(manifest, "component-artifact-manifest-v1")
    if not test_only_allow_unattested and evidence.get("verified_provenance") != "github_attestation_exact_match":
        raise ContractError("unattested accepted object rejected in production")
    manifest_digest = digest(manifest_path)
    if evidence.get("manifest_digest") != manifest_digest:
        raise ContractError("acceptance evidence manifest digest mismatch")
    for field in ("source_repository", "source_commit", "release_tag", "release_id", "workflow_run"):
        if evidence.get(field) != manifest.get(field):
            raise ContractError(f"acceptance evidence identity mismatch for {field}")

    entries = {}
    for item in manifest["artifacts"]:
        filename = item["filename"]
        if pathlib.PurePath(filename).name != filename or filename in entries:
            raise ContractError(f"unsafe or duplicate accepted RPM filename: {filename}")
        entries[filename] = item
    expected_paths = {pathlib.PurePosixPath("artifacts") / name for name in entries}
    actual_paths = {
        path.relative_to(accepted_object)
        for path in accepted_object.rglob("*.rpm")
        if path.is_file() or path.is_symlink()
    }
    if actual_paths != expected_paths:
        raise ContractError(
            f"accepted RPM set mismatch. Expected: {sorted(map(str, expected_paths))}. "
            f"Found: {sorted(map(str, actual_paths))}."
        )
    for filename, item in entries.items():
        rpm_path = artifacts_dir / filename
        if rpm_path.is_symlink() or not rpm_path.is_file():
            raise ContractError(f"accepted RPM is not a regular file: {filename}")
        if digest(rpm_path) != item["producer_artifact_sha256"]:
            raise ContractError(f"accepted RPM digest mismatch: {filename}")
    return accepted_object, evidence, manifest, entries


def validate_role_public_key(public_key_path, expected_fingerprint, gnupghome):
    fpr = str(expected_fingerprint).upper()
    if not re.fullmatch(r"[0-9A-F]{40}", fpr):
        raise ContractError("signing subkey fingerprint must be exact 40-hex")
    env = os.environ.copy(); env["GNUPGHOME"] = str(gnupghome)
    records = gpg_fingerprint_records(run([
        "gpg", "--batch", "--import-options", "show-only", "--with-colons",
        "--import", str(public_key_path),
    ], env).stdout)
    primary = [record for record in records if record["type"] == "pub"]
    subkeys = [record for record in records if record["type"] == "sub"]
    if len(primary) != 1 or len(subkeys) != 1 or subkeys[0]["fingerprint"] != fpr:
        raise ContractError(f"canonical RPM public key is not isolated for {fpr}")
    if "s" not in subkeys[0]["capabilities"].lower():
        raise ContractError("canonical RPM public subkey lacks signing capability")
    return primary[0]["fingerprint"]


def require_secret_signing_subkey(gnupghome, subkey_fingerprint, require_isolated=True):
    fpr = require_signing_subkey(gnupghome, subkey_fingerprint)
    env = os.environ.copy(); env["GNUPGHOME"] = str(gnupghome)
    records = gpg_fingerprint_records(run([
        "gpg", "--batch", "--with-colons", "--fingerprint", "--list-secret-keys"
    ], env).stdout)
    secret_subkeys = [record for record in records if record["type"] == "ssb" and record["secret_available"]]
    matches = [record for record in secret_subkeys if record["fingerprint"] == fpr]
    if len(matches) != 1:
        raise ContractError(f"secret signing subkey not found: {fpr}")
    if require_isolated:
        primary_secrets = [record for record in records if record["type"] == "sec" and record["secret_available"]]
        if primary_secrets:
            raise ContractError("offline primary secret key is forbidden in production signing")
        if [record["fingerprint"] for record in secret_subkeys] != [fpr]:
            raise ContractError("production GNUPGHOME must contain only the expected RPM signing secret subkey")
    return fpr


def _validate_passphrase_file(passphrase_file):
    path = pathlib.Path(passphrase_file)
    if path.is_symlink() or not path.is_file():
        raise ContractError("passphrase file must be a regular file")
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ContractError("passphrase file mode must be 0600")
    return path


def _sign_rpm_exact(source, target, gnupghome, key_id, passphrase_file):
    env = os.environ.copy(); env["GNUPGHOME"] = str(gnupghome)
    signer = os.getenv("RO_RPMSIGN") or shutil.which("rpmsign") or "/usr/bin/rpmsign"
    extra_args = "--batch --pinentry-mode loopback --passphrase-file " + shlex.quote(str(passphrase_file))
    shutil.copy2(source, target)
    run([
        signer, "--addsign", "--key-id", key_id,
        "--define", f"_gpg_sign_cmd_extra_args {extra_args}", str(target),
    ], env)


def verify_signed_rpms(rpm_paths, public_key_path):
    with tempfile.TemporaryDirectory() as verify_dir:
        rpmdb = pathlib.Path(verify_dir) / "rpmdb"
        rpmdb.mkdir()
        run(["rpmkeys", "--dbpath", str(rpmdb), "--import", str(public_key_path)])
        for rpm_path in rpm_paths:
            run(["rpmkeys", "--dbpath", str(rpmdb), "--checksig", str(rpm_path)])


def sign_accepted_component(accepted_path, output_dir, gnupghome, key_id, workflow_run,
                            passphrase_file, test_only_public_key=None,
                            test_only_allow_unattested=False):
    """Production RPM 6 signing path with accepted-object revalidation."""
    accepted_object, acceptance, manifest, entries = verify_accepted_object(
        accepted_path, test_only_allow_unattested=test_only_allow_unattested
    )
    run_id = _normalize_numeric_identity(workflow_run)
    if run_id is None:
        raise ContractError("workflow run must be a positive numeric identifier")
    passphrase_path = _validate_passphrase_file(passphrase_file)
    public_key = pathlib.Path(test_only_public_key) if test_only_public_key else ROOT / "keys/production/ro-asd-rpm-signing-public.asc"
    key_fpr = require_secret_signing_subkey(
        gnupghome, key_id, require_isolated=test_only_public_key is None
    )
    validate_role_public_key(public_key, key_fpr, gnupghome)

    output_dir = pathlib.Path(output_dir)
    if output_dir.exists():
        raise ContractError(f"signing output exists: {output_dir}")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".rpm-signing-", dir=output_dir.parent) as tmp:
        stage = pathlib.Path(tmp) / "signed"
        stage.mkdir()
        artifacts = []
        signed_paths = []
        for filename, item in sorted(entries.items()):
            source = accepted_object / "artifacts" / filename
            target = stage / filename
            _sign_rpm_exact(source, target, gnupghome, key_fpr, passphrase_path)
            signed_digest = digest(target)
            if signed_digest == item["producer_artifact_sha256"]:
                raise ContractError(f"RPM signature did not change artifact bytes: {filename}")
            signed_paths.append(target)
            artifacts.append({
                "filename": filename,
                "architecture": item["architecture"],
                "nevra": f"{item['name']}-{item['epoch']}:{item['version']}-{item['release']}.{item['architecture']}",
                "producer_artifact_sha256": item["producer_artifact_sha256"],
                "signed_artifact_sha256": signed_digest,
            })
        verify_signed_rpms(signed_paths, public_key)
        signing_evidence = {
            "schema_version": 1,
            "signed_at": timestamp(),
            "workflow_run": run_id,
            "acceptance_manifest_digest": acceptance["manifest_digest"],
            "rpm_signing_fingerprint": key_fpr,
            "artifacts": artifacts,
        }
        validate_schema(signing_evidence, "rpm-signing-evidence-v1")
        save(stage / "rpm-signing-evidence-v1.json", signing_evidence)
        stage.rename(output_dir)
    return signing_evidence


def verify_signed_component_bundle(components_root, source_runs_path, rpm_key_id,
                                   rpm_public_key=None,
                                   test_only_allow_unattested=False):
    """Revalidate exact signed-component artifacts before snapshot construction."""
    components_root = pathlib.Path(components_root)
    source_runs = load(source_runs_path)
    validate_schema(source_runs, "snapshot-input-v1")
    runs = source_runs["runs"]
    run_ids = [run["run_id"] for run in runs]
    if len(run_ids) != len(set(run_ids)):
        raise ContractError("snapshot input contains duplicate signing run IDs")

    public_key = pathlib.Path(rpm_public_key) if rpm_public_key else ROOT / "keys/production/ro-asd-rpm-signing-public.asc"
    expected_rpm_fpr = str(rpm_key_id).upper()
    with tempfile.TemporaryDirectory(prefix=".snapshot-rpm-key-") as tmp:
        validate_role_public_key(public_key, expected_rpm_fpr, pathlib.Path(tmp))

    verified_components = []
    filenames = set()
    for run_info in runs:
        run_id = run_info["run_id"]
        component_root = components_root / str(run_id)
        accepted_root = component_root / "accepted"
        signed_root = component_root / "signed"
        accepted_object, acceptance, manifest, entries = verify_accepted_object(
            accepted_root, test_only_allow_unattested=test_only_allow_unattested
        )

        evidence_path = signed_root / "rpm-signing-evidence-v1.json"
        if evidence_path.is_symlink() or not evidence_path.is_file():
            raise ContractError(f"RPM signing evidence missing for run {run_id}")
        signing = load(evidence_path)
        validate_schema(signing, "rpm-signing-evidence-v1")
        if signing["workflow_run"] != run_id:
            raise ContractError(f"RPM signing evidence workflow run mismatch for {run_id}")
        if signing["acceptance_manifest_digest"] != acceptance["manifest_digest"]:
            raise ContractError(f"RPM signing evidence acceptance digest mismatch for run {run_id}")
        if signing["rpm_signing_fingerprint"] != expected_rpm_fpr:
            raise ContractError(f"RPM signing fingerprint mismatch for run {run_id}")

        signed_entries = {item["filename"]: item for item in signing["artifacts"]}
        if set(signed_entries) != set(entries):
            raise ContractError(f"signed RPM set mismatch for run {run_id}")

        signed_paths = []
        packages = []
        for filename, item in sorted(entries.items()):
            if filename in filenames:
                raise ContractError(f"duplicate RPM filename across signed components: {filename}")
            filenames.add(filename)
            signed_path = signed_root / filename
            if signed_path.is_symlink() or not signed_path.is_file():
                raise ContractError(f"signed RPM is not a regular file: {filename}")
            signed_item = signed_entries[filename]
            expected_nevra = f"{item['name']}-{item['epoch']}:{item['version']}-{item['release']}.{item['architecture']}"
            for field, expected in (
                ("architecture", item["architecture"]),
                ("nevra", expected_nevra),
                ("producer_artifact_sha256", item["producer_artifact_sha256"]),
            ):
                if signed_item[field] != expected:
                    raise ContractError(f"signing evidence mismatch for {filename}: {field}")
            actual_signed_digest = digest(signed_path)
            if signed_item["signed_artifact_sha256"] != actual_signed_digest:
                raise ContractError(f"signed RPM digest mismatch: {filename}")
            if actual_signed_digest == item["producer_artifact_sha256"]:
                raise ContractError(f"signed RPM bytes equal producer bytes: {filename}")

            header = rpm_header(signed_path)
            for field in ("name", "epoch", "version", "release", "architecture", "source_rpm"):
                if header[field] != item[field]:
                    raise ContractError(f"signed RPM header mismatch for {filename}: {field}")
            signed_paths.append(signed_path)
            packages.append({
                "path": signed_path,
                "item": item,
                "manifest_digest": acceptance["manifest_digest"],
                "signed_digest": actual_signed_digest,
                "nevra": header["nevra"],
            })

        verify_signed_rpms(signed_paths, public_key)
        verified_components.append({
            "signing_run": run_id,
            "source_repository": manifest["source_repository"],
            "source_commit": manifest["source_commit"],
            "release_tag": manifest["release_tag"],
            "release_id": manifest["release_id"],
            "producer_workflow_run": manifest["workflow_run"],
            "acceptance_manifest_digest": acceptance["manifest_digest"],
            "packages": packages,
        })

    if not verified_components:
        raise ContractError("snapshot input contains no signed components")
    return source_runs, verified_components


def _sign_file_exact(path, gnupghome, key_id, passphrase_file):
    passphrase_path = _validate_passphrase_file(passphrase_file)
    env = os.environ.copy()
    env["GNUPGHOME"] = str(gnupghome)
    run([
        "gpg", "--batch", "--yes", "--armor",
        "--pinentry-mode", "loopback", "--passphrase-file", str(passphrase_path),
        "--local-user", f"{key_id}!", "--detach-sign",
        "--output", str(path) + ".asc", str(path),
    ], env)


def build_production_snapshot(components_root, source_runs_path, output, snapshot_id,
                              gnupghome, metadata_key_id, rpm_key_id, workflow_run,
                              passphrase_file, parent=None,
                              test_only_metadata_public_key=None,
                              test_only_rpm_public_key=None,
                              test_only_allow_unattested=False):
    """Build an immutable production candidate snapshot from exact signing runs."""
    if not re.fullmatch(r"repo-f44-[0-9]{8}-[0-9]{3}", snapshot_id):
        raise ContractError("invalid snapshot ID")
    if parent is not None and not re.fullmatch(r"repo-f44-[0-9]{8}-[0-9]{3}", parent):
        raise ContractError("invalid parent snapshot ID")
    build_run = _normalize_numeric_identity(workflow_run)
    if build_run is None:
        raise ContractError("snapshot workflow run must be a positive numeric identifier")

    passphrase_path = _validate_passphrase_file(passphrase_file)
    metadata_fpr = require_secret_signing_subkey(
        gnupghome, metadata_key_id,
        require_isolated=test_only_metadata_public_key is None,
    )
    metadata_public_key = (
        pathlib.Path(test_only_metadata_public_key)
        if test_only_metadata_public_key
        else ROOT / "keys/production/ro-asd-metadata-signing-public.asc"
    )
    rpm_public_key = (
        pathlib.Path(test_only_rpm_public_key)
        if test_only_rpm_public_key
        else ROOT / "keys/production/ro-asd-rpm-signing-public.asc"
    )
    validate_role_public_key(metadata_public_key, metadata_fpr, gnupghome)

    source_runs, components = verify_signed_component_bundle(
        components_root, source_runs_path, rpm_key_id,
        rpm_public_key=rpm_public_key,
        test_only_allow_unattested=test_only_allow_unattested,
    )

    output = pathlib.Path(output)
    final = output / "snapshots/fedora/44" / snapshot_id
    if final.exists():
        raise ContractError("immutable snapshot already exists")
    output.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=".production-snapshot-", dir=output) as tmp:
        stage = pathlib.Path(tmp) / snapshot_id
        repos = {arch: stage / "rpm" / arch for arch in ("x86_64", "aarch64", "source")}
        for repo in repos.values():
            repo.mkdir(parents=True)

        packages = []
        nevras = {}
        historical = {}
        for old_manifest in (output / "snapshots/fedora/44").glob("*/repository-snapshot-v1.json"):
            for old in load(old_manifest).get("packages", []):
                historical[old["nevra"]] = old["producer_artifact_sha256"]

        component_evidence = []
        for component in components:
            component_evidence.append({
                "signing_run": component["signing_run"],
                "source_repository": component["source_repository"],
                "source_commit": component["source_commit"],
                "release_tag": component["release_tag"],
                "release_id": component["release_id"],
                "producer_workflow_run": component["producer_workflow_run"],
                "acceptance_manifest_digest": component["acceptance_manifest_digest"],
            })
            for package in component["packages"]:
                item = package["item"]
                rpm_path = package["path"]
                nevra = package["nevra"]
                if nevra in historical and historical[nevra] != item["producer_artifact_sha256"]:
                    raise ContractError(f"historical NEVRA reuse with different content: {nevra}")
                if nevra in nevras and nevras[nevra] != package["signed_digest"]:
                    raise ContractError(f"same NEVRA has different content: {nevra}")
                nevras[nevra] = package["signed_digest"]

                arch = item["architecture"]
                targets = (
                    [repos["source"]] if arch in {"src", "nosrc"}
                    else [repos["x86_64"], repos["aarch64"]] if arch == "noarch"
                    else [repos[arch]]
                )
                for target in targets:
                    destination = target / rpm_path.name
                    if destination.exists():
                        raise ContractError(f"duplicate RPM filename in snapshot: {rpm_path.name}")
                    shutil.copy2(rpm_path, destination)

                packages.append({
                    "nevra": nevra,
                    "architecture": arch,
                    "filename": rpm_path.name,
                    "producer_artifact_sha256": item["producer_artifact_sha256"],
                    "published_signed_artifact_sha256": package["signed_digest"],
                    "producer_manifest_digest": package["manifest_digest"],
                })

        repodata = {}
        for arch, repo in repos.items():
            run(["createrepo_c", "--unique-md-filenames", str(repo)])
            repomd = repo / "repodata/repomd.xml"
            _sign_file_exact(repomd, gnupghome, metadata_fpr, passphrase_path)
            repodata[arch] = {
                "repomd_sha256": digest(repomd),
                "repomd_signature_sha256": digest(str(repomd) + ".asc"),
            }

        keys = stage / "keys"
        keys.mkdir()
        shutil.copy2(rpm_public_key, keys / "RPM-GPG-KEY-ro-asd")
        shutil.copy2(metadata_public_key, keys / "REPODATA-GPG-KEY-ro-asd")

        manifest = {
            "schema_version": 1,
            "snapshot_id": snapshot_id,
            "created_at": timestamp(),
            "fedora_release": 44,
            "parent_snapshot": parent,
            "packages": sorted(packages, key=lambda item: (item["filename"], item["architecture"])),
            "repositories": repodata,
            "rpm_signing_fingerprint": str(rpm_key_id).upper(),
            "metadata_signing_fingerprint": metadata_fpr,
            "creation_provenance": {"tool": "ro-repo-v2", "run": str(build_run)},
        }
        validate_schema(manifest, "repository-snapshot-v1")
        manifest_path = stage / "repository-snapshot-v1.json"
        save(manifest_path, manifest)
        _sign_file_exact(manifest_path, gnupghome, metadata_fpr, passphrase_path)

        build_evidence = {
            "schema_version": 1,
            "snapshot_id": snapshot_id,
            "created_at": timestamp(),
            "workflow_run": build_run,
            "source_signing_runs": [run["run_id"] for run in source_runs["runs"]],
            "repository_snapshot_sha256": digest(manifest_path),
            "rpm_signing_fingerprint": str(rpm_key_id).upper(),
            "metadata_signing_fingerprint": metadata_fpr,
            "components": component_evidence,
        }
        validate_schema(build_evidence, "snapshot-build-evidence-v1")
        build_evidence_path = stage / "snapshot-build-evidence-v1.json"
        save(build_evidence_path, build_evidence)
        _sign_file_exact(build_evidence_path, gnupghome, metadata_fpr, passphrase_path)

        with tempfile.TemporaryDirectory(prefix=".snapshot-verify-") as verify_tmp:
            verify_home = pathlib.Path(verify_tmp) / "gnupg"
            verify_home.mkdir(mode=0o700)
            verify_env = os.environ.copy()
            verify_env["GNUPGHOME"] = str(verify_home)
            run(["gpg", "--batch", "--import", str(metadata_public_key)], verify_env)
            verify_snapshot(stage, verify_home)
            verify_gpg_signature(
                build_evidence_path, str(build_evidence_path) + ".asc",
                metadata_fpr, verify_env,
            )

        final.parent.mkdir(parents=True, exist_ok=True)
        os.rename(stage, final)
    return build_evidence


def sign_packages(input_dir, output_dir, gnupghome, key_id):
    output_dir=pathlib.Path(output_dir)
    if output_dir.exists(): raise ContractError(f"output exists: {output_dir}")
    output_dir.mkdir(parents=True); env=os.environ.copy(); env["GNUPGHOME"]=str(gnupghome)
    with tempfile.TemporaryDirectory() as verify_dir:
        verify_root=pathlib.Path(verify_dir); rpmdb=verify_root/"rpmdb"; rpmdb.mkdir(); public_key=verify_root/"test-public-key.asc"
        exported=export_role_public_key(gnupghome,key_id)
        public_key.write_text(exported,encoding="ascii"); run(["rpmkeys","--dbpath",str(rpmdb),"--import",str(public_key)])
        for source in sorted(pathlib.Path(input_dir).rglob("*.rpm")):
            target=output_dir/source.name
            if target.exists(): raise ContractError(f"duplicate RPM filename: {source.name}")
            signer=os.getenv("RO_RPMSIGN") or shutil.which("rpmsign") or "/usr/bin/rpmsign"
            shutil.copy2(source,target); run([signer,"--define",f"_gpg_name {key_id}!","--define","__gpg /usr/bin/gpg","--addsign",str(target)],env); run(["rpmkeys","--dbpath",str(rpmdb),"--checksig",str(target)])
    if not list(output_dir.glob("*.rpm")): raise ContractError("no RPMs to sign")


def fingerprint(gnupghome,key_id):
    env=os.environ.copy(); env["GNUPGHOME"]=str(gnupghome)
    lines=run(["gpg","--batch","--with-colons","--fingerprint",key_id],env).stdout.splitlines()
    fprs=[x.split(":")[9] for x in lines if x.startswith("fpr:")]
    if not fprs: raise ContractError("GPG fingerprint not found")
    if key_id in fprs: return key_id
    if len(fprs) > 1: return fprs[-1]
    return fprs[0]

def gpg_fingerprint_records(text):
    records=[]; current=None
    for line in text.splitlines():
        parts=line.split(":")
        if not parts: continue
        if parts[0] in {"pub","sub","sec","ssb"}:
            current=parts
        elif parts[0]=="fpr" and current and len(parts) > 9:
            capabilities=current[11] if len(current) > 11 else ""
            secret_marker=current[14] if len(current) > 14 else ""
            records.append({
                "type":current[0], "fingerprint":parts[9].upper(),
                "capabilities":capabilities,
                "secret_available":current[0] in {"sec","ssb"} and secret_marker == "+",
            })
    return records

def require_signing_subkey(gnupghome,subkey_fingerprint):
    fpr=str(subkey_fingerprint).upper()
    if not re.fullmatch(r"[0-9A-F]{40}",fpr):
        raise ContractError("signing subkey fingerprint must be exact 40-hex")
    env=os.environ.copy(); env["GNUPGHOME"]=str(gnupghome)
    # Listing the complete ephemeral keyring keeps a missing/wrong-role key in
    # the contract-error path instead of exposing GnuPG's command failure.
    records=gpg_fingerprint_records(run(["gpg","--batch","--with-colons","--fingerprint"],env).stdout)
    matches=[record for record in records if record["fingerprint"]==fpr]
    if len(matches)!=1: raise ContractError(f"GPG signing subkey not found: {fpr}")
    if matches[0]["type"]!="sub": raise ContractError("role key must be a signing subkey, not a primary key")
    if "s" not in matches[0]["capabilities"].lower(): raise ContractError("role subkey must have signing capability")
    return fpr

def export_role_public_key(gnupghome,subkey_fingerprint):
    fpr=require_signing_subkey(gnupghome,subkey_fingerprint)
    env=os.environ.copy(); env["GNUPGHOME"]=str(gnupghome)
    exported=run(["gpg","--batch","--armor","--export-filter",f"drop-subkey=fpr <> {fpr}","--export",fpr],env).stdout
    if not exported.strip(): raise ContractError(f"empty GPG role public key export: {fpr}")
    with tempfile.TemporaryDirectory() as tmp:
        key_path=pathlib.Path(tmp)/"role-public-key.asc"
        key_path.write_text(exported,encoding="ascii")
        records=gpg_fingerprint_records(run(["gpg","--batch","--import-options","show-only","--with-colons","--import",str(key_path)],env).stdout)
    primary=[record["fingerprint"] for record in records if record["type"]=="pub"]
    subkeys=[record["fingerprint"] for record in records if record["type"]=="sub"]
    if len(primary)!=1 or subkeys!=[fpr]:
        raise ContractError(f"GPG role public key export is not isolated for {fpr}")
    return exported

def sign_file(path,gnupghome,key_id):
    env=os.environ.copy(); env["GNUPGHOME"]=str(gnupghome)
    run(["gpg","--batch","--yes","--armor","--local-user",f"{key_id}!","--detach-sign","--output",str(path)+".asc",str(path)],env)

def verify_gpg_signature(file_path, asc_path, expected_fingerprint, env):
    out = run(["gpg", "--status-fd", "1", "--verify", str(asc_path), str(file_path)], env).stdout
    for line in out.splitlines():
        if line.startswith("[GNUPG:] VALIDSIG "):
            if line.split()[2] == expected_fingerprint:
                return
    raise ContractError(f"GPG signature verification error: wrong key used for {file_path}")

def build_snapshot(signed_dir,manifests_dir,output,snapshot_id,gnupghome,metadata_key_id,rpm_key_id,parent=None,test_only_allow_unattested_acceptance=False):
    if not __import__("re").fullmatch(r"repo-f44-[0-9]{8}-[0-9]{3}",snapshot_id): raise ContractError("invalid snapshot ID")
    output=pathlib.Path(output); final=output/"snapshots/fedora/44"/snapshot_id
    if final.exists(): raise ContractError("immutable snapshot already exists")
    entries={}
    for acc in pathlib.Path(manifests_dir).rglob("acceptance-evidence-v1.json"):
        evidence = load(acc)
        if not test_only_allow_unattested_acceptance and evidence.get("verified_provenance") != "github_attestation_exact_match":
            raise ContractError("unattested component rejected in production")
        mp = acc.parent / "component-artifact-manifest-v1.json"
        if not mp.is_file(): raise ContractError(f"manifest missing for acceptance evidence: {acc}")
        if digest(mp) != evidence.get("manifest_digest"): raise ContractError(f"acceptance evidence manifest digest mismatch for {acc}")
        m=load(mp)
        
        for field in ("source_repository","source_commit","release_tag","release_id","workflow_run"):
            if evidence.get(field) != m.get(field):
                raise ContractError(f"acceptance evidence identity mismatch for {field}: {acc}")
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
        verify_root=pathlib.Path(tmp)/"rpm-verify"; verify_root.mkdir()
        rpmdb=verify_root/"rpmdb"; rpmdb.mkdir()
        public_key=verify_root/"test-public-key.asc"
        exported=export_role_public_key(gnupghome,rpm_key_id)
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
        exported_meta = export_role_public_key(gnupghome,metadata_key_id)
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


def verify_production_candidate(snapshot, gnupghome, candidate_run):
    """Verify the complete Step 3 handoff object before remote publication."""
    snapshot = pathlib.Path(snapshot)
    expected_run = _normalize_numeric_identity(candidate_run)
    if expected_run is None:
        raise ContractError("candidate workflow run must be a positive numeric identifier")

    manifest = verify_snapshot(snapshot, gnupghome)
    evidence_path = snapshot / "snapshot-build-evidence-v1.json"
    evidence_sig = pathlib.Path(str(evidence_path) + ".asc")
    if evidence_path.is_symlink() or not evidence_path.is_file():
        raise ContractError("snapshot build evidence is missing")
    if evidence_sig.is_symlink() or not evidence_sig.is_file():
        raise ContractError("snapshot build evidence signature is missing")

    evidence = load(evidence_path)
    validate_schema(evidence, "snapshot-build-evidence-v1")
    if evidence["snapshot_id"] != manifest["snapshot_id"]:
        raise ContractError("snapshot build evidence snapshot ID mismatch")
    if evidence["workflow_run"] != expected_run:
        raise ContractError("snapshot build evidence workflow run mismatch")
    if evidence["repository_snapshot_sha256"] != digest(snapshot / "repository-snapshot-v1.json"):
        raise ContractError("snapshot build evidence manifest digest mismatch")
    if evidence["rpm_signing_fingerprint"] != manifest["rpm_signing_fingerprint"]:
        raise ContractError("snapshot build evidence RPM fingerprint mismatch")
    if evidence["metadata_signing_fingerprint"] != manifest["metadata_signing_fingerprint"]:
        raise ContractError("snapshot build evidence metadata fingerprint mismatch")

    env = os.environ.copy()
    env["GNUPGHOME"] = str(gnupghome)
    verify_gpg_signature(
        evidence_path,
        evidence_sig,
        manifest["metadata_signing_fingerprint"],
        env,
    )
    return manifest, evidence


def directory_tree_digest(root):
    """Return a deterministic digest for a regular-file-only publication tree."""
    root = pathlib.Path(root)
    if not root.is_dir():
        raise ContractError(f"publication tree missing: {root}")
    hasher = hashlib.sha256()
    files = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ContractError(f"symlink forbidden in immutable publication tree: {path}")
        if path.is_file():
            files.append(path)
        elif not path.is_dir():
            raise ContractError(f"unsupported filesystem entry in publication tree: {path}")
    for path in sorted(files, key=lambda p: p.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix().encode("utf-8")
        hasher.update(len(rel).to_bytes(8, "big"))
        hasher.update(rel)
        size = path.stat().st_size
        hasher.update(size.to_bytes(8, "big"))
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(block)
    return hasher.hexdigest()


def stage_pages_snapshot(snapshot, site_root):
    """Add one immutable verified snapshot tree to persistent Pages storage."""
    snapshot = pathlib.Path(snapshot)
    site_root = pathlib.Path(site_root)
    manifest = load(snapshot / "repository-snapshot-v1.json")
    validate_schema(manifest, "repository-snapshot-v1")
    snapshot_id = manifest["snapshot_id"]
    if snapshot.name != snapshot_id:
        raise ContractError("snapshot directory name does not match signed snapshot identity")

    target = site_root / "snapshots" / "fedora" / "44" / snapshot_id
    candidate_digest = directory_tree_digest(snapshot)
    site_root.mkdir(parents=True, exist_ok=True)
    (site_root / ".nojekyll").touch(exist_ok=True)

    if target.exists():
        if not target.is_dir() or target.is_symlink():
            raise ContractError("immutable Pages snapshot target is not a regular directory")
        if directory_tree_digest(target) != candidate_digest:
            raise ContractError("immutable Pages snapshot already exists with different bytes")
        return {
            "snapshot_id": snapshot_id,
            "tree_sha256": candidate_digest,
            "created": False,
        }

    target.parent.mkdir(parents=True, exist_ok=True)
    stage = pathlib.Path(tempfile.mkdtemp(prefix=f".{snapshot_id}-", dir=target.parent))
    try:
        shutil.copytree(snapshot, stage / snapshot_id, symlinks=False)
        copied = stage / snapshot_id
        if directory_tree_digest(copied) != candidate_digest:
            raise ContractError("Pages snapshot copy digest mismatch")
        os.rename(copied, target)
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    return {
        "snapshot_id": snapshot_id,
        "tree_sha256": candidate_digest,
        "created": True,
    }



def build_signed_remote_publication(snapshot, channel, output, publication_run,
                                    gnupghome, metadata_key_id, passphrase_file):
    """Create a signed remote channel manifest without rebuilding repository bytes."""
    if channel not in {"beta", "stable"}:
        raise ContractError("only beta/stable channels exist")
    run_id = _normalize_numeric_identity(publication_run)
    if run_id is None:
        raise ContractError("publication workflow run must be a positive numeric identifier")

    snapshot = pathlib.Path(snapshot)
    output = pathlib.Path(output)
    manifest = load(snapshot / "repository-snapshot-v1.json")
    validate_schema(manifest, "repository-snapshot-v1")
    if snapshot.name != manifest["snapshot_id"]:
        raise ContractError("snapshot identity mismatch for remote publication")

    metadata_fpr = require_secret_signing_subkey(
        gnupghome, metadata_key_id, require_isolated=True
    )
    if metadata_fpr != manifest["metadata_signing_fingerprint"]:
        raise ContractError("remote publication metadata signing fingerprint mismatch")

    passphrase_path = _validate_passphrase_file(passphrase_file)
    target = output / channel
    if target.exists():
        raise ContractError("signed publication output already exists")
    target.mkdir(parents=True)

    publication = {
        "schema_version": 1,
        "channel": channel,
        "snapshot_id": manifest["snapshot_id"],
        "published_at": timestamp(),
        "publication_run": str(run_id),
    }
    validate_schema(publication, "publication-v1")
    publication_path = target / "publication-v1.json"
    save(publication_path, publication)
    _sign_file_exact(
        publication_path, gnupghome, metadata_fpr, passphrase_path
    )
    return publication


def verify_signed_remote_publication(publication_dir, snapshot, channel, gnupghome):
    """Verify a signed channel manifest against one immutable snapshot."""
    publication_dir = pathlib.Path(publication_dir)
    snapshot = pathlib.Path(snapshot)
    if channel not in {"beta", "stable"}:
        raise ContractError("only beta/stable channels exist")

    manifest = load(snapshot / "repository-snapshot-v1.json")
    validate_schema(manifest, "repository-snapshot-v1")
    publication_path = publication_dir / "publication-v1.json"
    signature_path = pathlib.Path(str(publication_path) + ".asc")
    if publication_path.is_symlink() or not publication_path.is_file():
        raise ContractError("remote publication manifest missing")
    if signature_path.is_symlink() or not signature_path.is_file():
        raise ContractError("remote publication signature missing")

    publication = load(publication_path)
    validate_schema(publication, "publication-v1")
    if publication["channel"] != channel:
        raise ContractError("remote publication channel mismatch")
    if publication["snapshot_id"] != manifest["snapshot_id"]:
        raise ContractError("remote publication snapshot mismatch")
    if _normalize_numeric_identity(publication["publication_run"]) is None:
        raise ContractError("remote publication run is not an exact numeric identity")

    env = os.environ.copy()
    env["GNUPGHOME"] = str(gnupghome)
    verify_gpg_signature(
        publication_path,
        signature_path,
        manifest["metadata_signing_fingerprint"],
        env,
    )
    return publication


def stage_remote_channel(publication_dir, site_root, channel, gnupghome):
    """Materialize a mutable remote channel from immutable snapshot bytes."""
    if channel not in {"beta", "stable"}:
        raise ContractError("only beta/stable channels exist")
    publication_dir = pathlib.Path(publication_dir)
    site_root = pathlib.Path(site_root)
    publication = load(publication_dir / "publication-v1.json")
    validate_schema(publication, "publication-v1")
    snapshot_id = publication["snapshot_id"]

    snapshot = site_root / "snapshots" / "fedora" / "44" / snapshot_id
    if not snapshot.is_dir() or snapshot.is_symlink():
        raise ContractError("referenced immutable snapshot is missing from Pages storage")
    verify_signed_remote_publication(
        publication_dir, snapshot, channel, gnupghome
    )

    base = site_root / "rpm" / "fedora" / "44"
    target = base / channel
    history = site_root / "publications" / "fedora" / "44" / channel
    run_id = publication["publication_run"]
    history_entry = history / run_id
    history.mkdir(parents=True, exist_ok=True)

    if history_entry.exists():
        if not history_entry.is_dir() or history_entry.is_symlink():
            raise ContractError("publication history entry is not a regular directory")
        expected = directory_tree_digest(publication_dir)
        if directory_tree_digest(history_entry) != expected:
            raise ContractError("publication history run already exists with different bytes")
    else:
        shutil.copytree(publication_dir, history_entry, symlinks=False)

    stage_parent = base
    stage_parent.mkdir(parents=True, exist_ok=True)
    stage = pathlib.Path(tempfile.mkdtemp(prefix=f".{channel}-", dir=stage_parent))
    new_tree = stage / channel
    new_tree.mkdir()

    try:
        for arch in ("x86_64", "aarch64", "source"):
            source = snapshot / "rpm" / arch
            if not source.is_dir() or source.is_symlink():
                raise ContractError(f"snapshot repository missing: {arch}")
            shutil.copytree(source, new_tree / arch, symlinks=False)
            if directory_tree_digest(source) != directory_tree_digest(new_tree / arch):
                raise ContractError(f"remote channel copy mismatch: {arch}")

        shutil.copy2(
            publication_dir / "publication-v1.json",
            new_tree / "publication-v1.json",
        )
        shutil.copy2(
            publication_dir / "publication-v1.json.asc",
            new_tree / "publication-v1.json.asc",
        )

        previous_snapshot = None
        previous_run = None
        if target.exists():
            if not target.is_dir() or target.is_symlink():
                raise ContractError("remote channel target is not a regular directory")
            previous_manifest = load(target / "publication-v1.json")
            validate_schema(previous_manifest, "publication-v1")
            previous_snapshot = previous_manifest["snapshot_id"]
            previous_run = previous_manifest["publication_run"]

            if directory_tree_digest(target) == directory_tree_digest(new_tree):
                shutil.rmtree(stage, ignore_errors=True)
                return {
                    "channel": channel,
                    "snapshot_id": snapshot_id,
                    "publication_run": run_id,
                    "previous_snapshot_id": previous_snapshot,
                    "previous_publication_run": previous_run,
                    "changed": False,
                }

            backup = base / f".{channel}-replace-{uuid.uuid4().hex}"
            os.rename(target, backup)
            try:
                os.rename(new_tree, target)
            except Exception:
                os.rename(backup, target)
                raise
            shutil.rmtree(backup)
        else:
            os.rename(new_tree, target)

        return {
            "channel": channel,
            "snapshot_id": snapshot_id,
            "publication_run": run_id,
            "previous_snapshot_id": previous_snapshot,
            "previous_publication_run": previous_run,
            "changed": True,
        }
    finally:
        shutil.rmtree(stage, ignore_errors=True)



def rollback_remote_channel(site_root, channel, target_publication_run, rollback_run,
                            reason, gnupghome):
    """Rollback a mutable remote channel to an earlier signed publication history entry."""
    if channel != "beta":
        raise ContractError("remote rollback currently supports beta only")

    target_run = _normalize_numeric_identity(target_publication_run)
    current_rollback_run = _normalize_numeric_identity(rollback_run)
    if target_run is None:
        raise ContractError("target publication run must be a positive numeric identifier")
    if current_rollback_run is None:
        raise ContractError("rollback workflow run must be a positive numeric identifier")
    if not isinstance(reason, str) or not reason.strip():
        raise ContractError("rollback reason must be non-empty")

    site_root = pathlib.Path(site_root)
    base = site_root / "rpm" / "fedora" / "44"
    current = base / channel
    if not current.is_dir() or current.is_symlink():
        raise ContractError("current remote beta publication is missing")

    current_publication_path = current / "publication-v1.json"
    current_publication = load(current_publication_path)
    validate_schema(current_publication, "publication-v1")
    current_publication_sha256 = digest(current_publication_path)
    if current_publication["channel"] != channel:
        raise ContractError("current remote beta channel mismatch")

    history = site_root / "publications" / "fedora" / "44" / channel
    target_publication_dir = history / str(target_run)
    if not target_publication_dir.is_dir() or target_publication_dir.is_symlink():
        raise ContractError("target beta publication history entry is missing")

    target_publication_path = target_publication_dir / "publication-v1.json"
    target_publication = load(target_publication_path)
    validate_schema(target_publication, "publication-v1")
    target_publication_sha256 = digest(target_publication_path)
    if target_publication["channel"] != channel:
        raise ContractError("target publication history channel mismatch")
    if target_publication["publication_run"] != str(target_run):
        raise ContractError("target publication history run identity mismatch")

    if current_publication["publication_run"] == str(target_run):
        raise ContractError("target publication is already the current beta")

    snapshot_id = target_publication["snapshot_id"]
    snapshot = site_root / "snapshots" / "fedora" / "44" / snapshot_id
    if not snapshot.is_dir() or snapshot.is_symlink():
        raise ContractError("rollback target immutable snapshot is missing")

    verify_signed_remote_publication(
        target_publication_dir, snapshot, channel, gnupghome
    )

    result = stage_remote_channel(
        target_publication_dir, site_root, channel, gnupghome
    )
    if not result.get("changed"):
        raise ContractError("rollback did not change the beta publication")

    evidence_dir = site_root / "rollbacks" / "fedora" / "44" / channel
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_dir / f"{current_rollback_run}.json"
    if evidence_path.exists():
        raise ContractError("rollback evidence run already exists")

    evidence = {
        "schema_version": 1,
        "channel": channel,
        "rollback_run": str(current_rollback_run),
        "rolled_back_at": timestamp(),
        "reason": reason.strip(),
        "from_publication_run": current_publication["publication_run"],
        "from_snapshot_id": current_publication["snapshot_id"],
        "from_publication_sha256": current_publication_sha256,
        "to_publication_run": target_publication["publication_run"],
        "to_snapshot_id": target_publication["snapshot_id"],
        "to_publication_sha256": target_publication_sha256,
    }
    validate_schema(evidence, "rollback-evidence-v1")
    save(evidence_path, evidence)
    return evidence


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
    beta = load(beta_path)
    if beta["snapshot_id"] != p["snapshot_id"]: raise ContractError("snapshot is not the current beta publication")

    snapshot_dir = pathlib.Path(output) / "snapshots/fedora/44" / p["snapshot_id"]
    snapshot_path = snapshot_dir / "repository-snapshot-v1.json"
    snapshot_manifest = load(snapshot_path)
    
    if gnupghome:
        verify_snapshot(snapshot_dir, gnupghome)
        env=os.environ.copy(); env["GNUPGHOME"]=str(gnupghome)
        verify_gpg_signature(beta_path, str(beta_path)+".asc", snapshot_manifest["metadata_signing_fingerprint"], env)

    age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(beta["published_at"].replace("Z", "+00:00"))
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
        if "tests" in ref_data:
            test_results = {t.get("name"): t.get("result") for t in ref_data["tests"]}
            if test_results.get(ev["name"]) != "pass": raise ContractError("evidence content result not pass")
        else:
            if ref_data.get("name") != ev["name"] or ref_data.get("result") != "pass": raise ContractError("evidence content result not pass")
        
        if ref_data.get("snapshot_id") != p["snapshot_id"]: raise ContractError("evidence content snapshot mismatch")
        
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
    component("verify-component"); x=component("accept-package"); x.add_argument("--accepted",type=pathlib.Path,required=True); x.add_argument("--attestations",type=pathlib.Path); x.add_argument("--test-only-allow-unattested",action="store_true"); x.add_argument("--report",type=pathlib.Path,required=True); x.add_argument("--expected-repository"); x.add_argument("--expected-tag"); x.add_argument("--expected-commit"); x.add_argument("--expected-release-id")
    x=s.add_parser("sign-package"); x.add_argument("--input",type=pathlib.Path,required=True); x.add_argument("--output",type=pathlib.Path,required=True); x.add_argument("--gnupghome",type=pathlib.Path,required=True); x.add_argument("--key-id",required=True)
    x=s.add_parser("sign-accepted-component"); x.add_argument("--accepted",type=pathlib.Path,required=True); x.add_argument("--output",type=pathlib.Path,required=True); x.add_argument("--gnupghome",type=pathlib.Path,required=True); x.add_argument("--key-id",required=True); x.add_argument("--workflow-run",required=True); x.add_argument("--passphrase-file",type=pathlib.Path,required=True); x.add_argument("--test-only-public-key",type=pathlib.Path); x.add_argument("--test-only-allow-unattested",action="store_true")
    x=s.add_parser("write-snapshot-input"); x.add_argument("--runs",required=True); x.add_argument("--output",type=pathlib.Path,required=True)
    x=s.add_parser("build-snapshot"); x.add_argument("--signed",type=pathlib.Path,required=True); x.add_argument("--manifests",type=pathlib.Path,required=True); x.add_argument("--output",type=pathlib.Path,required=True); x.add_argument("--snapshot-id",required=True); x.add_argument("--gnupghome",type=pathlib.Path,required=True); x.add_argument("--rpm-key-id",required=True); x.add_argument("--metadata-key-id",required=True); x.add_argument("--parent"); x.add_argument("--test-only-allow-unattested-acceptance",action="store_true")
    x=s.add_parser("build-production-snapshot"); x.add_argument("--components",type=pathlib.Path,required=True); x.add_argument("--source-runs",type=pathlib.Path,required=True); x.add_argument("--output",type=pathlib.Path,required=True); x.add_argument("--snapshot-id",required=True); x.add_argument("--gnupghome",type=pathlib.Path,required=True); x.add_argument("--rpm-key-id",required=True); x.add_argument("--metadata-key-id",required=True); x.add_argument("--workflow-run",required=True); x.add_argument("--passphrase-file",type=pathlib.Path,required=True); x.add_argument("--parent"); x.add_argument("--test-only-metadata-public-key",type=pathlib.Path); x.add_argument("--test-only-rpm-public-key",type=pathlib.Path); x.add_argument("--test-only-allow-unattested",action="store_true")
    x=s.add_parser("verify-production-candidate"); x.add_argument("--snapshot",type=pathlib.Path,required=True); x.add_argument("--gnupghome",type=pathlib.Path,required=True); x.add_argument("--candidate-run",required=True)
    x=s.add_parser("stage-pages-snapshot"); x.add_argument("--snapshot",type=pathlib.Path,required=True); x.add_argument("--site-root",type=pathlib.Path,required=True)
    x=s.add_parser("verify-snapshot"); x.add_argument("--snapshot",type=pathlib.Path,required=True); x.add_argument("--gnupghome",type=pathlib.Path)
    x=s.add_parser("build-signed-remote-publication"); x.add_argument("--snapshot",type=pathlib.Path,required=True); x.add_argument("--channel",choices=["beta","stable"],required=True); x.add_argument("--output",type=pathlib.Path,required=True); x.add_argument("--publication-run",required=True); x.add_argument("--gnupghome",type=pathlib.Path,required=True); x.add_argument("--metadata-key-id",required=True); x.add_argument("--passphrase-file",type=pathlib.Path,required=True)
    x=s.add_parser("stage-remote-channel"); x.add_argument("--publication",type=pathlib.Path,required=True); x.add_argument("--site-root",type=pathlib.Path,required=True); x.add_argument("--channel",choices=["beta","stable"],required=True); x.add_argument("--gnupghome",type=pathlib.Path,required=True)
    x=s.add_parser("rollback-remote-channel"); x.add_argument("--site-root",type=pathlib.Path,required=True); x.add_argument("--channel",choices=["beta"],required=True); x.add_argument("--target-publication-run",required=True); x.add_argument("--rollback-run",required=True); x.add_argument("--reason",required=True); x.add_argument("--gnupghome",type=pathlib.Path,required=True)
    x=s.add_parser("publish-local"); x.add_argument("--output",type=pathlib.Path,required=True); x.add_argument("--snapshot-id",required=True); x.add_argument("--channel",choices=["beta","stable"],required=True); x.add_argument("--publication-run",default="local"); x.add_argument("--gnupghome",type=pathlib.Path,required=True)
    x=s.add_parser("promote-snapshot"); x.add_argument("--output",type=pathlib.Path,required=True); x.add_argument("--promotion",type=pathlib.Path,required=True); x.add_argument("--publication-run",default="local"); x.add_argument("--gnupghome",type=pathlib.Path,required=True)
    x=s.add_parser("rollback-publication"); x.add_argument("--output",type=pathlib.Path,required=True); x.add_argument("--channel",choices=["beta","stable"],required=True)
    x=s.add_parser("generate-catalog"); x.add_argument("--snapshot",type=pathlib.Path,required=True); x.add_argument("--editorial",type=pathlib.Path); x.add_argument("--output",type=pathlib.Path,required=True); x.add_argument("--gnupghome",type=pathlib.Path,required=True)
    return p.parse_args()

def main():
    a=cli()
    if a.command == "accept-package":
        expected = {
            "source_repository": a.expected_repository,
            "release_tag": a.expected_tag,
            "source_commit": a.expected_commit,
            "release_id": a.expected_release_id,
        }
        identity = acceptance_report_identity(a.manifest, expected)
        accepted_target = None
        try:
            accepted_target = accept(a.manifest,a.artifacts,a.accepted,a.config,a.fedora_names,a.test_only_allow_unattested,expected_identity=expected)
            write_acceptance_report(a.report, "accepted", identity)
            print(f"ok: {a.command}")
            return 0
        except ContractError as exc:
            if accepted_target is not None:
                shutil.rmtree(accepted_target, ignore_errors=True)
            write_acceptance_report(a.report, "rejected", identity, exc)
            print(f"error: {exc}",file=sys.stderr)
            return 2
        except Exception:
            if accepted_target is not None:
                shutil.rmtree(accepted_target, ignore_errors=True)
            error = ContractError(
                "unexpected internal acceptance error", code="INTERNAL_ACCEPTANCE_ERROR",
                stage="acceptance", hint="Inspect the acceptance job logs and retry after correcting the internal failure.",
            )
            write_acceptance_report(a.report, "rejected", identity, error)
            print(f"error: {error}",file=sys.stderr)
            return 2
    try:
        if a.command=="verify-component": verify_component(a.manifest,a.artifacts,a.config,a.fedora_names)
        elif a.command=="sign-package": sign_packages(a.input,a.output,a.gnupghome,a.key_id)
        elif a.command=="sign-accepted-component": sign_accepted_component(a.accepted,a.output,a.gnupghome,a.key_id,a.workflow_run,a.passphrase_file,a.test_only_public_key,a.test_only_allow_unattested)
        elif a.command=="write-snapshot-input": write_snapshot_input(a.output,a.runs)
        elif a.command=="build-snapshot": build_snapshot(a.signed,a.manifests,a.output,a.snapshot_id,a.gnupghome,a.metadata_key_id,a.rpm_key_id,a.parent,a.test_only_allow_unattested_acceptance)
        elif a.command=="build-production-snapshot": build_production_snapshot(a.components,a.source_runs,a.output,a.snapshot_id,a.gnupghome,a.metadata_key_id,a.rpm_key_id,a.workflow_run,a.passphrase_file,a.parent,a.test_only_metadata_public_key,a.test_only_rpm_public_key,a.test_only_allow_unattested)
        elif a.command=="verify-production-candidate": verify_production_candidate(a.snapshot,a.gnupghome,a.candidate_run)
        elif a.command=="stage-pages-snapshot": print(json.dumps(stage_pages_snapshot(a.snapshot,a.site_root),sort_keys=True))
        elif a.command=="verify-snapshot": verify_snapshot(a.snapshot,a.gnupghome)
        elif a.command=="build-signed-remote-publication": build_signed_remote_publication(a.snapshot,a.channel,a.output,a.publication_run,a.gnupghome,a.metadata_key_id,a.passphrase_file)
        elif a.command=="stage-remote-channel": print(json.dumps(stage_remote_channel(a.publication,a.site_root,a.channel,a.gnupghome),sort_keys=True))
        elif a.command=="rollback-remote-channel": print(json.dumps(rollback_remote_channel(a.site_root,a.channel,a.target_publication_run,a.rollback_run,a.reason,a.gnupghome),sort_keys=True))
        elif a.command=="publish-local": publish(a.output,a.snapshot_id,a.channel,a.publication_run,a.gnupghome)
        elif a.command=="promote-snapshot": promote(a.output,a.promotion,a.publication_run,a.gnupghome)
        elif a.command=="rollback-publication": print(f"rolled back to: {rollback(a.output,a.channel)}")
        elif a.command=="generate-catalog": catalog(a.snapshot,a.editorial,a.output,a.gnupghome)
        print(f"ok: {a.command}"); return 0
    except ContractError as exc: print(f"error: {exc}",file=sys.stderr); return 2

if __name__=="__main__": raise SystemExit(main())
