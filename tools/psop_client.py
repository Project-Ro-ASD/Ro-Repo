"""PSOP-only public verification and atomic disposable client transactions.

This is not a freshness/discovery authority. A new client can accept a valid old
descriptor. Known generations cannot regress. No production client roots, package
database or configuration are writable through this API.
"""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import copy
import gzip
import xml.etree.ElementTree as ET

from psop_context import DOMAIN, require_evidence, frozen_tree
from v3_backend_trust import b64, canonical, digest, strict_json, verify_bytes, require_test_root
from v3_client_update import Client as V3Client
from v3_policy_profile import sha
from v3_promotion_planner import PlanningError, evr_compare, _parse
from ro_repo import validate_schema, validate_role_public_key, verify_signed_rpms
from v3_signed_beta_history import _keyring, _signature, _verify


def member(path):
    if (not isinstance(path, str) or not path or not re.fullmatch(r"[A-Za-z0-9_./+~^-]+", path)
            or pathlib.PurePosixPath(path).is_absolute() or ".." in pathlib.PurePosixPath(path).parts
            or pathlib.PurePosixPath(path).as_posix() != path):
        raise PlanningError("unsafe immutable PSOP member")
    return path


def verify_envelope(raw, key, pin, context, *, now):
    value = strict_json(raw)
    if (not isinstance(value, dict) or set(value) != {"domain", "role", "context", "payload", "signature"}
            or value["domain"] != DOMAIN or value["role"] != "publication" or value["context"] != context):
        raise PlanningError("PSOP publication/descriptor domain substitution")
    verify_bytes(key, pin, canonical({k: v for k, v in value.items() if k != "signature"}), b64(value["signature"]))
    p = value["payload"]
    if (not isinstance(p, dict) or type(p.get("issued_at")) is not int or type(p.get("expires_at")) is not int
            or not p["issued_at"] <= now < p["expires_at"] or not 0 < p["expires_at"] - p["issued_at"] <= 3600):
        raise PlanningError("expired or unbounded PSOP envelope")
    return p


def issue_descriptor(gateway, signed, approval, attempt, *, origin, now, previous=None, seconds=300, scope=None):
    """New bounded test authority from an exact completed PR-B publication."""
    from psop_pages import checked_origin
    from psop_signing import SignedResult
    checked_origin(origin, scope=scope)
    if type(seconds) is not int or not 1 <= seconds <= 3600:
        raise PlanningError("bounded descriptor validity required")
    if not isinstance(signed, SignedResult):
        raise PlanningError("exact SignedResult required")
    s = require_evidence(signed, gateway.context)
    a = require_evidence(approval, gateway.context, "approved")
    receipt = gateway.receipt(attempt)
    record = gateway.ledger.inspect(attempt)
    gateway._store.verify_target(record["attempt"]["prepared"])
    if (receipt["status"] != "COMPLETE" or receipt["writer"] != "psop-stable"
            or receipt["result_sha256"] != s["result_sha256"] or receipt["approval_sha256"] != approval.sha256
            or s["approval_sha256"] != approval.sha256 or record["head"]["digest"] != s["result_sha256"]
            or now >= a["expiry"] or seconds > a["expiry"] - now):
        raise PlanningError("fresh approval and exact current completed result/receipt required")
    generation = record["head"]["generation"]
    prev = None
    if previous is not None:
        p = strict_json(previous)["payload"]
        prev = verify_envelope(previous, gateway.context.signer("publication").public,
            gateway.context.signer("publication").key_sha256, gateway.context.pin, now=p["issued_at"])
        validate_schema(prev, "psop-client-descriptor-v1")
    if ((generation == 1) != (prev is None) or prev is not None and
            (prev["generation"] + 1 != generation or prev["result_sha256"] != a["payload"]["review"]["previous_stable_sha256"]
             or prev["origin"] != origin)):
        raise PlanningError("explicit contiguous descriptor lineage required; rollback BLOCKED")
    body = {"schema_version": 1, "domain": "psop-client-descriptor-test-1", "context": gateway.context.pin,
        "origin": origin, "generation": generation, "previous_generation": 0 if prev is None else prev["generation"],
        "previous_result_sha256": None if prev is None else prev["result_sha256"],
        "result_sha256": s["result_sha256"], "signed_inventory": s["inventory"],
        "publication_sha256": receipt["publication_sha256"], "receipt": receipt,
        "receipt_sha256": sha(receipt), "metadata_key": a["payload"]["metadata_key"],
        "rollback_authority": False, "production_activation": "BLOCKED", "publishable": False}
    raw = gateway.context.envelope("publication", body, now=now, seconds=seconds)
    validate_schema(strict_json(raw)["payload"], "psop-client-descriptor-v1")
    return raw


class VerifiedView:
    def __init__(self, descriptor, raw, path, inventory):
        self.descriptor, self.raw, self.path, self.inventory = descriptor, raw, path, inventory

    def check(self):
        if frozen_tree(self.path) != self.inventory:
            raise PlanningError("verified client payload changed")


def verify_metadata_links(stage, advertised):
    """Reject signed URL overrides and bind primary metadata to exact RPM set."""
    ns = {"r": "http://linux.duke.edu/metadata/repo", "c": "http://linux.duke.edu/metadata/common"}
    for arch in ("x86_64", "aarch64", "source"):
        repo = stage / "rpm" / arch
        try:
            repomd = ET.fromstring((repo / "repodata/repomd.xml").read_bytes())
            primary = None
            for data in repomd.findall("r:data", ns):
                location = data.find("r:location", ns)
                if location is None or set(location.attrib) != {"href"}:
                    raise PlanningError("metadata URL override rejected")
                href = member(location.attrib["href"])
                if not href.startswith("repodata/"):
                    raise PlanningError("metadata must be inside immutable repodata")
                checksum = data.find("r:checksum", ns)
                if checksum is None or checksum.get("type") != "sha256" or digest((repo / href).read_bytes()) != checksum.text:
                    raise PlanningError("repomd metadata checksum mismatch")
                if data.get("type") == "primary":
                    if primary is not None:
                        raise PlanningError("duplicate primary metadata")
                    primary = repo / href
            if primary is None:
                raise PlanningError("missing primary metadata")
            with gzip.open(primary, "rb") as stream:
                raw = stream.read(64 * 1024 * 1024 + 1)
            if len(raw) > 64 * 1024 * 1024:
                raise PlanningError("primary metadata exceeds bound")
            document = ET.fromstring(raw)
            actual = {}
            for package in document.findall("c:package", ns):
                loc = package.find("c:location", ns)
                if loc is None or set(loc.attrib) != {"href"}:
                    raise PlanningError("package URL override rejected")
                path = "rpm/" + arch + "/" + member(loc.attrib["href"])
                checksum = package.find("c:checksum", ns)
                if path in actual or checksum is None or checksum.get("type") != "sha256":
                    raise PlanningError("ambiguous primary RPM inventory")
                actual[path] = checksum.text
            if actual != {p: h for p, h in advertised.items() if p.startswith("rpm/" + arch + "/")}:
                raise PlanningError("primary metadata/exact result mismatch")
            if any("{http://www.w3.org/XML/1998/namespace}base" in node.attrib for tree in (repomd, document) for node in tree.iter()):
                raise PlanningError("metadata XML base override rejected")
        except (ET.ParseError, OSError, EOFError) as exc:
            raise PlanningError("malformed or unavailable repository metadata") from exc


class Client(V3Client):
    """Reuses V3 flock and fsync+rename; one pointer commits repo+state together."""
    def __init__(self, root, *, origin, context, publication_key, publication_pin, roots, clock, ca=None, scope=None):
        from psop_pages import checked_origin
        self.root = require_test_root(root)
        self.origin = checked_origin(origin, scope=scope)
        self.context, self.publication_key, self.publication_pin = context, publication_key, publication_pin
        self.clock, self.roots, self.ca, self.scope = clock, copy.deepcopy(roots), copy.deepcopy(ca), scope
        if set(roots) != {"rpm", "metadata"} or roots["rpm"]["fingerprint"] == roots["metadata"]["fingerprint"]:
            raise PlanningError("independent preinstalled signing roles required")
        self._roots()
        self.key_bytes = {r: pathlib.Path(v["path"]).read_bytes() for r, v in self.roots.items()}
        if any(digest(self.key_bytes[r]) != v["sha256"] for r, v in self.roots.items()):
            raise PlanningError("public roots changed while freezing")

    def _roots(self):
        for role, value in self.roots.items():
            if set(value) != {"path", "sha256", "fingerprint"}:
                raise PlanningError("closed preinstalled public root contract required")
            path = pathlib.Path(value["path"])
            if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != value["sha256"]:
                raise PlanningError("preinstalled public key pin mismatch")
        if self.ca is not None:
            path = pathlib.Path(self.ca["path"])
            if set(self.ca) != {"path", "sha256"} or path.is_symlink() or digest(path.read_bytes()) != self.ca["sha256"]:
                raise PlanningError("pinned test HTTPS CA mismatch")

    def verify(self, raw, *, reader=None):
        from psop_pages import HTTPSReader
        require_test_root(self.root)
        self._roots()
        d = verify_envelope(raw, self.publication_key, self.publication_pin, self.context, now=self.clock())
        validate_schema(d, "psop-client-descriptor-v1")
        if (d["context"] != self.context or d["origin"] != self.origin
                or d["previous_generation"] != d["generation"] - 1
                or (d["generation"] == 1) != (d["previous_result_sha256"] is None)
                or d["metadata_key"] != {k: self.roots["metadata"][k] for k in ("sha256", "fingerprint")}):
            raise PlanningError("descriptor lineage/origin/preinstalled role mismatch")
        receipt = d["receipt"]
        validate_schema(receipt, "psop-publication-v1")
        if (sha(receipt) != d["receipt_sha256"] or receipt["context"] != self.context or receipt["status"] != "COMPLETE"
                or receipt["writer"] != "psop-stable" or receipt["result_sha256"] != d["result_sha256"]
                or receipt["publication_sha256"] != d["publication_sha256"]):
            raise PlanningError("descriptor/receipt result mismatch")
        reader = reader or HTTPSReader(self.origin, d["result_sha256"], receipt["attempt"], ca=self.ca, scope=self.scope)
        publication = reader.publication()
        if digest(publication) != d["publication_sha256"]:
            raise PlanningError("public publication identity mismatch")
        p0 = strict_json(publication).get("payload", {})
        p = verify_envelope(publication, self.publication_key, self.publication_pin, self.context, now=p0.get("issued_at", -1))
        if (set(p) != {"context", "writer", "result_sha256", "signed_inventory", "approval_sha256", "review", "metadata_key",
                "production_activation", "publishable", "issued_at", "expires_at"}
                or p["context"] != self.context or p["writer"] != "psop-stable" or p["publishable"] is not False
                or p["production_activation"] != "BLOCKED" or p["signed_inventory"] != d["signed_inventory"]
                or p["result_sha256"] != d["result_sha256"] or p["approval_sha256"] != receipt["approval_sha256"]
                or p["metadata_key"] != d["metadata_key"]):
            raise PlanningError("exact SignedResult/publication binding mismatch")
        review = p["review"]
        validate_schema(review, "psop-review-v1")
        if (review["context"] != self.context or review["result_sha256"] != d["result_sha256"]
                or review["previous_stable_sha256"] != d["previous_result_sha256"]
                or review["evidence_sha256"] != receipt["evidence_sha256"]):
            raise PlanningError("candidate/result/review/receipt mismatch")
        inv = d["signed_inventory"]
        paths = [member(x["path"]) for x in inv]
        if len(set(paths)) != len(paths) or paths != sorted(paths):
            raise PlanningError("noncanonical or duplicate signed inventory")
        unsigned = [x for x in inv if not x["path"].endswith(".asc")]
        signatures = {x["path"] for x in inv if x["path"].endswith(".asc")}
        expected = {"test-metadata-public.asc", "psop-result-v1.json.asc", *(
            "rpm/" + arch + "/repodata/repomd.xml.asc" for arch in ("x86_64", "aarch64", "source"))}
        if signatures != expected or sha(unsigned) != d["result_sha256"]:
            raise PlanningError("approved unsigned result inventory mismatch")
        stage = pathlib.Path(tempfile.mkdtemp(prefix=".verified-", dir=self.root))
        try:
            for item in inv:
                data = reader.read(item["path"])
                if digest(data) != item["sha256"]:
                    raise PlanningError("missing/mixed/stale immutable member")
                path = stage / item["path"];path.parent.mkdir(parents=True, exist_ok=True);path.write_bytes(data)
            if (stage / "test-metadata-public.asc").read_bytes() != pathlib.Path(self.roots["metadata"]["path"]).read_bytes():
                raise PlanningError("embedded key cannot replace preinstalled trust")
            with tempfile.TemporaryDirectory(prefix=".public-gpg-", dir=self.root) as temp:
                home = pathlib.Path(temp)
                ring = _keyring(self.roots["metadata"]["path"], self.roots["metadata"]["sha256"], home)
                for role, root in self.roots.items():
                    validate_role_public_key(root["path"], root["fingerprint"], home / "gnupg")
                manifest = _signature(stage, "psop-result-v1.json", ring)
                for arch in ("x86_64", "aarch64", "source"):
                    path = stage / "rpm" / arch / "repodata/repomd.xml"
                    _verify(["gpgv", "--keyring", str(ring), str(path) + ".asc", str(path)])
            fields = {"domain", "plan_sha256", "source_sha256", "policy_sha256", "packages", "parameters",
                      "previous_stable_sha256", "publishable", "rpm_signing_fingerprint"}
            if (set(manifest) != fields or manifest["domain"] != "psop-result-test-1" or manifest["publishable"] is not False
                    or manifest["plan_sha256"] != review["plan_sha256"] or manifest["source_sha256"] != review["inputs_sha256"]
                    or manifest["policy_sha256"] != review["policy_sha256"]
                    or manifest["previous_stable_sha256"] != review["previous_stable_sha256"]
                    or manifest["rpm_signing_fingerprint"] != self.roots["rpm"]["fingerprint"]):
                raise PlanningError("signed candidate/result manifest binding mismatch")
            advertised, identities = {}, set()
            for entry in manifest["packages"]:
                name, _, _, _, arch = _parse(entry)
                if (name, arch) in identities:
                    raise PlanningError("duplicate package identity in signed result")
                identities.add((name, arch))
                for view in (("source",) if arch in {"src", "nosrc"} else ("x86_64", "aarch64") if arch == "noarch" else (arch,)):
                    advertised["rpm/" + view + "/" + member(entry["filename"])] = entry["published_signed_artifact_sha256"]
            actual = {x["path"]: x["sha256"] for x in inv if x["path"].endswith(".rpm")}
            if actual != advertised or not actual:
                raise PlanningError("manifest/full RPM inventory mismatch")
            verify_metadata_links(stage, advertised)
            verify_signed_rpms(sorted(stage.rglob("*.rpm")), pathlib.Path(self.roots["rpm"]["path"]))
            if self.clock() >= d["expires_at"]:
                raise PlanningError("descriptor expired during complete verification")
            view = VerifiedView({**d, "packages": manifest["packages"]}, raw, stage, frozen_tree(stage))
            return view
        except BaseException:
            shutil.rmtree(stage)
            raise

    def active(self):
        path = self.root / "active.json"
        if path.is_symlink():
            raise PlanningError("unsafe active client state")
        if not path.exists():
            return None
        value = strict_json(path.read_bytes())
        if set(value) != {"generation", "result_sha256", "descriptor_sha256", "packages", "slot"} or not re.fullmatch(r"slot-[a-f0-9]{64}", value["slot"]):
            raise PlanningError("corrupt client state")
        return value

    def _lineage(self, view, active, pending, resume, intent):
        d = view.descriptor
        if pending is not None and (pending != intent or not resume):
            raise PlanningError("unresolved client transaction blocks switching; explicit same-view resume required")
        if active is not None:
            if d["generation"] <= active["generation"] or (d["previous_generation"], d["previous_result_sha256"]) != (active["generation"], active["result_sha256"]):
                raise PlanningError("descriptor replay/rollback or missing lineage")
            old = {(_parse(x)[0], x["architecture"]): x for x in active["packages"]}
            if any(key in old and evr_compare(x, old[key]) < 0 for x in d["packages"] for key in [(_parse(x)[0], x["architecture"])]):
                raise PlanningError("package downgrade requires separate rollback policy; BLOCKED")

    def update(self, raw, *, reader=None, operation=None, packages=(), resume=False, inject=lambda _: None):
        with self.locked():
            pending_path = self.root / "pending.json"
            if pending_path.is_symlink():
                raise PlanningError("unsafe pending transaction")
            pending = strict_json(pending_path.read_bytes()) if pending_path.exists() else None
            view = self.verify(raw, reader=reader)
            try:
                active = self.active()
                intent = {"descriptor_sha256": digest(raw), "generation": view.descriptor["generation"],
                          "operation": operation, "packages": list(packages)}
                # A crash after the single active-pointer rename has already
                # committed repo+state. Clear only the exact matching journal;
                # never run DNF twice or relax replay/lineage rules.
                if (resume and pending == intent
                        and active is not None and active["descriptor_sha256"] == digest(raw)):
                    pending_path.unlink();self._sync_root()
                    return {"scope": "psop-client-disposable", "recovered_active_commit": True,
                        "generation": active["generation"], "production_activation": "BLOCKED", "publishable": False}
                self._lineage(view, active, pending, resume, intent)
                view.check()
                slot_name = "slot-" + digest(raw)
                slot = self.root / slot_name
                if slot.is_symlink():
                    raise PlanningError("unsafe client slot")
                slot.mkdir(exist_ok=True)
                repos = slot / "repos";repos.mkdir(exist_ok=True)
                if repos.is_symlink():
                    raise PlanningError("unsafe client repos")
                root_bundle = b"\n".join(self.key_bytes[r] for r in ("rpm", "metadata"))
                # Merge separate role exports before DNF deduplicates common primary IDs.
                with tempfile.TemporaryDirectory(prefix=".keys-", dir=self.root) as temp:
                    home = pathlib.Path(temp);keys = home / "input.asc";keys.write_bytes(root_bundle)
                    subprocess.run(["gpg", "--no-options", "--homedir", str(home), "--batch", "--import", str(keys)], check=True, capture_output=True)
                    merged = subprocess.run(["gpg", "--no-options", "--homedir", str(home), "--batch", "--armor", "--export"], check=True, capture_output=True).stdout
                self._atomic(slot / "roots.asc", merged)
                repo = ("[ro-psop-test]\nname=PSOP verified disposable view\nenabled=1\nbaseurl=" + self.origin + "/psop/snapshots/" + view.descriptor["result_sha256"] + "/rpm/$basearch\n"
                    "gpgcheck=1\nrepo_gpgcheck=1\nsslverify=1\nskip_if_unavailable=0\nmetadata_expire=0\ngpgkey=file://" + str(slot / "roots.asc") + "\n")
                if self.ca is not None:
                    self._atomic(slot / "ca.pem", pathlib.Path(self.ca["path"]).read_bytes())
                    repo += "sslcacert=" + str(slot / "ca.pem") + "\n"
                self._atomic(repos / "ro-psop-test.repo", repo.encode())
                command = None
                if operation is not None:
                    payload = slot / "payload"
                    if payload.exists():
                        if frozen_tree(payload) != view.inventory:
                            raise PlanningError("frozen transaction payload changed")
                    else:
                        shutil.copytree(view.path, payload)
                    if frozen_tree(payload) != view.inventory:
                        raise PlanningError("frozen DNF inventory mismatch")
                    for path in payload.rglob("*"):
                        if path.is_file():
                            with path.open("rb") as stream:
                                os.fsync(stream.fileno())
                    for path in [*sorted((p for p in payload.rglob("*") if p.is_dir()), reverse=True), payload]:
                        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                        try:
                            os.fsync(fd)
                        finally:
                            os.close(fd)
                    # No second public/CDN read after full verification. The
                    # active repo retains its immutable HTTPS URL; this separate
                    # transaction repo consumes only frozen, checked bytes.
                    transaction = slot / "transaction-repos";transaction.mkdir(exist_ok=True)
                    if transaction.is_symlink():
                        raise PlanningError("unsafe transaction repos")
                    local_repo = repo.replace(self.origin + "/psop/snapshots/" + view.descriptor["result_sha256"], "file://" + str(payload))
                    self._atomic(transaction / "ro-psop-test.repo", local_repo.encode())
                    command = self._dnf(operation, packages, transaction, view)
                inject("after-preparation")
                if self.clock() >= view.descriptor["expires_at"]:
                    raise PlanningError("descriptor expired before transaction admission")
                self._atomic(pending_path, canonical(intent))
                inject("after-journal")
                if command is not None:
                    if self.clock() >= view.descriptor["expires_at"]:
                        raise PlanningError("descriptor expired before DNF start; pending recovery required")
                    subprocess.run(command, check=True, timeout=1800, env={"PATH": os.defpath, "HOME": str(self.root), "LC_ALL": "C"})
                    if operation != "makecache":
                        expected = {e["nevra"] for e in view.descriptor["packages"] if _parse(e)[0] in packages and e["architecture"] in {"x86_64", "noarch"}}
                        installed = subprocess.run(["rpm", "--root", str(self.root / "dnf-root"), "-q", *packages,
                            "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n"], check=True, capture_output=True, text=True, timeout=30)
                        if set(installed.stdout.splitlines()) != expected:
                            raise PlanningError("DNF success did not install exact verified NEVRA")
                inject("after-transaction")
                state = {"generation": view.descriptor["generation"], "result_sha256": view.descriptor["result_sha256"],
                    "descriptor_sha256": digest(raw), "packages": view.descriptor["packages"], "slot": slot_name}
                self._atomic(slot / "descriptor.json", raw)
                self._atomic(self.root / "active.json", canonical(state))
                inject("after-active")
                pending_path.unlink();self._sync_root()
                return {"scope": "psop-client-disposable", "generation": state["generation"], "result_sha256": state["result_sha256"],
                    "descriptor_sha256": digest(raw), "publication_sha256": view.descriptor["publication_sha256"],
                    "receipt_sha256": view.descriptor["receipt_sha256"], "verified_inventory_paths": len(view.inventory),
                    "origin": self.origin, "repo_sha256": digest(repo.encode()),
                    "view_verification": "PASS", "dnf5": "UNVERIFIED" if command is None else "PASS",
                    "global_latest": "UNVERIFIED", "production_activation": "BLOCKED", "publishable": False}
            finally:
                shutil.rmtree(view.path)

    def _sync_root(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _dnf(self, operation, packages, repos, view):
        if operation not in {"install", "upgrade", "makecache"}:
            raise PlanningError("rollback/downgrade or arbitrary DNF command BLOCKED")
        names = {_parse(x)[0] for x in view.descriptor["packages"] if x["architecture"] in {"x86_64", "noarch"}}
        if (operation != "makecache" and not packages or operation == "makecache" and packages
                or any(not isinstance(x, str) or x not in names for x in packages)):
            raise PlanningError("only exact verified package names may reach DNF")
        installroot = self.root / "dnf-root"
        if installroot.is_symlink():
            raise PlanningError("unsafe DNF installroot")
        installroot.mkdir(exist_ok=True)
        # V3's path/command guard is also applied; callers never supply flags.
        command = ["dnf5", "-y", "--installroot=" + str(installroot), "--releasever=44", "--no-plugins"]
        V3Client._command(self, command)
        return [*command, "--config=/dev/null", "--setopt=reposdir=" + str(repos), "--disable-repo=*", "--enable-repo=ro-psop-test",
            "--setopt=cachedir=" + str(self.root / "dnf-cache"), "--setopt=logdir=" + str(self.root / "dnf-logs"), "--setopt=install_weak_deps=False",
            "--setopt=ro-psop-test.gpgcheck=1", "--setopt=ro-psop-test.repo_gpgcheck=1", "--setopt=ro-psop-test.sslverify=1",
            "--setopt=ro-psop-test.skip_if_unavailable=0", operation, *packages]
