"""Freeze independently attested Fedora 44 metadata and exact RPM cache.

Fedora repositories need not supply detached repomd signatures. Such inputs
require an independent signed metadata pin, rather than pretending HTTPS or
an unsigned metalink authenticates a repository. No system-repo fallback.
"""
import hashlib
import pathlib
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import gzip
import bz2
import lzma

from v3_backend_trust import TOKEN, digest, require_attestation, HEX
from v3_integration import tree_inventory
from v3_policy_profile import sha
from v3_promotion_planner import PlanningError
from v3_stable_composer import _sha256


def member(root, relative):
    if not isinstance(relative, str) or any(c in relative for c in ("\\", "%", ":", "?", "#", "\n", "\r", "\0")):
        raise PlanningError("invalid upstream member")
    path = pathlib.PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != relative or not path.parts:
        raise PlanningError("unsafe upstream member")
    target = pathlib.Path(root) / relative
    if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(pathlib.Path(root).resolve()):
        raise PlanningError("missing/unsafe pinned upstream member")
    return target


def repomd_members(root, expected):
    raw = member(root, "repodata/repomd.xml").read_bytes()
    if digest(raw) != expected or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise PlanningError("unpinned/unsafe upstream repomd")
    try:
        xml = ET.fromstring(raw)
        if any("{http://www.w3.org/XML/1998/namespace}base" in element.attrib for element in xml.iter()):
            raise PlanningError("upstream metadata base URL overrides pinned cache")
        namespace = "{http://linux.duke.edu/metadata/repo}"
        seen, types = set(), {}
        for entry in xml.findall(namespace + "data"):
            location = entry.find(namespace + "location")
            checksum = entry.find(namespace + "checksum")
            if location is None or set(location.attrib) != {"href"} or checksum is None or checksum.get("type") != "sha256":
                raise PlanningError("upstream metadata requires SHA256 references")
            relative = location.get("href")
            kind = entry.get("type")
            if relative in seen or kind in types or not HEX.fullmatch(checksum.text or ""):
                raise PlanningError("ambiguous upstream metadata reference")
            seen.add(relative)
            types[kind] = relative
            if hashlib.sha256(member(root, relative).read_bytes()).hexdigest() != checksum.text:
                raise PlanningError("upstream metadata checksum mismatch")
        if not seen:
            raise PlanningError("empty upstream repodata")
        return types
    except ET.ParseError as exc:
        raise PlanningError("invalid upstream repomd XML") from exc


class PinnedUpstream:
    def __init__(self, root, manifest, public_key, seal):
        if seal is not TOKEN:
            raise PlanningError("unverified upstream repository")
        self.root, self.manifest, self.public_key = pathlib.Path(root), manifest, public_key

    def check(self):
        if sha(tree_inventory(self.root)) != self.manifest["tree_sha256"]:
            raise PlanningError("pinned upstream changed")


def primary_inventory(root, metadata_path, packages):
    """DNF RPM locations/checksums must not escape the independently pinned cache."""
    file = member(root, metadata_path)
    opener = gzip.open if file.suffix == ".gz" else bz2.open if file.suffix == ".bz2" else lzma.open if file.suffix in {".xz", ".lzma"} else open
    limit = 512 * 1024 * 1024
    if file.suffix == ".zck":
        raise PlanningError("zchunk-only primary decoder provisioning BLOCKED")
    try:
        if file.suffix == ".zst":
            if shutil.which("zstd") is None:
                raise PlanningError("pinned upstream Zstandard decoder unavailable; BLOCKED")
            process = subprocess.Popen(["zstd", "-q", "-d", "-c", "--", str(file)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                raw = process.stdout.read(limit + 1)
                if len(raw) > limit:
                    raise PlanningError("bounded upstream primary XML")
                if process.wait(timeout=60):
                    raise PlanningError("invalid Zstandard upstream primary")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                process.stdout.close()
        else:
            with opener(file, "rb") as stream:
                raw = stream.read(limit + 1)
        if len(raw) > limit or b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
            raise PlanningError("unsafe/bounded upstream primary XML")
        document = ET.fromstring(raw)
        if any("{http://www.w3.org/XML/1998/namespace}base" in element.attrib for element in document.iter()):
            raise PlanningError("upstream package base URL overrides pinned cache")
        namespace = "{http://linux.duke.edu/metadata/common}"
        approved = {p["nevra"]: p for p in packages}
        found = set()
        for entry in document.findall(namespace + "package"):
            location, checksum = entry.find(namespace + "location"), entry.find(namespace + "checksum")
            version = entry.find(namespace + "version")
            if location is None or set(location.attrib) != {"href"} or checksum is None or version is None or checksum.get("type") != "sha256":
                raise PlanningError("invalid upstream primary package references")
            path = location.get("href", "")
            relative = pathlib.PurePosixPath(path)
            if (not path or relative.is_absolute() or ".." in relative.parts or relative.as_posix() != path or
                    any(c in path for c in ("\\", "%", ":", "?", "#", "\n", "\r"))):
                raise PlanningError("upstream RPM URL escapes pinned cache")
            nevra = (entry.findtext(namespace + "name", "") + "-" + version.get("epoch", "0") + ":" +
                     version.get("ver", "") + "-" + version.get("rel", "") + "." + entry.findtext(namespace + "arch", ""))
            if nevra in approved:
                if nevra in found or path != approved[nevra]["path"] or checksum.text != approved[nevra]["sha256"]:
                    raise PlanningError("upstream primary differs from exact pinned RPM inventory")
                found.add(nevra)
        if found != set(approved):
            raise PlanningError("pinned upstream RPM absent from primary metadata")
    except (ET.ParseError, OSError, EOFError, lzma.LZMAError) as exc:
        raise PlanningError("invalid compressed upstream primary metadata") from exc


def verify_upstream(root, manifest, pin, *, rpm_key, rpm_key_sha256, now):
    fields = {"schema_version", "scope", "fedora_release", "architecture", "repo_id", "tree_sha256",
              "repomd_sha256", "metadata_authentication", "rpm_key_sha256", "packages"}
    if (not isinstance(manifest, dict) or set(manifest) != fields or manifest["schema_version"] != 3 or
            manifest["scope"] != "v3-pinned-fedora-upstream" or manifest["fedora_release"] != 44 or
            manifest["architecture"] not in {"x86_64", "aarch64"} or
            not isinstance(manifest["repo_id"], str) or not re.fullmatch(r"pinned-fedora-[a-z0-9-]+", manifest["repo_id"]) or
            manifest["metadata_authentication"] not in {"gpg", "signed-pin"} or
            not isinstance(manifest["packages"], list) or not manifest["packages"]):
        raise PlanningError("invalid pinned upstream manifest")
    from ro_repo import validate_schema
    validate_schema(manifest, "pinned-upstream-v3")
    payload = require_attestation(pin, "upstream-pin")
    if payload.get("manifest") != manifest or not payload["issued_at"] <= now < payload["expires_at"]:
        raise PlanningError("independent upstream pin missing/stale")
    if pathlib.Path(rpm_key).is_symlink():
        raise PlanningError("unsafe upstream trust key")
    public = pathlib.Path(rpm_key).read_bytes()
    if digest(public) != rpm_key_sha256 or manifest["rpm_key_sha256"] != rpm_key_sha256:
        raise PlanningError("unpinned upstream RPM trust root")
    before = tree_inventory(root)
    if sha(before) != manifest["tree_sha256"]:
        raise PlanningError("upstream cache differs from independent pin")
    with tempfile.TemporaryDirectory(prefix="v3-upstream-") as directory:
        work = pathlib.Path(directory)
        frozen = work / "repo"
        shutil.copytree(root, frozen, symlinks=True)
        if tree_inventory(frozen) != before:
            raise PlanningError("upstream changed during freezing")
        metadata = repomd_members(frozen, manifest["repomd_sha256"])
        if "primary" not in metadata:
            raise PlanningError("upstream primary metadata missing")
        primary_inventory(frozen, metadata["primary"], manifest["packages"])
        key = work / "public.asc"
        key.write_bytes(public)
        if manifest["metadata_authentication"] == "gpg":
            from v3_signed_beta_history import _keyring, _verify
            ring = _keyring(key, rpm_key_sha256, work)
            _verify(["gpgv", "--keyring", str(ring), str(member(frozen, "repodata/repomd.xml.asc")), str(frozen / "repodata/repomd.xml")])
        db = work / "rpmdb"
        db.mkdir()
        def run(args):
            result = subprocess.run(args, capture_output=True, text=True, timeout=60)
            if result.returncode:
                raise PlanningError("upstream RPM verification failed: " + result.stderr[-500:])
            return result.stdout
        run(["rpm", "--dbpath", str(db), "--initdb"])
        run(["rpm", "--dbpath", str(db), "--import", str(key)])
        paths, nevras = set(), set()
        for package in manifest["packages"]:
            if set(package) != {"path", "nevra", "sha256"} or package["path"] in paths or package["nevra"] in nevras:
                raise PlanningError("ambiguous upstream package inventory")
            paths.add(package["path"])
            nevras.add(package["nevra"])
            file = member(frozen, package["path"])
            if _sha256(file) != package["sha256"]:
                raise PlanningError("upstream RPM digest mismatch")
            nevra = run(["rpm", "-qp", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}", str(file)]).strip()
            if nevra != package["nevra"] or nevra.rsplit(".", 1)[-1] not in {manifest["architecture"], "noarch"}:
                raise PlanningError("upstream NEVRA/architecture substitution")
            check = run(["rpmkeys", "--dbpath", str(db), "--checksig", str(file)])
            if (not re.search(r"\bsignatures?\b", check, re.I) or not re.search(r"\bOK\b", check) or
                    re.search(r"NOKEY|NOT OK|BAD|unsigned", check, re.I)):
                raise PlanningError("upstream RPM signature absent/untrusted")
        if {p.relative_to(frozen).as_posix() for p in frozen.rglob("*.rpm")} != paths:
            raise PlanningError("upstream RPM outside approved inventory")
        if tree_inventory(root) != before or tree_inventory(frozen) != before:
            raise PlanningError("upstream changed during validation")
    return PinnedUpstream(root, manifest, public, TOKEN)
