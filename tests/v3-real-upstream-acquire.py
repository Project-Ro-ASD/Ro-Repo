"""Read-only Fedora acquisition for disposable real-package acceptance.

Metadata is frozen against official metalink SHA256 before dependency solving.
DNF only prints URLs from local metadata; acquisition then downloads exact
checksummed RPMs over the captured HTTPS origin. No install or publication here.
Pins observed in this test are not an independent production attestor.
"""
import concurrent.futures
import hashlib
import json
import pathlib
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_pinned_upstream import member, repomd_members
from v3_promotion_planner import PlanningError


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise PlanningError("acquisition redirect rejected")


def get(url, target, expected=None, limit=128 * 1024 * 1024):
    if not url.startswith("https://"):
        raise PlanningError("acquisition requires HTTPS")
    target.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
    checksum, size = hashlib.sha256(), 0
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=45) as response, target.open("xb") as output:
            while block := response.read(1024 * 1024):
                size += len(block)
                if size > limit:
                    raise PlanningError("bounded acquisition object")
                checksum.update(block)
                output.write(block)
        if expected is not None and checksum.hexdigest() != expected:
            raise PlanningError("acquisition checksum mismatch")
        return checksum.hexdigest()
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def safe_relative(path):
    if not isinstance(path, str) or not path:
        raise PlanningError("unsafe acquisition member")
    relative = pathlib.PurePosixPath(path)
    if (relative.is_absolute() or ".." in relative.parts or
            relative.as_posix() != path or any(c in path for c in (":", "%", "\\", "?", "#", "\n", "\r", "\0"))):
        raise PlanningError("unsafe acquisition member")
    return path


def main(work, pages):
    work, pages = pathlib.Path(work), pathlib.Path(pages)
    work.mkdir()
    repos = work / "repos"
    repos.mkdir()
    ns = "{http://linux.duke.edu/metadata/repo}"
    receipts = {}
    for name, feed in (("release", "fedora-44"), ("updates", "updates-released-f44")):
        metalink = work / (name + "-metalink.xml")
        get("https://mirrors.fedoraproject.org/metalink?repo=" + feed + "&arch=x86_64", metalink, limit=2 * 1024 * 1024)
        xml = ET.fromstring(metalink.read_bytes())
        pinned = next(e.text for e in xml.iter() if e.tag.endswith("hash") and e.get("type") == "sha256")
        urls = [e.text for e in xml.iter() if e.tag.endswith("url") and (e.text or "").startswith("https://")]
        root = work / name
        root.mkdir()
        failures = []
        for url in urls[:8]:
            try:
                get(url, root / "repodata/repomd.xml", pinned, limit=1024 * 1024)
                origin = url.removesuffix("repodata/repomd.xml")
                break
            except Exception as exc:
                failures.append(type(exc).__name__ + ": " + str(exc))
        else:
            raise PlanningError("no HTTPS mirror matches captured metalink: " + str(failures))
        entries = ET.fromstring((root / "repodata/repomd.xml").read_bytes()).findall(ns + "data")
        jobs = [(e.find(ns + "location").get("href"), e.findtext(ns + "checksum")) for e in entries]
        if sum(int(e.findtext(ns + "size", "0")) for e in entries) > 512 * 1024 * 1024:
            raise PlanningError("bounded metadata repository")
        def download(pair):
            path, checksum = pair
            safe_relative(path)
            return path, get(origin + path, root / path, checksum)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            downloaded = dict(pool.map(download, jobs))
        metadata = repomd_members(root, pinned)
        receipts[name] = {"origin": origin, "repomd_sha256": pinned, "metadata_sha256": downloaded,
                          "primary": metadata["primary"], "mirror_failures": failures, "packages": []}
        (repos / (name + ".repo")).write_text("[pinned-fedora-" + name + "]\nname=Frozen test input\nbaseurl=file://" + str(root) +
                  "\nenabled=0\ngpgcheck=1\nrepo_gpgcheck=0\n")
        print("Frozen official metadata:", name, pinned, flush=True)
    snapshots = pages / "snapshots/fedora/44"
    for name, snapshot in (("current", "repo-f44-20261009-001"), ("previous", "repo-f44-20260920-001")):
        (repos / (name + ".repo")).write_text("[ro-" + name + "]\nname=Captured signed Ro input\nbaseurl=file://" +
            str(snapshots / snapshot / "rpm/x86_64") + "\nenabled=0\ngpgcheck=1\nrepo_gpgcheck=0\n")
    common = ["dnf", "--use-host-config", "--releasever=44", "--setopt=reposdir=" + str(repos),
              "--setopt=install_weak_deps=False", "--setopt=cachedir=" + str(work / "solver-cache"),
              "--setopt=persistdir=" + str(work / "solver-persist"), "--installroot=" + str(work / "solver-root"),
              "--repo=pinned-fedora-release", "--repo=pinned-fedora-updates", "--repo=ro-current", "--repo=ro-previous"]
    cases = {"assist-previous": ["ro-assist-0:0.2.4-1.fc44.x86_64"],
             "assist-current": ["ro-assist-0:0.2.5-1.fc44.x86_64"],
             "dolphin": ["dolphin-0:26.08.1-1.roasd1.fc44.x86_64", "dolphin-libs-0:26.08.1-1.roasd1.fc44.x86_64", "dolphin-devel-0:26.08.1-1.roasd1.fc44.x86_64"],
             "installer": ["ro-installer-0:2.4.4-1.fc44.x86_64"],
             "noarch": [p["nevra"] for p in json.loads((snapshots / "repo-f44-20261009-001/repository-snapshot-v1.json").read_bytes())["packages"] if p["architecture"] == "noarch"]}
    selected, outcomes = set(), {}
    for name, targets in cases.items():
        result = subprocess.run(common + ["download", "--resolve", "--alldeps", "--url", "--from-repo=ro-current,ro-previous", *targets],
                                capture_output=True, text=True, timeout=180)
        (work / (name + "-solve.log")).write_text(result.stdout + result.stderr)
        outcomes[name] = "PASS" if result.returncode == 0 else "FAIL"
        if result.returncode == 0:
            selected.update(line for line in result.stdout.splitlines() if line.startswith("file://"))
        print("Actual package solver:", name, outcomes[name], flush=True)
    for name, receipt in receipts.items():
        root = work / name
        paths = {url.removeprefix("file://" + str(root) + "/") for url in selected if url.startswith("file://" + str(root) + "/")}
        for path in paths:
            safe_relative(path)
        primary = work / (name + "-primary.xml")
        with primary.open("wb") as output:
            subprocess.run(["zstd", "-q", "-d", "-c", "--", str(member(root, receipt["primary"]))], stdout=output, check=True, timeout=60)
        common_ns = "{http://linux.duke.edu/metadata/common}"
        package_bytes = 0
        for _, element in ET.iterparse(primary, events=("end",)):
            if element.tag == common_ns + "package":
                path = element.find(common_ns + "location").get("href")
                if path in paths:
                    package_bytes += int(element.find(common_ns + "size").get("package"))
                    version = element.find(common_ns + "version")
                    nevra = (element.findtext(common_ns + "name") + "-" + version.get("epoch", "0") + ":" + version.get("ver") + "-" +
                             version.get("rel") + "." + element.findtext(common_ns + "arch"))
                    receipt["packages"].append({"path": path, "nevra": nevra, "sha256": element.findtext(common_ns + "checksum")})
                element.clear()
        primary.unlink()
        if {p["path"] for p in receipt["packages"]} != paths or len(paths) > 1000 or package_bytes > 2 * 1024 ** 3:
            raise PlanningError("solver URLs differ from pinned primary inventory")
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(lambda p: get(receipt["origin"] + p["path"], root / p["path"], p["sha256"]), receipt["packages"]))
        print("Captured exact signed-RPM candidates:", name, len(paths), flush=True)
    (work / "acquisition.json").write_text(json.dumps({"scope": "v3-real-upstream-acquisition-test-only", "publishable": False,
          "feeds": receipts, "solver": outcomes, "independent_production_attestor": "UNVERIFIED"}, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
