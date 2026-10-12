"""Native DNF metadata URL probe; query only, no RPM installation or network.

The synthetic parser repository contains no RPMs. It proves URL interpretation,
not package signature/solver/application acceptance.
"""
import hashlib
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_pinned_upstream import primary_inventory
from v3_promotion_planner import PlanningError


def main():
    with tempfile.TemporaryDirectory(prefix="v3-dnf-url-probe-") as directory:
        root = pathlib.Path(directory)
        repo, repos = root / "repo", root / "repos"
        (repo / "repodata").mkdir(parents=True)
        repos.mkdir()
        primary = '''<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="1">
<package type="rpm"><name>v3-url-probe</name><arch>x86_64</arch><version epoch="0" ver="1" rel="1"/>
<checksum type="sha256" pkgid="YES">SHA</checksum><summary>parser only</summary><description>parser only</description>
<packager/><url/><time file="1" build="1"/><size package="1" installed="1" archive="1"/>
<location xml:base="file:///v3-outside-pinned-cache/" href="probe.rpm"/>
<format><rpm:license>MIT</rpm:license><rpm:vendor/><rpm:group>test</rpm:group><rpm:buildhost>test</rpm:buildhost>
<rpm:sourcerpm>probe.src.rpm</rpm:sourcerpm><rpm:header-range start="0" end="1"/>
<rpm:provides><rpm:entry name="v3-url-probe" flags="EQ" epoch="0" ver="1" rel="1"/></rpm:provides>
</format></package></metadata>'''.replace("SHA", "a" * 64).encode()
        (repo / "repodata/primary.xml").write_bytes(primary)
        repomd = ('<repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision><data type="primary">'
                  '<checksum type="sha256">' + hashlib.sha256(primary).hexdigest() + '</checksum>'
                  '<location href="repodata/primary.xml"/><timestamp>1</timestamp><size>' + str(len(primary)) + '</size></data></repomd>')
        (repo / "repodata/repomd.xml").write_text(repomd)
        (repos / "probe.repo").write_text('[pinned-probe]\nname=Parser only\nbaseurl=file://' + str(repo) +
                                         '\nenabled=0\ngpgcheck=0\nrepo_gpgcheck=0\n')
        result = subprocess.run(["dnf", "--use-host-config", "--releasever=44", "--setopt=reposdir=" + str(repos),
                    "--setopt=cachedir=" + str(root / "cache"), "--setopt=persistdir=" + str(root / "persist"),
                    "--installroot=" + str(root / "installroot"), "--repo=pinned-probe", "repoquery", "--location"],
                    capture_output=True, text=True, timeout=60, check=True)
        print("Native DNF5 location: " + result.stdout.strip(), flush=True)
        assert "file:///v3-outside-pinned-cache/probe.rpm" in result.stdout, result.stdout
        try:
            primary_inventory(repo, "repodata/primary.xml", [{"path": "probe.rpm", "nevra": "v3-url-probe-0:1-1.x86_64", "sha256": "a" * 64}])
        except PlanningError as exc:
            print("PASS: pinned upstream rejects DNF xml:base override: " + str(exc))
        else:
            raise AssertionError("unsafe external package base URL accepted by pinned validator")


if __name__ == "__main__":
    main()
