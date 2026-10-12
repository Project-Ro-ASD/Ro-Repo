"""Read-only machine evidence and manual real acceptance preparation.

This kit never installs packages, launches an installer or operates on disks.
Application/GUI/boot results remain UNVERIFIED until a maintainer supplies
actual per-case evidence through the existing signed acceptance contracts.
"""
import argparse
import datetime as dt
import json
import pathlib
import platform
import subprocess

from v3_backend_trust import digest, canonical
from v3_promotion_planner import PlanningError

COMMANDS = {
    "os": ["cat", "/etc/os-release"], "architecture": ["uname", "-m"],
    "boot": ["cat", "/proc/sys/kernel/random/boot_id"],
    "dnf": ["dnf5", "--version"], "packages": ["rpm", "-qa", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n"],
    "disks": ["lsblk", "--json", "--output", "NAME,TYPE,SIZE,RO,MOUNTPOINTS"],
    "repos": ["dnf5", "--cacheonly", "repo", "list", "--enabled"],
    "virt": ["systemd-detect-virt"],
}
CASES = ["assist-install", "assist-upgrade", "assist-runtime", "dolphin-plasma", "installer-gui",
         "installer-disposable-vm", "boot", "reboot", "repo-isolation", "component-upgrade",
         "config-preservation", "package-conflicts", "recovery"]


def collect(output, *, environment, run=subprocess.run):
    output = pathlib.Path(output)
    if output.exists() or output.is_symlink() or environment not in {"laptop-x86_64", "university-desktop", "qemu-ro-asd", "native-aarch64", "emulated-aarch64"}:
        raise PlanningError("new evidence directory and exact real/emulated environment required")
    output.mkdir(mode=0o700, parents=True)
    observations = {}
    for name, command in COMMANDS.items():
        try:
            result = run(command, capture_output=True, timeout=60)
            raw = result.stdout + b"\nSTDERR\n" + result.stderr
            code = result.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            raw, code = type(exc).__name__.encode(), None
        (output / (name + ".log")).write_bytes(raw)
        observations[name] = {"command": command, "exit_code": code, "sha256": digest(raw)}
    report = {"schema_version": 3, "scope": "v3-hardware-readonly-observation", "publishable": False,
        "environment": environment, "architecture": platform.machine(), "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "observations": observations, "cases": {case: {"result": "UNVERIFIED", "evidence": []} for case in CASES},
        "production_activation": "BLOCKED", "authenticated_runner": "UNVERIFIED"}
    (output / "observation.json").write_bytes(canonical(report))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--environment", required=True)
    args = parser.parse_args()
    print(json.dumps(collect(args.output, environment=args.environment), indent=2))
