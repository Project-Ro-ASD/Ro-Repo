"""Exact source/runtime identity collector; never reads credential variables."""
import os
import pathlib
import subprocess

from v3_backend_trust import digest
from v3_policy_profile import sha

ROOT = pathlib.Path(__file__).parents[1]


def source_inventory():
    files = []
    for folder in ("tools", "tests", "schemas", "config", "keys", "scripts", ".github/workflows"):
        for path in (ROOT / folder).rglob("*"):
            if path.is_file() and path.suffix in {".py", ".sh", ".yml", ".json", ".asc"}:
                files.append({"path": path.relative_to(ROOT).as_posix(), "sha256": digest(path.read_bytes()),
                              "mode": oct(path.stat().st_mode & 0o777)})
    return sorted(files, key=lambda x: x["path"])


def capture():
    inventory = source_inventory()
    git = ["git", "-c", "safe.directory=" + str(ROOT), "-C", str(ROOT)]
    head = subprocess.check_output([*git, "rev-parse", "HEAD"], text=True).strip()
    dirty = bool(subprocess.check_output([*git, "status", "--porcelain"], text=True).strip())
    return {"source_head": head, "source_dirty": dirty, "source_inventory": inventory,
        "source_inventory_sha256": sha(inventory), "github": {k: os.environ.get(k) for k in (
            "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW_REF", "GITHUB_HEAD_REF")},
        "claim": "execution observation; not authenticated production test authority"}
