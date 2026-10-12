"""Read-only complete expected-file HTTP parity of a captured Pages tree.

Uses the existing fixed-origin bounded streaming transport. It cannot enumerate
unknown extra CDN files or turn an observed Git/API pin into production trust.
"""
import concurrent.futures
import hashlib
import json
import pathlib
import sys
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_remote_beta_tree import remote_file_chunks, REMOTE_ORIGIN, PREFIXES, GIT_PLACEHOLDER, _safe_path, MAX_FILE_BYTES
from v3_policy_profile import canonical
from v3_promotion_planner import PlanningError


def audit(pages, tree, output):
    pages, tree, output = map(pathlib.Path, (pages, tree, output))
    value = json.loads(tree.read_bytes())
    if value.get("truncated") or output.exists():
        raise PlanningError("incomplete inventory or existing immutable output")
    selected = [p for p in value["tree"] if p["type"] == "blob" and p["path"] != GIT_PLACEHOLDER and
                any(p["path"].startswith(prefix + "/") for prefix in PREFIXES)]
    if any(not _safe_path(p["path"]) or p.get("mode") != "100644" or type(p.get("size")) is not int or
           not 0 <= p["size"] <= MAX_FILE_BYTES for p in selected):
        raise PlanningError("unsafe captured inventory member")
    def verify(item):
        expected = hashlib.sha256((pages / item["path"]).read_bytes()).hexdigest()
        checksum, size = hashlib.sha256(), 0
        try:
            for block in remote_file_chunks(REMOTE_ORIGIN + urllib.parse.quote(item["path"], safe="/") + "?v3-audit=" + value["sha"]):
                size += len(block)
                if size > item["size"]:
                    raise PlanningError("remote object exceeds exact Git size")
                checksum.update(block)
            if size != item["size"] or checksum.hexdigest() != expected:
                raise PlanningError("remote bytes differ from captured Git blob")
            return {"path": item["path"], "sha256": expected, "bytes": size, "status": "PASS"}
        except PlanningError as exc:
            return {"path": item["path"], "sha256": expected, "status": "FAIL", "reason": str(exc)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        records = list(pool.map(verify, selected))
    result = {"scope": "v3-real-public-beta-byte-observation", "publishable": False, "pages_commit": value["sha"],
              "expected_files": len(records), "matched_files": sum(r["status"] == "PASS" for r in records), "files": records,
              "unknown_extra_remote_files": "UNVERIFIED", "independent_production_source_authority": "UNVERIFIED"}
    output.write_bytes(canonical(result) + b"\n")
    print("Public HTTPS byte parity:", result["matched_files"], "/", result["expected_files"])


if __name__ == "__main__":
    audit(*sys.argv[1:])
