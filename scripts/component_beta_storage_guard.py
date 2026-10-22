"""Optional exact storage precondition for V2 orchestrated writers.

Run under the existing ro-repo-pages-storage concurrency lock. The existing
fetch/expected-head/push CAS remains the final check after local staging.
"""
import os
import pathlib
import re
import subprocess
import sys
import time


def check_storage(root, request_id, expected, deadline=None):
    if not request_id and not expected:
        return  # Preserve legacy manual entry points.
    if not re.fullmatch(r"[0-9a-f]{40}", expected or ""):
        raise ValueError("orchestrated publication requires exact Pages storage commit")
    if request_id:
        if not re.fullmatch(r"[1-9][0-9]{9}", deadline or "") or time.time() >= int(deadline):
            raise ValueError("orchestrated writer deadline expired or missing")
    actual = subprocess.check_output(
        ["git", "-C", str(pathlib.Path(root)), "rev-parse", "HEAD"], text=True
    ).strip()
    if actual != expected:
        raise ValueError("Pages storage changed: stale parent or intervening publication; restart preflight")


if __name__ == "__main__":
    check_storage(sys.argv[1], os.environ.get("REQUEST_ID", ""),
                  os.environ.get("EXPECTED_STORAGE_COMMIT", ""),
                  os.environ.get("REQUEST_DEADLINE", ""))
