#!/usr/bin/env python3
"""Local HTTPS acceptance or separately authorized READ-ONLY external Pages."""
import argparse
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from psop_acceptance_support import exercise
from psop_client import Client
from psop_pages import ExternalScope, verify_external
from v3_backend_trust import canonical, strict_json, test_workspace


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=("local", "external"), default="local")
    p.add_argument("--output", required=True, type=pathlib.Path)
    p.add_argument("--authorization", type=pathlib.Path)
    p.add_argument("--client-pins", type=pathlib.Path)
    p.add_argument("--descriptor", type=pathlib.Path)
    for name in ("commit", "build-id", "deployment-id", "run-id"):p.add_argument("--" + name)
    a = p.parse_args()
    if a.output.exists():raise ValueError("immutable acceptance output already exists")
    if a.mode == "local":
        exercise(a.output, dnf=False)
    elif a.authorization is None:
        a.output.write_bytes(canonical({"scope": "external-disposable-pages", "status": "BLOCKED",
            "reason": "NO_PREEXISTING_EXPLICITLY_AUTHORIZED_TEST_TARGET", "network_requests": 0,
            "production_activation": "BLOCKED", "publishable": False}) + b"\n")
        return 2
    else:
        # Inventory is provided by an explicitly authorizing human. This tool
        # never creates permissions, a repository, a key or a Pages deployment.
        scope = ExternalScope(strict_json(a.authorization.read_bytes()), now=int(time.time()))
        if not all((a.client_pins, a.descriptor, a.commit, a.build_id, a.deployment_id, a.run_id)):
            p.error("external observation needs independently pinned public roots and exact identities")
        pins = strict_json(a.client_pins.read_bytes())
        root = test_workspace()
        try:
            client = Client(root, origin=scope.value["origin"], context=pins["context"],
                publication_key=pathlib.Path(pins["publication_key"]).read_bytes(), publication_pin=pins["publication_pin"],
                roots=pins["roots"], clock=lambda: int(time.time()), scope=scope)
            report = verify_external(scope, client, a.descriptor.read_bytes(), commit=a.commit,
                build_id=a.build_id, deployment_id=a.deployment_id, run_id=a.run_id)
            a.output.write_bytes(canonical(report) + b"\n")
        finally:
            import shutil
            shutil.rmtree(root)
    return 0


if __name__ == "__main__":
    sys.exit(main())
