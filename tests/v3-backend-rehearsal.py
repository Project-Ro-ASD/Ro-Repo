"""One isolated, cryptographic end-to-end backend rehearsal evidence bundle."""
import argparse
import hashlib
import json
import pathlib
import sys

from v3_backend_support import Keys, Fixture
from v3_policy_profile import sha
from v3_pages_backend import IsolatedGitStore, GitReader
from v3_immutable_view import verify_remote, IsolatedStore


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    output = pathlib.Path(parser.parse_args().output)
    if output.exists():
        raise RuntimeError("immutable test evidence already exists")
    root = pathlib.Path(__file__).resolve().parents[1]
    inventory = [{"path": p.relative_to(root).as_posix(), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                 for folder in ("tools", "tests", "schemas", "config") for p in sorted((root / folder).glob("*"))
                 if p.is_file() and p.suffix in {".py", ".sh", ".json"}]
    keys = Keys()
    fixture = Fixture(keys)
    try:
        fixture.advance("AUTHORIZED")
        fixture.view = IsolatedStore(fixture.root).stage(fixture.result, fixture.approval, keys.signers["publication"],
                      origin="https://test.invalid", audit_key_sha256=keys.signers["audit"].key_sha256, now=fixture.now)
        fixture.backend.signed(fixture.attempt, fixture.view)
        fixture.backend.staged(fixture.attempt, fixture.view)
        store = IsolatedGitStore(fixture.root)
        staged = store.stage(fixture.view, expected=None)
        deployment = keys.attestation("deployment", {"result_stable_sha256": fixture.result.sha256,
                     "publication_sha256": fixture.view.envelope_sha256, "git_commit": staged["git_commit"], "deployment_id": "isolated-git-test"})
        remote = verify_remote(fixture.view, GitReader(store, fixture.view), deployment, now=fixture.now)
        fixture.backend.remotely_verified(fixture.attempt, remote)
        fixture.backend.publish(fixture.attempt, fixture.approval)
        advertisement = store.advertise(fixture.view, fixture.approval, remote, keys.signers["publication"],
                     expected=staged["git_commit"], previous_digest=None, now=fixture.now)
        post_deployment = keys.attestation("deployment", {"result_stable_sha256": fixture.result.sha256,
                     "publication_sha256": fixture.view.envelope_sha256, "git_commit": advertisement["git_commit"], "deployment_id": "isolated-git-post-test"})
        post = verify_remote(fixture.view, GitReader(store, fixture.view), post_deployment, now=fixture.now,
                             post_ledger=fixture.ledger, advertisement_key=keys.signers["publication"].public,
                             advertisement_key_sha256=keys.signers["publication"].key_sha256)
        fixture.backend.post_verified(fixture.attempt, post)
        output.mkdir(parents=True)
        record = {"scope": "v3-backend-rehearsal-test-only", "publishable": False, "source_code_sha256": sha(inventory),
                  "source_inventory": inventory, "cryptographic_protocol": "PASS", "transactional_state_machine": "PASS",
                  "git_cas": "PASS", "state": fixture.ledger.inspect(fixture.attempt), "git_staging": staged,
                  "advertisement": advertisement, "real_application_acceptance": "UNVERIFIED", "real_protected_approval": "UNVERIFIED",
                  "github_pages_cdn": "UNVERIFIED", "production_activation": "BLOCKED"}
        (output / "rehearsal.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        for role, signer in keys.signers.items():
            (output / (role + "-ephemeral-public.pem")).write_bytes(signer.public)
        print("PASS: isolated signed backend and Git CAS rehearsal; production BLOCKED")
    finally:
        fixture.close()
        keys.close()


if __name__ == "__main__":
    main()
