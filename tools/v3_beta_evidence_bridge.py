"""Read-only V3 bridge: GPG-checked local beta archives + live Actions metadata.

This is a consistency check, NOT an authenticated production attestation:
the caller supplies the archive, registry and public-key hash, and no Pages
branch provenance, remote bytes, or protected runner identity are proven here.
No workflow dispatch, branch write, signing or promotion is performed.
"""
import argparse
import json
import os
import pathlib

from v3_promotion_planner import PlanningError
from v3_signed_beta_history import _json_file, signed_archive_bundle
from v3_github_beta_api import collect, github_json
from v3_github_beta_audit import validate_history

REPOSITORY = "Project-Ro-ASD/Ro-Repo"
COLLECTION_SCOPE = "v3-github-beta-api-collection-untrusted"


def verify_evidence(collection, publication_root, snapshot_root, registry,
                    group, key_path, key_sha256, now):
    """Check exact successful-run coverage and selected-group timing, fail closed.

    Tests call this with mocked inputs. A real invocation must fetch API
    metadata and independently obtain the locally staged signed archive.
    """
    if (not isinstance(collection, dict)
            or collection.get("scope") != COLLECTION_SCOPE
            or collection.get("repository") != REPOSITORY
            or collection.get("publishable") is not False
            or collection.get("api_response_immutability_verified") is not False
            or collection.get("archive_completeness_verified") is not False):
        raise PlanningError("unexpected or unsafe GitHub collection identity")
    runs = collection.get("run_details")
    jobs = collection.get("job_details")
    total = collection.get("total_workflow_runs")
    successes = collection.get("successful_runs")
    if (not isinstance(runs, list) or not isinstance(jobs, list)
            or type(total) is not int or type(successes) is not int
            or total < 0 or successes < 0 or successes > total
            or successes != len(runs) or successes != len(jobs)):
        raise PlanningError("inconsistent GitHub collection counts")

    bundle = signed_archive_bundle(
        publication_root, snapshot_root, registry, group,
        key_path, key_sha256, now,
    )
    # This checks each successful GitHub run and all its sign/publish/verify
    # jobs, including runs without the selected group, against EVERY signed
    # archive record. A partial or forged archive must not pass.
    timed_rows = validate_history(
        bundle, collection["run_details"], collection["job_details"], now,
    )
    return {
        "scope": "v3-local-signed-beta-and-api-consistency-untrusted",
        "repository": REPOSITORY,
        "promotion_group": group,
        "signed_publications_checked": len(bundle["signed_publications"]),
        "successful_github_runs_checked": successes,
        "matching_candidate_publications": len(timed_rows),
        "candidate_remote_verify_times": timed_rows,
        "signature_checks_on_supplied_local_archive_completed": True,
        "caller_supplied_metadata_public_key_sha256_checked": True,
        "signed_archive_matches_successful_api_run_and_job_records": True,
        "api_source_authenticated_by_protected_runner": False,
        "metadata_key_pin_independently_authenticated": False,
        "pages_storage_branch_and_commit_verified": False,
        "remote_pages_bytes_rechecked": False,
        "archive_completeness_verified": False,
        "approval_granted": False,
        "publishable": False,
    }


def main():
    p = argparse.ArgumentParser(description="Read-only beta archive/Actions consistency check (no publication)")
    p.add_argument("--publications", required=True, help="Local signed beta publications archive root")
    p.add_argument("--snapshots", required=True, help="Local signed snapshot manifests root")
    p.add_argument("--registry", required=True, help="Local producer registry JSON")
    p.add_argument("--promotion-group", required=True)
    p.add_argument("--metadata-key", required=True, help="Metadata signing public key (not private key)")
    p.add_argument("--metadata-key-sha256", required=True, help="Out-of-band pinned public-key file SHA-256")
    p.add_argument("--now", required=True, help="UTC timestamp")
    p.add_argument("--output", required=True, help="New test-only JSON report file")
    a = p.parse_args()

    output = pathlib.Path(a.output)
    if output.exists() or output.is_symlink():
        raise PlanningError("refusing to overwrite or follow evidence output")
    if not os.environ.get("GITHUB_TOKEN"):
        raise PlanningError("GITHUB_TOKEN required for read-only Actions API access")
    registry = _json_file(pathlib.Path(a.registry))
    collection = collect(REPOSITORY, os.environ["GITHUB_TOKEN"], github_json)
    report = verify_evidence(
        collection, a.publications, a.snapshots, registry,
        a.promotion_group, a.metadata_key, a.metadata_key_sha256, a.now,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "signed_publications_checked": report["signed_publications_checked"],
        "matching_candidate_publications": report["matching_candidate_publications"],
        "publishable": False,
    }))


if __name__ == "__main__":
    main()
