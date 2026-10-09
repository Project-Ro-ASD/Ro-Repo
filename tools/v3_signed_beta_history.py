"""Offline first-beta-publication proof from archived, signed Ro-Repo records.

Requires *independently pinned* metadata public key SHA256. Verifies GPG
signatures, not GitHub provenance, trusted wall-clock time, or publication URL.
Never grants approval or publishes packages.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tempfile

from v3_promotion_planner import PlanningError, plan
from v3_promotion_policy import evaluate, _time

RUN = re.compile(r"^[1-9][0-9]*$")
SNAP = re.compile(r"^repo-f44-[0-9]{8}-[0-9]{3}$")
SHA = re.compile(r"^[a-f0-9]{64}$")


def _json_file(path):
    if path.is_symlink() or not path.is_file():
        raise PlanningError("missing or symlinked signed manifest")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PlanningError("malformed signed manifest JSON") from exc


def _verify(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PlanningError("metadata signature verifier unavailable") from exc
    if r.returncode != 0:
        raise PlanningError("metadata signature verification failed")


def _signature(directory, name, keyring):
    manifest = directory / name
    asc = directory / (name + ".asc")
    if directory.is_symlink() or manifest.is_symlink() or asc.is_symlink() or not manifest.is_file() or not asc.is_file():
        raise PlanningError("missing or unsafe signed metadata")
    _verify(["gpgv", "--keyring", str(keyring), str(asc), str(manifest)])
    return _json_file(manifest)


def _keyring(public_key, expected_hash, tmp):
    key = pathlib.Path(public_key)
    if key.is_symlink() or not key.is_file() or not isinstance(expected_hash, str) or not SHA.fullmatch(expected_hash):
        raise PlanningError("metadata key must have a pinned SHA256")
    if hashlib.sha256(key.read_bytes()).hexdigest() != expected_hash:
        raise PlanningError("metadata signing key pin mismatch")
    ring = pathlib.Path(tmp) / "metadata.gpg"
    _verify(["gpg", "--batch", "--no-default-keyring", "--keyring", str(ring),
             "--import", str(key)])
    return ring


def signed_history(beta_publications, snapshots, registry, candidate_group, key_path, key_sha256, now):
    """Read ALL supplied archive entries, fail closed on malformed entries.

    The caller must source complete immutable archives independently.
    GPG-signed timestamps alone do NOT prove the actual first public
    availability time. Live CI must additionally verify trusted GitHub
    publication events, archival completeness and Pages availability.
    """
    publication_root = pathlib.Path(beta_publications)
    snapshot_root = pathlib.Path(snapshots)
    if publication_root.is_symlink() or snapshot_root.is_symlink() or not publication_root.is_dir() or not snapshot_root.is_dir():
        raise PlanningError("invalid archive roots")
    rows = []
    manifests = {}
    with tempfile.TemporaryDirectory(prefix="v3-metadata-gpg-") as temp:
        keyring = _keyring(key_path, key_sha256, temp)
        folders = sorted(publication_root.iterdir())
        if not folders:
            raise PlanningError("beta archive empty")
        for directory in folders:
            if directory.is_symlink() or not directory.is_dir() or not RUN.fullmatch(directory.name):
                raise PlanningError("unexpected beta history entry")
            pub = _signature(directory, "publication-v1.json", keyring)
            if not isinstance(pub, dict) or set(pub) != {"schema_version", "channel", "publication_run", "published_at", "snapshot_id", "store_tree_sha256"}:
                raise PlanningError("unexpected signed publication fields")
            if pub["schema_version"] != 1 or pub["channel"] != "beta" or pub["publication_run"] != directory.name:
                raise PlanningError("publication identity mismatch")
            _time(pub["published_at"])
            if _time(pub["published_at"]) > _time(now):
                raise PlanningError("future-dated publication")
            if not isinstance(pub["store_tree_sha256"], str) or not SHA.fullmatch(pub["store_tree_sha256"]):
                raise PlanningError("invalid publication store digest")
            snap_id = pub["snapshot_id"]
            if not isinstance(snap_id, str) or not SNAP.fullmatch(snap_id):
                raise PlanningError("invalid snapshot identity")
            snap_dir = snapshot_root / snap_id
            if snap_id not in manifests:
                manifest = _signature(snap_dir, "repository-snapshot-v1.json", keyring)
                if not isinstance(manifest, dict) or manifest.get("schema_version") != 1 or manifest.get("snapshot_id") != snap_id or manifest.get("fedora_release") != 44:
                    raise PlanningError("snapshot mismatch")
                manifests[snap_id] = manifest
            snapshot = manifests[snap_id]
            # The selected group need not appear in every earlier snapshot.
            from v3_promotion_planner import _policies, _parse
            groups, owner = _policies(registry)
            if candidate_group not in groups:
                raise PlanningError("unknown promotion group")
            group_present = any(owner.get(_parse(p)[0]) == candidate_group for p in snapshot["packages"])
            if group_present:
                proposed = plan(snapshot, None, registry, candidate_group)
                rows.append({"publication_run": directory.name,
                             "published_at": pub["published_at"],
                             "promotion_group": candidate_group,
                             "candidate_sha256": proposed["candidate_sha256"]})
    return rows


def assess(candidate, archive_root, snapshot_root, registry, key, key_sha, risk, mode, now, reason=None):
    history = signed_history(archive_root, snapshot_root, registry, candidate["promotion_group"], key, key_sha, now)
    outcome = evaluate(candidate, history, risk, mode, now, reason=reason)
    outcome["signed_archive_metadata_checked"] = True
    outcome["trusted_publication_times_verified"] = False
    outcome["archive_completeness_verified"] = False
    outcome["published_store_bytes_verified"] = False
    outcome["approval_granted"] = False
    outcome["publishable"] = False
    return outcome


def main():
    p = argparse.ArgumentParser(description="Offline signed beta-history assessment, NEVER production approval")
    for field in ("candidate", "publications", "snapshots", "registry", "metadata-key", "metadata-key-sha256", "risk", "mode", "now"):
        p.add_argument("--" + field, required=True)
    p.add_argument("--reason")
    args = p.parse_args()
    candidate = _json_file(pathlib.Path(args.candidate))
    registry = _json_file(pathlib.Path(args.registry))
    result = assess(candidate, args.publications, args.snapshots, registry,
                    args.metadata_key, args.metadata_key_sha256, args.risk, args.mode, args.now, args.reason)
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
