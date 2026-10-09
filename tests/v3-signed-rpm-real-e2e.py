#!/usr/bin/env python3
"""Fedora 44 integration: the actual production-fixture signed RPMs pass V3 preflight.

This runs inside tests/e2e-local.sh using its temporary GPG key and signed
snapshot. No network, production keys, channel writes or publish authority.
"""
import hashlib
import json
import pathlib
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from v3_promotion_planner import PlanningError
from v3_stable_composer import compose
from v3_rpm_preflight import verify


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def assert_rejected(function, explanation, allowed_messages):
    try:
        function()
    except PlanningError as exc:
        if not any(message in str(exc) for message in allowed_messages):
            raise AssertionError(f"{explanation}: wrong failure reason: {exc}") from exc
        print(f"correctly rejected {explanation}: {exc}")
    else:
        raise AssertionError(f"{explanation}: accepted unexpectedly")


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: v3-signed-rpm-real-e2e.py SNAPSHOT REGISTRY PUBLIC-KEY UNSIGNED-RPMS")
    snapshot, registry_file, key, unsigned_dir = map(pathlib.Path, sys.argv[1:])
    registry = json.loads(registry_file.read_text())
    # This SHA is generated from the ephemeral test-only key. A production
    # verifier must receive the trusted signing key hash out of band.
    expected_key_sha = digest(key.read_bytes())
    with tempfile.TemporaryDirectory(prefix="v3-preflight-real-fixture-") as tmp:
        staged = pathlib.Path(tmp) / "stable-candidate"
        result = compose(snapshot, None, registry, "ro-control", staged)
        assert result["publishable"] is False
        manifest = json.loads((staged / "promotion-plan-v3.json").read_text())
        assert {p["architecture"] for p in manifest["resulting_stable_packages"]} == {"src", "x86_64"}
        evidence = verify(staged, key, expected_key_sha)
        assert evidence["local_header_checks_passed"] is True
        assert evidence["local_rpm_signature_checks_passed"] is True
        assert evidence["verified_beta_provenance"] is False
        assert evidence["dnf_tests_executed"] is False
        assert evidence["publishable"] is False
        assert len(evidence["checked_rpm_files"]) == 2
        print("real Fedora 44 signed x86_64+SRPM preflight passed")

        binary = next(p for p in staged.glob("rpm/x86_64/*.rpm"))
        signed_bytes = binary.read_bytes()
        binary.write_bytes(signed_bytes + b"tampered")
        assert_rejected(
            lambda: verify(staged, key, expected_key_sha),
            "tampered signed RPM bytes",
            ("signed RPM bytes differ",),
        )
        binary.write_bytes(signed_bytes)
        assert_rejected(
            lambda: verify(staged, key, "f" * 64 if expected_key_sha != "f" * 64 else "a" * 64),
            "wrong trusted signing key digest",
            ("trusted RPM public key hash mismatch",),
        )

        # Adversarial case: attacker can edit metadata and recompute *all*
        # candidate hashes to match a different, unsigned RPM. SHA alone cannot
        # make that RPM trusted; rpmkeys must reject it independently.
        unsigned = unsigned_dir / binary.name
        if not unsigned.is_file():
            raise AssertionError(f"missing unsigned test fixture {unsigned.name}")
        unsigned_bytes = unsigned.read_bytes()
        if unsigned_bytes == signed_bytes:
            raise AssertionError("expected signed fixture RPM bytes to differ from unsigned original")
        binary.write_bytes(unsigned_bytes)
        unsigned_sha = digest(unsigned_bytes)
        selected = json.loads((staged / "promotion-plan-v3.json").read_text())
        metadata = json.loads((staged / "composition-v3.json").read_text())
        for name in ("selected_group_packages", "resulting_stable_packages"):
            for p in selected[name]:
                if p["filename"] == binary.name:
                    p["published_signed_artifact_sha256"] = unsigned_sha
        sorted_group = sorted(selected["selected_group_packages"], key=lambda p: (p["nevra"], p["filename"]))
        candidate_sha = digest(canonical(sorted_group))
        selected["candidate_sha256"] = candidate_sha
        metadata["candidate_sha256"] = candidate_sha
        metadata["plan_sha256"] = digest(canonical(selected))
        for file in metadata["files"]:
            if file["path"] == "rpm/x86_64/" + binary.name:
                file["sha256"] = unsigned_sha
        (staged / "promotion-plan-v3.json").write_bytes(canonical(selected) + b"\n")
        (staged / "composition-v3.json").write_bytes(canonical(metadata) + b"\n")
        assert_rejected(
            lambda: verify(staged, key, expected_key_sha),
            "unsigned RPM with internally consistent forged metadata",
            ("RPM command failed", "RPM signature missing or not trusted"),
        )
        print("real signed RPM V3 integration and negative cases passed")


if __name__ == "__main__":
    main()
