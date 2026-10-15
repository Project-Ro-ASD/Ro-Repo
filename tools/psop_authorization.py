"""Authenticated PSOP approval, distinct from V1/V2/V3 and production issuers."""
import re

from psop_context import Evidence, SEAL, require_evidence
from v3_backend_trust import strict_json
from v3_policy_profile import sha
from v3_promotion_planner import PlanningError
from ro_repo import validate_schema

WRITERS = ("psop-stable", "v2-snapshot", "v2-beta", "v2-rollback", "v2-stable")


def approval_request(review_bundle, authenticated_identity, *, attempt, nonce, writer, expected_git, metadata_key):
    return {"schema_version": 1, "domain": "psop-approval-test-1", "review": review_bundle.data,
            "identity": authenticated_identity, "attempt": attempt, "nonce": nonce,
            "writer": writer, "expected_git": expected_git, "metadata_key": metadata_key,
            "publishable": False}


def verify_approval(raw, authenticated_identity, review_bundle, trusted_policy, now, *, context):
    r = require_evidence(review_bundle, context)
    validate_schema(r, "psop-review-v1")
    if r["policy_sha256"] != sha(trusted_policy) or r["policy_version"] != trusted_policy["version"]:
        raise PlanningError("approval policy mismatch")
    body = strict_json(raw).get("payload", {})
    validate_schema(body, "psop-approval-v1")
    identity = body["identity"]
    if (identity != authenticated_identity or identity["issuer"] != context.descriptor["origin"] + "/issuer"
            or identity["repository"] != context.descriptor["repository"]
            or not all(re.fullmatch(r"[1-9][0-9]*", identity[k]) for k in ("actor", "run_id", "run_attempt"))):
        raise PlanningError("untrusted production or substituted workload identity")
    expected = approval_request(review_bundle, identity, attempt=body["attempt"], nonce=body["nonce"],
        writer=body["writer"], expected_git=body["expected_git"], metadata_key=body["metadata_key"])
    proof = context.verify(raw, "approval", expected, now=now)
    return Evidence({"context": context.pin, "role": "approved", "payload": proof.data["payload"],
        "envelope_sha256": proof.data["envelope_sha256"], "review_sha256": review_bundle.sha256,
        "expiry": body["expires_at"], "publishable": False}, SEAL)
