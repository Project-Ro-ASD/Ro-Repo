"""Exact, expiring signed authorization contract for isolated V3 rehearsals.

Only a detached GPG signature verified against the independently pinned
approval public key authenticates this local approval. GitHub read-only
receipts, success flags, actor strings and CLI booleans grant no authority.
Production protected-environment and OIDC authorization remain BLOCKED.
"""
import datetime as dt
import pathlib
import re
import tempfile

from v3_integration import verify_proposal
from v3_policy_profile import sha
from v3_promotion_planner import PlanningError
from v3_promotion_policy import _time
from v3_signed_beta_history import _signature, _keyring

BINDINGS = ("proposal_sha256", "candidate_sha256", "promotion_group", "mode", "reason",
            "previous_stable_snapshot_id", "previous_stable_sha256", "result_stable_sha256",
            "stable_set_sha256", "policy_version", "policy_sha256", "evidence_sha256", "first_seen")
ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$")


def request(value, attempt, *, operation="promote", target_verified_sha256=None):
    verify_proposal(value)
    if not isinstance(attempt, str) or not ID.fullmatch(attempt):
        raise PlanningError("invalid publication attempt identity")
    if operation not in {"promote", "recover"}:
        raise PlanningError("unsupported operation")
    if value["result_stable_sha256"] is None:
        raise PlanningError("approval requires exact complete resulting snapshot digest")
    if operation == "promote" and value["mode"] == "normal" and not value["dwell_met"]:
        raise PlanningError("insufficient normal dwell")
    if operation == "promote" and "group-validation-claim" not in value["evidence_sha256"]:
        raise PlanningError("mandatory component tests missing; fast-track waives only dwell")
    if operation == "recover" and target_verified_sha256 != value["result_stable_sha256"]:
        raise PlanningError("recovery target was not previously verified")
    return {"schema_version": 3, "scope": "v3-local-authorization-request",
            **{field: value[field] for field in BINDINGS}, "attempt_id": attempt,
            "operation": operation, "target_verified_sha256": target_verified_sha256}


def verify_signed(value, directory, attempt, key, key_sha256, *, now,
                  operation="promote", target_verified_sha256=None):
    expected = request(value, attempt, operation=operation,
                       target_verified_sha256=target_verified_sha256)
    with tempfile.TemporaryDirectory(prefix="v3-approval-key-") as home:
        ring = _keyring(key, key_sha256, home)
        approval = _signature(pathlib.Path(directory), "authorization-v3.json", ring)
    fields = set(expected) | {"approved_at", "expires_at", "actor"}
    if not isinstance(approval, dict) or set(approval) != fields:
        raise PlanningError("invalid signed approval contract")
    from ro_repo import validate_schema, ContractError
    try:
        validate_schema(approval, "authorization-v3")
    except ContractError as exc:
        raise PlanningError("invalid signed approval schema") from exc
    if any(approval[field] != expected[field] for field in expected):
        raise PlanningError("stale or substituted authorization binding")
    start, expiry, current = (_time(approval["approved_at"]),
                              _time(approval["expires_at"]), _time(now))
    if not start <= current < expiry or expiry - start > dt.timedelta(hours=24):
        raise PlanningError("expired or invalid approval window")
    if not isinstance(approval["actor"], str) or not approval["actor"].strip():
        raise PlanningError("missing approval actor attribution")
    return {"scope": "v3-local-signed-authorization-verified", "approval_sha256": sha(approval),
            "request": expected, "actor": approval["actor"], "expires_at": approval["expires_at"],
            "local_approval_signature_verified": True, "protected_environment_verified": False,
            "oidc_identity_verified": False, "publishable": False}
