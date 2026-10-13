"""Protected empty-stable bootstrap/import clients on existing V3 contracts.

No history is invented, overwritten or imported by this adapter. Actual stable
history forces the existing migration route. Initialization is executable only
against the existing disposable DB boundary; production remains BLOCKED.
"""
import secrets

from v3_backend_trust import (Workload, canonical, digest, key_identity,
                              require_attestation, verify_envelope)
from v3_policy_profile import sha
from v3_postgresql_production import initialize_empty_rehearsal
from v3_promotion_planner import PlanningError

_SEAL = object()


class EmptyStableEvidence:
    def __init__(self, storage, https, roots, seal):
        if seal is not _SEAL:
            raise PlanningError("authenticated bootstrap evidence required")
        self.storage, self.https, self.roots = storage, https, roots
        self.sha256 = sha({"storage": storage.sha256, "https": https.sha256})
        self.expiry = min(storage.payload["expires_at"], https.payload["expires_at"])


def observe_empty(storage, storage_transport, https_transport, *, database, schema, origin,
                  storage_key, storage_pin, https_key, https_pin):
    from v3_immutable_view import immutable_url
    immutable_url(origin, "0"*64, "x86_64")
    if key_identity(storage_key) == key_identity(https_key):
        raise PlanningError("independent storage and HTTPS bootstrap observers required")
    commit = storage.head()
    files = storage.files(commit)
    history = storage.empty_history(commit)
    inventory = digest(canonical(files))
    common = {"database": database, "schema": schema, "storage_commit": commit,
              "inventory_sha256": inventory, "stable_absent": True, "writer_exclusive": True,
              "origin": origin, "history_sha256": history}
    attestations = []
    for transport, public, pin, kind in ((storage_transport, storage_key, storage_pin, "storage"),
                                       (https_transport, https_key, https_pin, "https")):
        nonce = secrets.token_hex(32)
        expected = {**common, "nonce": nonce, "observation": kind}
        result = transport.request("POST", "/v1/empty-stable", expected)
        remote = result.get("payload", {}).get("remote_sha256")
        if not isinstance(remote, str) or len(remote) != 64 or any(c not in "0123456789abcdef" for c in remote):
            raise PlanningError("independent authenticated HTTPS empty-state evidence missing")
        attestations.append(verify_envelope(canonical(result), role="empty-stable", public_key=public,
            key_sha256=pin, expected={**expected, "remote_sha256": remote}, now=transport.clock()))
    if attestations[0].payload["remote_sha256"] != attestations[1].payload["remote_sha256"]:
        raise PlanningError("independent empty-state observations disagree")
    if storage.head() != commit or storage.files(commit) != files:
        raise PlanningError("storage changed during bootstrap observation")
    return EmptyStableEvidence(*attestations, {key_identity(storage_key), key_identity(https_key)}, _SEAL)


class BootstrapAuthorization:
    def __init__(self, evidence, approval, witness, workload, clock, roots, seal):
        if seal is not _SEAL:
            raise PlanningError("verified protected bootstrap authorization required")
        self.evidence, self.approval, self.witness, self.workload = evidence, approval, witness, workload
        self.clock, self.roots = clock, roots
        self.expiry = min(evidence.expiry, approval.payload["expires_at"], witness.payload["expires_at"], workload.claims["exp"])

    def check(self, adapter, audit_key):
        payload = require_attestation(self.evidence.storage, "empty-stable")
        if (not self.clock() < self.expiry or payload["database"] != adapter.config["dbname"] or
                payload["schema"] != adapter.config["schema"] or key_identity(audit_key) in self.roots):
            raise PlanningError("bootstrap expired/mismatched; fresh independent evidence and authorization required")


def authorize_empty(evidence, workload, *, attempt, approval_transport, witness_transport,
                    approval_key, approval_pin, witness_key, witness_pin, allowed_reviewer_ids,
                    environment_config_sha256):
    from v3_authorization import ID
    from v3_backend_trust import HEX
    if (not isinstance(evidence, EmptyStableEvidence) or not isinstance(workload, Workload) or
            not isinstance(attempt, str) or not ID.fullmatch(attempt) or not HEX.fullmatch(environment_config_sha256)):
        raise PlanningError("verified empty state/workload/attempt/configuration required")
    roots = evidence.roots | {key_identity(approval_key), key_identity(witness_key)}
    if len(roots) != 4:
        raise PlanningError("bootstrap observation/approval/witness roots must be independent")
    clock = witness_transport.clock
    if not clock() < min(evidence.expiry, workload.claims["exp"]):
        raise PlanningError("bootstrap evidence or workload expired")
    storage = evidence.storage.payload
    expected = {"request": {"schema_version": 3, "operation": "initialize-empty-stable",
        "attempt_id": attempt, "database": storage["database"], "schema": storage["schema"],
        "storage_commit": storage["storage_commit"], "inventory_sha256": storage["inventory_sha256"],
        "remote_sha256": storage["remote_sha256"], "history_sha256": storage["history_sha256"],
        "origin": storage["origin"]}, "authenticated_evidence_sha256": evidence.sha256}
    raw = canonical(approval_transport.request("POST", "/v1/approval", expected))
    from v3_backend_trust import strict_json
    reviewer = strict_json(raw).get("payload", {}).get("reviewer_id")
    if (not isinstance(reviewer, str) or not reviewer.isdecimal() or reviewer not in allowed_reviewer_ids or
            reviewer == workload.claims["actor_id"]):
        raise PlanningError("independent bootstrap reviewer required")
    approval = verify_envelope(raw, role="human-approval", public_key=approval_key, key_sha256=approval_pin,
        expected={**expected, "reviewer_id": reviewer}, now=clock())
    witness_expected = {**expected, "approval_sha256": approval.sha256,
        "workload_token_sha256": workload.token_sha256, "environment": workload.claims["environment"],
        "environment_config_sha256": environment_config_sha256, "run_id": workload.claims["run_id"],
        "run_attempt": workload.claims["run_attempt"], "reviewer_id": reviewer, "decision": "approved"}
    witness_raw = canonical(witness_transport.request("POST", "/v1/witness", {**witness_expected,
        "approval": strict_json(raw)}))
    witness = verify_envelope(witness_raw, role="protected-environment-witness", public_key=witness_key,
        key_sha256=witness_pin, expected=witness_expected, now=clock())
    return BootstrapAuthorization(evidence, approval, witness, workload, clock, roots, _SEAL)


def initialize_empty(adapter, signer, authorization, *, audit_key, audit_pin):
    if not isinstance(authorization, BootstrapAuthorization):
        raise PlanningError("fresh protected bootstrap approval required")
    authorization.check(adapter, audit_key)
    def guard(db):
        authorization.check(adapter, audit_key)
    return initialize_empty_rehearsal(adapter, signer, authorization.evidence.storage,
        audit_key=audit_key, audit_key_sha256=audit_pin, now=authorization.clock(), guard=guard,
        consumed={"bootstrap-approval": authorization.approval.sha256,
                  "bootstrap-jti": authorization.workload.claims["jti"]})


def interrupted_first_publication(backend, attempt, approval, *, now):
    """Classify recovery using authenticated ledger; never reset initial head.

    Same fresh envelopes can resume the existing outbox. An expired first
    advertisement cannot use Backend's 'recover' route (no POST_VERIFIED view).
    A separate reviewed reauthorization transition is still a CODE BLOCKER.
    """
    from v3_backend_evidence import Authorization
    if not isinstance(approval, Authorization):
        raise PlanningError("fresh independently verified publication authorization required")
    record = backend.ledger.inspect(attempt)
    value = record["attempt"]
    if value["immutable"]["proposal"]["previous_stable_sha256"] is not None:
        raise PlanningError("not a first-stable publication")
    signed = value["proofs"].get("AUTHORIZED", {})
    if now >= min(approval.expiry, signed.get("expires_at", 0)):
        raise PlanningError("expired first publication BLOCKED; fresh exact-result reauthorization transition required")
    if signed.get("authorization_sha256") != approval.sha256:
        raise PlanningError("stale/substituted first-publication recovery evidence")
    if value["state"] not in {"STAGED", "REMOTE_VERIFIED", "PUBLISHED", "POST_VERIFIED"}:
        raise PlanningError("first publication not at a resumable outbox boundary")
    return {"attempt_id": attempt, "resume": "existing-outbox", "state": value["state"],
            "reinitialize": False, "publishable": False, "production_activation": "BLOCKED"}


def import_existing(*args, **kwargs):
    raise PlanningError("live stable import BLOCKED; authenticated V2 migration, protected cutover and client acceptance required")
