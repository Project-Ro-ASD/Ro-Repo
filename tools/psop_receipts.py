"""Durable, explicitly non-production PSOP publication observations."""
from ro_repo import validate_schema
from v3_backend_trust import strict_json
from v3_policy_profile import sha


def receipt(ledger, attempt):
    state = ledger.inspect(attempt)
    value = state["attempt"]
    p, a = value["prepared"], value["approval"]
    intent = value["proofs"]["OUTBOX"]["receipts"].get("provider_intent")
    # Receipt identity is the attempt's last signed audit event, not the moving
    # global checkpoint. Later publications must not rewrite old receipts.
    checkpoint = state["checkpoint"]
    with ledger.adapter.transaction() as db:
        ledger._integrity(db)
        for seq, raw in db.execute("SELECT seq,body FROM events ORDER BY seq DESC").fetchall():
            event = strict_json(raw)
            if event["attempt_id"] == attempt:
                checkpoint = {"seq": seq, "sha256": sha(event)}
                break
    result = {"schema_version": 1, "domain": "psop-publication-test-1", "context": ledger.context.pin,
        "attempt": attempt, "writer": a["payload"]["writer"],
        "identity": a["payload"]["identity"], "publication_sha256": p["publication_sha256"],
        "status": "UNKNOWN" if intent and intent["status"] == "IN_FLIGHT" else value["state"],
        "approval_sha256": p["approval_sha256"], "result_sha256": p["result_sha256"],
        "evidence_sha256": a["payload"]["review"]["evidence_sha256"],
        "before_git": p["expected_git"], "target_git": p["target_git"],
        "created_at": value["created_at"], "admitted_at": None if not intent else intent["admitted_at"],
        "requested_at": value["proofs"]["OUTBOX"]["receipts"].get("requested_at"),
        "observed_at": value["proofs"].get("observed_at"), "checkpoint": checkpoint,
        "provider_deadline_fencing": "UNVERIFIED", "pages_build_ordering": "UNVERIFIED",
        "global_cdn_freshness": "UNVERIFIED", "production_activation": "BLOCKED", "publishable": False}
    validate_schema(result, "psop-publication-v1")
    return result
