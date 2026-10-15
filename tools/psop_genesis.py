"""Explicit synthetic genesis; never derive authority from 404 or absence."""
from psop_context import Evidence, SEAL, require_evidence
from v3_promotion_planner import PlanningError


def genesis_request(inputs, history):
    return {"inputs_sha256": inputs.sha256, "history_sha256": history.sha256,
            "source_pins": inputs.data["pins"], "previous_stable_sha256": None,
            "empty_stable": True, "scope": "synthetic-test-genesis"}


def verify_genesis(inputs, history, bound_approval, *, context, now):
    i, h = require_evidence(inputs, context), require_evidence(history, context)
    if i["previous_stable_sha256"] is not None or h["status"] != "PASS_TEST_ONLY":
        raise PlanningError("explicit verified empty base and complete test history required")
    proof = context.verify(bound_approval, "genesis", genesis_request(inputs, history), now=now)
    return Evidence({"context": context.pin, "inputs_sha256": inputs.sha256,
                     "history_sha256": history.sha256, "approval_sha256": proof.sha256,
                     "previous_stable_sha256": None, "production_genesis": "BLOCKED"}, SEAL)
