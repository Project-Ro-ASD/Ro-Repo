"""Authenticated stage evidence and independent protected human authorization.

The environment witness is a separately provisioned signing service contract.
No GitHub API success field, OIDC environment claim, or CI artifact implements
that service. Its real deployment is an activation blocker.
"""
import copy
import re

from v3_authorization import request
from v3_backend_trust import (Attestation, TOKEN, Workload, HEX, require_attestation,
                              verify_envelope)
from v3_group_validation import validate_claim
from v3_integration import verify_proposal
from v3_policy_profile import BASE, DESKTOP, SYSTEM, require_complete, sha
from v3_promotion_planner import PlanningError, _policies, _parse
from v3_promotion_policy import _time

SUPPORTED_TESTS = BASE | DESKTOP | SYSTEM | {"ro-store-gui"}


def bindings(proposal):
    verify_proposal(proposal)
    return {key: copy.deepcopy(proposal[key]) for key in
            ("proposal_sha256", "candidate_sha256", "promotion_group", "policy_sha256",
             "previous_stable_sha256", "result_stable_sha256", "stable_set_sha256", "evidence_sha256")}


class Evidence:
    def __init__(self, data, expiry, seal):
        if seal is not TOKEN:
            raise PlanningError("unauthenticated stage evidence")
        self._data, self.expiry = copy.deepcopy(data), expiry
        self.sha256 = sha(data)

    @property
    def data(self):
        return copy.deepcopy(self._data)


def verify_evidence(proposal, plan, registry, claim, attestations, *, now):
    """Consume cryptographically verified source/history/test capabilities.

    All retained groups contribute their test floors. Claim consistency is
    checked with the existing verifier; a separate signed runner attests the
    exact claim and immutable logs. The history witness authenticates dwell.
    """
    policy = require_complete(plan, registry)
    verify_proposal(proposal)
    if (proposal["policy_sha256"] != sha(policy) or
            plan["selected_group_packages"] != proposal["candidate_identity"]["packages"] or
            sha(claim) != proposal["evidence_sha256"].get("group-validation-claim")):
        raise PlanningError("evidence differs from canonical proposal/claim")
    validate_claim(plan, registry, claim)
    common = bindings(proposal)
    if set(attestations) != {"source", "beta-history", "tests"}:
        raise PlanningError("incomplete authenticated evidence")
    payloads = {role: require_attestation(attestations[role], role) for role in attestations}
    for role, payload in payloads.items():
        if any(payload.get(k) != v for k, v in common.items()) or not payload["issued_at"] <= now < payload["expires_at"]:
            raise PlanningError("stale or mismatched authenticated evidence: " + role)
    if (payloads["source"].get("candidate_identity") != proposal["candidate_identity"] or
            not proposal["candidate_identity"]["source_provenance"]):
        raise PlanningError("missing authenticated exact source provenance")
    provenance = proposal["candidate_identity"]["source_provenance"]
    if (any(item.get("source_repository") != policy["repository"] or
            not isinstance(item.get("source_commit"), str) or not re.fullmatch(r"[0-9a-f]{40}", item["source_commit"]) for item in provenance) or
            payloads["source"].get("producer_repository") != policy["repository"] or
            payloads["source"].get("producer_commits") != sorted({item["source_commit"] for item in provenance}) or
            payloads["source"].get("signer_workflow") != policy["trusted_signer_workflow"]):
        raise PlanningError("source repository/commit/workflow trust divergence")
    if payloads["beta-history"].get("first_seen") != proposal["first_seen"]:
        raise PlanningError("unauthenticated first-seen history")
    seen = _time(proposal["first_seen"]["published_at"]).timestamp()
    actual_dwell = now - seen >= proposal["minimum_beta_days"] * 86400
    if seen > now or proposal["dwell_met"] != actual_dwell:
        raise PlanningError("first-seen dwell inconsistent with trusted time")
    _, owners = _policies(registry)
    groups = sorted({owners[_parse(p)[0]] for p in plan["resulting_stable_packages"]})
    from v3_policy_profile import profile
    required = sorted(set().union(*(set(profile(registry, group)["required_tests"]) for group in groups)))
    if not set(required) <= SUPPORTED_TESTS:
        raise PlanningError("unknown required acceptance test")
    architectures = sorted({p["architecture"] for p in plan["resulting_stable_packages"]} - {"src", "noarch"})
    if any(p["architecture"] == "noarch" for p in plan["resulting_stable_packages"]):
        architectures = sorted(set(architectures) | {"x86_64", "aarch64"})
    performed = {(c["architecture"], c["name"]) for c in claim["checks"] if c["result"] == "pass"}
    if {(a, t) for a in architectures for t in required} - performed:
        raise PlanningError("retained-group mandatory acceptance missing")
    tests = payloads["tests"]
    if (tests.get("claim_sha256") != sha(claim) or tests.get("required_tests") != required or
            tests.get("architectures") != architectures or tests.get("groups") != groups or
            tests.get("result") != "PASS" or tests.get("application_acceptance") != "PASS" or
            not isinstance(tests.get("logs"), dict) or not tests["logs"] or
            any(not isinstance(v, str) or not HEX.fullmatch(v) for v in tests["logs"].values()) or
            not isinstance(tests.get("execution"), dict) or set(tests["execution"]) != set(architectures) or
            any(v not in {"native", "emulated"} for v in tests["execution"].values())):
        raise PlanningError("mandatory authenticated full-set/application acceptance missing")
    return Evidence({"bindings": common, "attestations": {k: v.sha256 for k, v in attestations.items()},
                     "required_tests": required, "architectures": architectures, "groups": groups},
                    min(p["expires_at"] for p in payloads.values()), TOKEN)


class Authorization:
    def __init__(self, payload, expiry, seal):
        if seal is not TOKEN:
            raise PlanningError("unverified protected approval")
        self._payload, self.expiry = copy.deepcopy(payload), expiry
        self.sha256 = sha(payload)

    @property
    def payload(self):
        return copy.deepcopy(self._payload)


def authorization_request(proposal, attempt, evidence, *, operation="promote", target=None):
    if not isinstance(evidence, Evidence) or evidence.data["bindings"] != bindings(proposal):
        raise PlanningError("authenticated evidence required before approval")
    return {"request": request(proposal, attempt, operation=operation, target_verified_sha256=target),
            "authenticated_evidence_sha256": evidence.sha256}


def verify_protected(proposal, attempt, evidence, workload, *, approval_raw, witness_raw,
                     approval_key, approval_key_sha256, witness_key, witness_key_sha256,
                     allowed_reviewer_ids, environment_config_sha256, now,
                     operation="promote", target=None):
    if not isinstance(workload, Workload) or not isinstance(evidence, Evidence):
        raise PlanningError("verified workload and evidence required")
    if not now < min(evidence.expiry, workload.claims["exp"]):
        raise PlanningError("expired workload/evidence at authorization")
    if approval_key_sha256 == witness_key_sha256 or not HEX.fullmatch(environment_config_sha256):
        raise PlanningError("independent approval/witness trust roots required")
    expected = authorization_request(proposal, attempt, evidence, operation=operation, target=target)
    from v3_backend_trust import strict_json
    parsed = strict_json(approval_raw)
    reviewer = parsed.get("payload", {}).get("reviewer_id") if isinstance(parsed, dict) else None
    if reviewer not in allowed_reviewer_ids:
        raise PlanningError("unauthorized human reviewer")
    approval = verify_envelope(approval_raw, role="human-approval", public_key=approval_key,
                               key_sha256=approval_key_sha256, expected={**expected, "reviewer_id": reviewer}, now=now)
    reviewer = approval.payload["reviewer_id"]
    if reviewer == workload.claims["actor_id"] or not isinstance(reviewer, str) or not reviewer.isdecimal():
        raise PlanningError("independent authorized reviewer required")
    witness_expected = {**expected, "approval_sha256": approval.sha256,
                        "workload_token_sha256": workload.token_sha256,
                        "environment": workload.claims["environment"],
                        "environment_config_sha256": environment_config_sha256,
                        "run_id": workload.claims["run_id"], "run_attempt": workload.claims["run_attempt"],
                        "reviewer_id": reviewer, "decision": "approved"}
    witness = verify_envelope(witness_raw, role="protected-environment-witness", public_key=witness_key,
                              key_sha256=witness_key_sha256, expected=witness_expected, now=now)
    return Authorization({**expected, "approval_sha256": approval.sha256,
                          "witness_sha256": witness.sha256, "reviewer_id": reviewer,
                          "approval_key_sha256": approval_key_sha256, "witness_key_sha256": witness_key_sha256,
                          "workload_token_sha256": workload.token_sha256,
                          "jti": workload.claims["jti"], "run_id": workload.claims["run_id"],
                          "run_attempt": workload.claims["run_attempt"]},
                         min(approval.payload["expires_at"], witness.payload["expires_at"],
                             evidence.expiry, workload.claims["exp"]), TOKEN)
