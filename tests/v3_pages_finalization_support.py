"""Fresh disposable signing capabilities; no production beta dwell evidence."""
from v3_backend_evidence import verify_evidence, authorization_request, verify_protected
from v3_backend_trust import digest, verify_oidc, verify_envelope
from v3_immutable_view import verify_attested_result
from v3_policy_profile import sha


def fresh_authority(fx, attempt, *, operation="promote", resume=None):
    keys, now = fx.keys, fx.now
    attestations = {role:keys.attestation(role, expected, now=now) for role,expected in fx.expectations.items()}
    evidence = verify_evidence(fx.proposal, fx.plan, fx.registry, fx.claim, attestations, now=now)
    raw, pins = keys.oidc(attempt, changes={"iat":now, "nbf":now, "exp":now+300, "jti":"fresh-"+attempt+"-"+str(now)})
    workload = verify_oidc(raw, keys.jwks, jwks_sha256=digest(keys.jwks), pins=pins, now=now, fetched_at=now)
    expected = authorization_request(fx.proposal, attempt, evidence, operation=operation, resume=resume)
    a, w = keys.signers["approval"], keys.signers["witness"]
    approved_raw = a.envelope("human-approval", {**expected, "reviewer_id":"456", "issued_at":now, "expires_at":now+300})
    approved = verify_envelope(approved_raw, role="human-approval", public_key=a.public, key_sha256=a.key_sha256,
        expected={**expected, "reviewer_id":"456"}, now=now)
    witnessed_raw = w.envelope("protected-environment-witness", {**expected, "approval_sha256":approved.sha256,
        "workload_token_sha256":workload.token_sha256, "environment":workload.claims["environment"],
        "environment_config_sha256":"f"*64, "run_id":workload.claims["run_id"], "run_attempt":workload.claims["run_attempt"],
        "reviewer_id":"456", "decision":"approved", "issued_at":now, "expires_at":now+300})
    approval = verify_protected(fx.proposal, attempt, evidence, workload, approval_raw=approved_raw, witness_raw=witnessed_raw,
        approval_key=a.public, approval_key_sha256=a.key_sha256, witness_key=w.public, witness_key_sha256=w.key_sha256,
        allowed_reviewer_ids={"456"}, environment_config_sha256="f"*64, now=now, operation=operation, resume=resume)
    preflight = keys.attestation("result-preflight", {"proposal_sha256":fx.proposal["proposal_sha256"],
        "result_stable_sha256":fx.result.sha256, "stable_set_sha256":fx.proposal["stable_set_sha256"], "plan_sha256":sha(fx.plan),
        "rpm_signatures":"PASS", "metadata_signatures":"PASS", "srpm_closure":"PASS"}, now=now)
    result = verify_attested_result(fx.source, fx.proposal, fx.plan, preflight, now=now)
    return evidence, result, approval
