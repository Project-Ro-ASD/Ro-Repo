"""Deployable clients for existing independent trust contracts.

These are clients, not replacement approval/signing/checkpoint authorities.
An absent or incorrectly provisioned service fails closed. No private key is
loaded, generated, or trusted from a response. Production activation is guarded
by the existing backend, storage, schema and PostgreSQL boundaries.
"""
import copy
import secrets

from v3_backend_evidence import authorization_request, verify_protected
from v3_backend_trust import (b64, canonical, digest, encode, key_identity,
                              strict_json, verify_bytes, verify_envelope)
from v3_identity_integration import lifecycle_oidc
from v3_independent_authority import AuthorityClient
from v3_immutable_view import HTTPSReader, verify_remote
from v3_promotion_planner import PlanningError


class ProtectedSigner:
    """External RSA/SHA256 signing boundary compatible with Ledger/AuthorityClient.

    The server must independently enforce exact-result policy before signing.
    A bearer token or a successful HTTP response alone never authenticates bytes.
    """
    def __init__(self, transport, *, public_key, key_sha256, purpose, context):
        if digest(public_key) != key_sha256 or purpose not in {"publication", "audit", "independent-update"}:
            raise PlanningError("independent pinned signing purpose/key required")
        key_identity(public_key)
        if not isinstance(context, dict) or not context:
            raise PlanningError("explicit workload and protected signing context required")
        self.transport, self.public, self.key_sha256 = transport, public_key, key_sha256
        self.purpose, self.context = purpose, copy.deepcopy(context)

    def sign(self, data):
        if not isinstance(data, bytes):
            raise PlanningError("exact signing bytes required")
        parsed = strict_json(data)
        if not isinstance(parsed, dict) or canonical(parsed) != data:
            raise PlanningError("canonical signing message required")
        if self.purpose == "audit":
            if parsed.get("domain") != "ro-repo-v3-audit-1":
                raise PlanningError("audit signing domain substitution")
        else:
            allowed = {"publication": {"publication", "stable-advertisement"},
                       "independent-update": {"independent-update"}}
            payload = parsed.get("payload", {})
            if (set(parsed) != {"domain", "role", "payload"} or parsed["domain"] != "ro-repo-v3-backend-1" or
                    parsed["role"] not in allowed[self.purpose] or not isinstance(payload, dict) or
                    type(payload.get("issued_at")) is not int or type(payload.get("expires_at")) is not int or
                    not payload["issued_at"] <= self.transport.clock() < payload["expires_at"] or
                    not 0 < payload["expires_at"] - payload["issued_at"] <= 86400):
                raise PlanningError("expired/substituted protected signing request")
        nonce = secrets.token_hex(32)
        result = self.transport.request("POST", "/v1/sign", {"purpose": self.purpose,
            "context": self.context, "nonce": nonce, "data": encode(data), "sha256": digest(data)})
        if (not isinstance(result, dict) or set(result) != {"nonce", "sha256", "key_sha256", "signature"} or
                result["nonce"] != nonce or result["sha256"] != digest(data) or result["key_sha256"] != self.key_sha256):
            raise PlanningError("signing response identity substitution")
        signature = b64(result["signature"])
        verify_bytes(self.public, self.key_sha256, data, signature)
        return signature

    def envelope(self, role, payload):
        allowed = {"publication": {"publication", "stable-advertisement"},
                   "independent-update": {"independent-update"}, "audit": set()}
        if role not in allowed[self.purpose]:
            raise PlanningError("signing role exceeds provisioned purpose")
        expected = {k: v for k, v in payload.items() if k not in {"issued_at", "expires_at"}}
        unsigned = {"domain": "ro-repo-v3-backend-1", "role": role, "payload": payload}
        raw = canonical({**unsigned, "signature": encode(self.sign(canonical(unsigned)))})
        verify_envelope(raw, role=role, public_key=self.public, key_sha256=self.key_sha256,
                        expected=expected, now=self.transport.clock())
        return raw


def authority_client(transport, *, public_key, key_sha256, updater=None):
    """Use the existing nonce-bound signed checkpoint/reservation protocol."""
    def exchange(request):
        return canonical(transport.request("POST", "/v1/exchange", request))
    return AuthorityClient(exchange, public_key=public_key, key_sha256=key_sha256,
                           clock=transport.clock, updater=updater)


def workload_from_services(raw, jwks, lifecycle_transport, *, lifecycle_key, lifecycle_pin,
                           pins, minimum_epoch):
    nonce = secrets.token_hex(32)
    result = lifecycle_transport.request("POST", "/v1/jwks-lifecycle", {"nonce": nonce,
        "issuer": "https://token.actions.githubusercontent.com", "jwks_sha256": digest(jwks)})
    payload = result.get("payload", {})
    fields = {"issuer", "jwks_sha256", "epoch", "fetched_at", "revoked_kids", "nonce", "issued_at", "expires_at"}
    if set(payload) != fields or payload.get("nonce") != nonce:
        raise PlanningError("JWKS lifecycle response replay")
    attestation = verify_envelope(canonical(result), role="jwks-lifecycle", public_key=lifecycle_key,
        key_sha256=lifecycle_pin, expected={k: v for k, v in payload.items() if k not in {"issued_at", "expires_at"}},
        now=lifecycle_transport.clock())
    return lifecycle_oidc(raw, jwks, attestation, pins=pins, now=lifecycle_transport.clock(), minimum_epoch=minimum_epoch)


def protected_authorization(proposal, attempt, evidence, workload, *, approval_transport,
                            witness_transport, approval_key, approval_pin, witness_key, witness_pin,
                            allowed_reviewer_ids, environment_config_sha256, operation="promote", target=None, resume=None):
    expected = authorization_request(proposal, attempt, evidence, operation=operation, target=target, resume=resume)
    approved = approval_transport.request("POST", "/v1/approval", expected)
    approval_raw = canonical(approved)
    # Verify before forwarding to the witness. Approval is exact-result-bound;
    # the witness additionally binds the independently verified workload token.
    reviewer = approved.get("payload", {}).get("reviewer_id")
    if reviewer not in allowed_reviewer_ids or reviewer == workload.claims["actor_id"]:
        raise PlanningError("independent allowed reviewer required")
    approval = verify_envelope(approval_raw, role="human-approval", public_key=approval_key,
        key_sha256=approval_pin, expected={**expected, "reviewer_id": reviewer}, now=approval_transport.clock())
    witness = witness_transport.request("POST", "/v1/witness", {**expected,
        "approval": strict_json(approval_raw), "workload_token_sha256": workload.token_sha256,
        "environment": workload.claims["environment"], "environment_config_sha256": environment_config_sha256,
        "run_id": workload.claims["run_id"], "run_attempt": workload.claims["run_attempt"],
        "reviewer_id": reviewer, "approval_sha256": approval.sha256})
    return verify_protected(proposal, attempt, evidence, workload, approval_raw=approval_raw,
        witness_raw=canonical(witness), approval_key=approval_key, approval_key_sha256=approval_pin,
        witness_key=witness_key, witness_key_sha256=witness_pin, allowed_reviewer_ids=allowed_reviewer_ids,
        environment_config_sha256=environment_config_sha256, now=witness_transport.clock(), operation=operation, target=target, resume=resume)


class IndependentDeployment:
    def __init__(self, transport, *, public_key, key_sha256, origin):
        self.transport, self.public_key, self.pin, self.origin = transport, public_key, key_sha256, origin

    def verify(self, view, commit, *, now, ledger=None, signer=None, reader_factory=HTTPSReader, expected_deployment_id=None):
        from v3_github_provider import oid
        nonce = secrets.token_hex(32)
        expected = {"nonce": nonce, "origin": self.origin, "result_stable_sha256": view.sha256,
            "publication_sha256": view.envelope_sha256, "git_commit": oid(commit)}
        result = self.transport.request("POST", "/v1/deployment-observation", expected)
        deployment_id = result.get("payload", {}).get("deployment_id")
        if (not isinstance(deployment_id, str) or not deployment_id or
                expected_deployment_id is not None and deployment_id != expected_deployment_id):
            raise PlanningError("independent deployment not yet observed")
        deployment = verify_envelope(canonical(result), role="deployment", public_key=self.public_key,
            key_sha256=self.pin, expected={**expected, "deployment_id": deployment_id}, now=now)
        reader = reader_factory(self.origin, view.sha256, view.descriptor["request"]["attempt_id"])
        # Provider status/commit never substitutes for actual HTTPS byte checks.
        result = verify_remote(view, reader, deployment, now=now, post_ledger=ledger,
            advertisement_key=None if signer is None else signer.public,
            advertisement_key_sha256=None if signer is None else signer.key_sha256)
        if not 0 <= self.transport.clock() - now <= 60 or self.transport.clock() >= deployment.payload["expires_at"]:
            raise PlanningError("deployment observation expired during byte verification")
        return result
