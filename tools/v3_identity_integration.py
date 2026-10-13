"""Provisioned identity lifecycle and fresh observer integration.

No JWT-provided key, GitHub API approval field or environment claim supplies
trust. The operator lifecycle root separately authenticates JWKS bytes, epoch
and revocations. A monotonic epoch must be retained outside a restored runner.
"""
from v3_backend_trust import digest, key_identity, require_attestation, strict_json, verify_oidc
from v3_integration import proposal
from v3_policy_profile import require_complete, sha
from v3_promotion_planner import PlanningError


def verify_root_set(roots):
    required = {"source", "beta-history", "tests", "approval", "witness", "publication", "audit", "checkpoint", "jwks-lifecycle", "discovery", "deployment", "restore-observation"}
    if not isinstance(roots, dict) or set(roots) != required:
        raise PlanningError("provision every independent V3 public trust role")
    identities = []
    for role, root in roots.items():
        if not isinstance(root, dict) or set(root) != {"public_key", "sha256"} or not isinstance(root["public_key"], bytes) or digest(root["public_key"]) != root["sha256"]:
            raise PlanningError("independent public bytes and SHA256 pin required: " + role)
        identities.append(key_identity(root["public_key"]))
    if len(set(identities)) != len(identities):
        raise PlanningError("independent trust roles must use distinct canonical keys")
    return {"roles": sorted(roots), "production_activation": "BLOCKED", "deployment": "UNVERIFIED"}


def lifecycle_oidc(raw, jwks, lifecycle, *, pins, now, minimum_epoch):
    payload = require_attestation(lifecycle, "jwks-lifecycle")
    required = {"issuer", "jwks_sha256", "epoch", "fetched_at", "revoked_kids", "issued_at", "expires_at"}
    # The HTTPS client requires a nonce; offline legacy callers retain the
    # original contract. Never strip a signed nonce or manufacture an attestation.
    if (set(payload) not in (required, required | {"nonce"}) or payload["issuer"] != "https://token.actions.githubusercontent.com" or
            payload["jwks_sha256"] != digest(jwks) or type(payload["epoch"]) is not int or payload["epoch"] < minimum_epoch or
            type(payload["fetched_at"]) is not int or not 0 <= now - payload["fetched_at"] <= 3600 or
            not payload["issued_at"] <= now < payload["expires_at"] or not isinstance(payload["revoked_kids"], list) or
            any(not isinstance(k, str) or not k for k in payload["revoked_kids"])):
        raise PlanningError("stale/substituted/revoked JWKS lifecycle")
    from v3_backend_trust import b64
    header = strict_json(b64(raw.split(".")[0]))
    if header.get("kid") in payload["revoked_kids"]:
        raise PlanningError("revoked OIDC key")
    return verify_oidc(raw, jwks, jwks_sha256=payload["jwks_sha256"], pins=pins, now=now,
                       fetched_at=payload["fetched_at"])


def proposal_from_genesis(client, plan, registry, provenance, *, availability_sha256, now, **kwargs):
    policy = require_complete(plan, registry)
    identity = {"promotion_group": plan["promotion_group"], "fedora_release": 44, "policy": policy,
                "packages": plan["selected_group_packages"], "source_provenance": provenance}
    candidate = sha(identity)
    genesis = client.read("history/" + candidate)
    if (not isinstance(genesis, dict) or genesis.get("candidate_sha256") != candidate or
            genesis.get("promotion_group") != plan["promotion_group"] or genesis.get("availability_sha256") != availability_sha256):
        raise PlanningError("fresh authenticated V3 first-seen genesis missing/mismatched")
    row = {k: genesis[k] for k in ("promotion_group", "publication_run", "published_at")}
    row["candidate_sha256"] = plan["candidate_sha256"]
    return proposal(plan, registry, [row], provenance, now=now, **kwargs)
