"""Pinned asymmetric trust for the V3 backend; no network trust discovery.

GitHub API records and decoded JWT payloads are never capabilities. The caller
supplies independently provisioned trust anchors, not keys from the envelope.
Private-key operations are restricted to disposable /tmp test workspaces.
"""
import base64
import copy
import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
from functools import lru_cache
from types import MappingProxyType

from v3_policy_profile import canonical, sha
from v3_promotion_planner import PlanningError

TOKEN = object()
HEX = re.compile(r"^[0-9a-f]{64}$")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise PlanningError("duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, TypeError) as exc:
        raise PlanningError("invalid JSON") from exc


def b64(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise PlanningError("invalid base64url")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise PlanningError("invalid base64url") from exc
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        raise PlanningError("noncanonical base64url")
    return raw


def encode(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _der(tag, data):
    length = len(data)
    size = bytes([length]) if length < 128 else length.to_bytes((length.bit_length()+7)//8, "big")
    if length >= 128:
        size = bytes([128 | len(size)]) + size
    return bytes([tag]) + size + data


def rsa_pem(jwk):
    if (jwk.get("kty") != "RSA" or jwk.get("alg", "RS256") != "RS256" or
            jwk.get("use", "sig") != "sig" or jwk.get("key_ops", ["verify"]) != ["verify"] or
            any(k in jwk for k in ("d", "p", "q", "dp", "dq", "qi"))):
        raise PlanningError("unsupported JWT public key")
    n, e = b64(jwk.get("n")), b64(jwk.get("e"))
    modulus, exponent = int.from_bytes(n, "big"), int.from_bytes(e, "big")
    if (modulus.bit_length() < 2048 or modulus.bit_length() > 8192 or
            exponent < 65537 or exponent % 2 == 0 or n[0] == 0 or e[0] == 0):
        raise PlanningError("weak or noncanonical RSA key")
    def integer(raw):
        return _der(2, (b"\0" if raw[0] & 128 else b"") + raw)
    body = base64.b64encode(_der(48, integer(n) + integer(e)))
    return b"-----BEGIN RSA PUBLIC KEY-----\n" + b"\n".join(body[i:i+64] for i in range(0, len(body), 64)) + b"\n-----END RSA PUBLIC KEY-----\n"


def verify_bytes(public_key, expected_sha256, data, signature):
    if not HEX.fullmatch(expected_sha256) or digest(public_key) != expected_sha256:
        raise PlanningError("independent signing key pin mismatch")
    key_identity(public_key)
    with tempfile.TemporaryDirectory(prefix="v3-verify-") as directory:
        root = pathlib.Path(directory)
        for name, content in (("key", public_key), ("data", data), ("sig", signature)):
            (root / name).write_bytes(content)
        result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(root / "key"),
                                 "-signature", str(root / "sig"), str(root / "data")],
                                capture_output=True, timeout=30)
        if result.returncode:
            raise PlanningError("invalid asymmetric signature")


@lru_cache(maxsize=128)
def key_identity(public_key):
    """Canonical key identity prevents whitespace/encoding role collisions."""
    result = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=public_key,
                            capture_output=True, timeout=30)
    text_result = subprocess.run(["openssl", "pkey", "-pubin", "-text_pub", "-noout"], input=public_key,
                                 capture_output=True, timeout=30)
    bits = re.search(rb"Public-Key: \((\d+) bit\)", text_result.stdout)
    if result.returncode or text_result.returncode or b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" not in result.stdout or not bits or not 2048 <= int(bits.group(1)) <= 8192:
        raise PlanningError("pinned RSA signing key must be 2048..8192 bits")
    return digest(result.stdout)


class Workload:
    def __init__(self, claims, token_digest, seal):
        if seal is not TOKEN:
            raise PlanningError("unverified workload")
        self.claims = MappingProxyType(copy.deepcopy(claims))
        self.token_sha256 = token_digest


def verify_oidc(raw, jwks_bytes, *, jwks_sha256, pins, now, fetched_at, max_cache_age=3600):
    """Offline verification of a pinned GitHub JWKS and exact workload claims.

    Subject is provisioned verbatim: GitHub's 2026 subject format can include
    immutable repository/owner IDs. Environment identity is not human consent.
    """
    if digest(jwks_bytes) != jwks_sha256 or not 0 <= now - fetched_at <= max_cache_age:
        raise PlanningError("untrusted or stale JWKS")
    if not isinstance(raw, str) or len(raw) > 32768 or len(raw.split(".")) != 3:
        raise PlanningError("invalid JWT encoding")
    head, body, signature = raw.split(".")
    header, claims = strict_json(b64(head)), strict_json(b64(body))
    if not isinstance(header, dict) or set(header) - {"alg", "kid", "typ"} or header.get("alg") != "RS256" or header.get("typ", "JWT") != "JWT":
        raise PlanningError("JWT algorithm/header substitution")
    jwks = strict_json(jwks_bytes)
    if not isinstance(jwks, dict) or set(jwks) != {"keys"} or not isinstance(jwks["keys"], list):
        raise PlanningError("invalid pinned JWKS")
    kids = [k.get("kid") for k in jwks["keys"] if isinstance(k, dict)]
    if len(kids) != len(jwks["keys"]) or len(set(kids)) != len(kids) or not all(isinstance(k, str) and k for k in kids):
        raise PlanningError("ambiguous JWKS identity")
    matches = [key for key in jwks["keys"] if key["kid"] == header.get("kid")]
    if len(matches) != 1:
        raise PlanningError("unknown JWT key")
    key = rsa_pem(matches[0])
    verify_bytes(key, digest(key), (head + "." + body).encode(), b64(signature))
    required = {"aud", "sub", "repository", "repository_id", "repository_owner_id", "ref", "sha",
                "workflow_ref", "workflow_sha", "job_workflow_ref", "job_workflow_sha", "environment",
                "event_name", "runner_environment", "run_id", "run_attempt", "actor_id"}
    if set(pins) != required or not isinstance(claims, dict):
        raise PlanningError("incomplete independent workload pins")
    if claims.get("iss") != "https://token.actions.githubusercontent.com" or any(claims.get(k) != v for k, v in pins.items()):
        raise PlanningError("wrong OIDC issuer/audience/workload claims")
    for name in ("iat", "nbf", "exp"):
        if type(claims.get(name)) is not int:
            raise PlanningError("invalid JWT time claim")
    if not (claims["iat"] <= now < claims["exp"] and claims["nbf"] <= now and
            claims["iat"] <= claims["nbf"] < claims["exp"] and 0 < claims["exp"] - claims["iat"] <= 600):
        raise PlanningError("expired or invalid JWT lifetime")
    if not isinstance(claims.get("jti"), str) or not claims["jti"] or len(claims["jti"]) > 256:
        raise PlanningError("missing JWT replay identity")
    return Workload(claims, digest(raw.encode()), TOKEN)


class Attestation:
    def __init__(self, role, payload, envelope_digest, seal):
        if seal is not TOKEN:
            raise PlanningError("unverified attestation")
        self.role, self._payload, self.sha256 = role, copy.deepcopy(payload), envelope_digest

    @property
    def payload(self):
        return copy.deepcopy(self._payload)


def verify_envelope(raw, *, role, public_key, key_sha256, expected, now):
    envelope = strict_json(raw)
    if not isinstance(envelope, dict) or set(envelope) != {"domain", "role", "payload", "signature"} or envelope["domain"] != "ro-repo-v3-backend-1" or envelope["role"] != role:
        raise PlanningError("attestation domain/role substitution")
    from ro_repo import validate_schema, ContractError
    try:
        validate_schema(envelope, "backend-envelope-v3")
    except ContractError as exc:
        raise PlanningError("invalid signed backend envelope schema") from exc
    unsigned = {k: envelope[k] for k in ("domain", "role", "payload")}
    verify_bytes(public_key, key_sha256, canonical(unsigned), b64(envelope["signature"]))
    payload = envelope["payload"]
    if not isinstance(payload, dict) or set(payload) != set(expected) | {"issued_at", "expires_at"} or any(payload[k] != v for k, v in expected.items()):
        raise PlanningError("altered attestation bindings")
    if type(payload["issued_at"]) is not int or type(payload["expires_at"]) is not int or not payload["issued_at"] <= now < payload["expires_at"] or not 0 < payload["expires_at"] - payload["issued_at"] <= 86400:
        raise PlanningError("expired attestation")
    return Attestation(role, payload, sha(envelope), TOKEN)


def require_attestation(value, role):
    if not isinstance(value, Attestation) or value.role != role:
        raise PlanningError("verified " + role + " attestation required")
    return value.payload


def test_workspace():
    root = pathlib.Path(tempfile.mkdtemp(prefix="v3-backend-test-"))
    (root / ".test-only").write_text("publishable=false\n")
    return root


def require_test_root(root):
    root = pathlib.Path(root)
    if (root.is_symlink() or root.parent.resolve() != pathlib.Path(tempfile.gettempdir()).resolve() or
            not re.fullmatch(r"v3-backend-test-[a-z0-9_-]+", root.name) or root.stat().st_uid != os.getuid() or
            root.stat().st_mode & 0o077 or (root / ".test-only").is_symlink() or
            (root / ".test-only").read_text() != "publishable=false\n"):
        raise PlanningError("only private disposable test storage is executable")
    return root


class TestSigner:
    """Disposable-key signer used by every executable backend adapter."""
    def __init__(self, root, name):
        self.root = require_test_root(root)
        if not re.fullmatch(r"[a-z][a-z-]{0,40}", name):
            raise PlanningError("invalid test key name")
        self.private = self.root / (name + ".private")
        if self.private.exists() or self.private.is_symlink():
            raise PlanningError("test key already exists")
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(self.private)], check=True, capture_output=True, timeout=30)
        self.private.chmod(0o600)
        self.public = subprocess.run(["openssl", "pkey", "-in", str(self.private), "-pubout"], check=True, capture_output=True, timeout=30).stdout
        self.key_sha256 = digest(self.public)

    def sign(self, data):
        require_test_root(self.root)
        if self.private.is_symlink() or not self.private.is_file():
            raise PlanningError("unsafe test key")
        return subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.private)], input=data, check=True, capture_output=True, timeout=30).stdout

    def envelope(self, role, payload):
        unsigned = {"domain": "ro-repo-v3-backend-1", "role": role, "payload": payload}
        return canonical({**unsigned, "signature": encode(self.sign(canonical(unsigned)))})
