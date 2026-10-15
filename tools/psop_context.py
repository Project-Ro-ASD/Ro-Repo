"""Physical local-only execution boundary and PSOP-specific signed test evidence.

Application Python is trusted, as in the V3 capability API. Untrusted callers
provide closed JSON and signatures, never pickled Python objects. No remote Git,
HTTP publication, caller-selected transport, environment credential or target is
accepted. A marker or test=true flag alone is insufficient.
"""
import copy
import os
import pathlib
import re
import shutil
import uuid

from v3_backend_trust import (TestSigner, test_workspace, require_test_root,
                              canonical, digest, strict_json, encode, b64, verify_bytes)
from v3_integration import tree_inventory
from v3_policy_profile import sha
from v3_promotion_planner import PlanningError

DOMAIN = "ro-repo-psop-disposable-1"
ROLES = ("audit", "approval", "source", "availability", "tests", "genesis", "drain", "publication")
SEAL = object()


class Evidence:
    def __init__(self, data, seal):
        if seal is not SEAL:
            raise PlanningError("verified PSOP capability required")
        self._data = copy.deepcopy(data)
        self.sha256 = sha(self._data)

    @property
    def data(self):
        return copy.deepcopy(self._data)

    def check(self):
        if sha(self._data) != self.sha256:
            raise PlanningError("mutated verified PSOP evidence")


class Context:
    @classmethod
    def create(cls):
        root = test_workspace()
        identity = uuid.uuid4().hex
        for role in ROLES:
            key = TestSigner(root, role)
            (root / (role + ".public")).write_bytes(key.public)
        descriptor = {"domain": DOMAIN, "id": identity,
            "repository": "psop-test/" + identity, "ref": "refs/heads/isolated-storage",
            "origin": "https://psop-" + identity + ".invalid", "device": root.stat().st_dev,
            "inode": root.stat().st_ino,
            "keys": {r: digest((root / (r + ".public")).read_bytes()) for r in ROLES}}
        raw = canonical(descriptor)
        (root / "psop-context.json").write_bytes(raw)
        return cls(root, digest(raw))

    def __init__(self, root, pin):
        self.root, self.pin = pathlib.Path(root), pin
        self.check()

    def check(self):
        require_test_root(self.root)
        path = self.root / "psop-context.json"
        if path.is_symlink() or digest(path.read_bytes()) != self.pin:
            raise PlanningError("disposable context pin mismatch")
        d = strict_json(path.read_bytes())
        expected = {"domain", "id", "repository", "ref", "origin", "device", "inode", "keys"}
        if (set(d) != expected or d["domain"] != DOMAIN or not re.fullmatch(r"[0-9a-f]{32}", d["id"])
                or d["repository"] != "psop-test/" + d["id"] or d["ref"] != "refs/heads/isolated-storage"
                or d["origin"] != "https://psop-" + d["id"] + ".invalid"
                or (d["device"], d["inode"]) != (self.root.stat().st_dev, self.root.stat().st_ino)
                or set(d["keys"]) != set(ROLES)):
            raise PlanningError("production or substituted execution context rejected")
        for role, pin in d["keys"].items():
            public = self.root / (role + ".public")
            private = self.root / (role + ".private")
            if public.is_symlink() or private.is_symlink() or digest(public.read_bytes()) != pin:
                raise PlanningError("disposable identity root mismatch")
        if len(set(d["keys"].values())) != len(ROLES):
            raise PlanningError("PSOP test roles must use distinct keys")
        self.descriptor = d
        return d

    def signer(self, role):
        d = self.check()
        if role not in ROLES:
            raise PlanningError("unsupported disposable issuer")
        key = TestSigner.__new__(TestSigner)
        key.root, key.private = self.root, self.root / (role + ".private")
        key.public, key.key_sha256 = (self.root / (role + ".public")).read_bytes(), d["keys"][role]
        return key

    def envelope(self, role, body, *, now, seconds=300):
        unsigned = {"domain": DOMAIN, "role": role, "context": self.pin,
                    "payload": {**body, "issued_at": now, "expires_at": now + seconds}}
        return canonical({**unsigned, "signature": encode(self.signer(role).sign(canonical(unsigned)))})

    def verify(self, raw, role, expected, *, now):
        self.check()
        e = strict_json(raw)
        if (not isinstance(e, dict) or set(e) != {"domain", "role", "context", "payload", "signature"}
                or e["domain"] != DOMAIN or e["role"] != role or e["context"] != self.pin):
            raise PlanningError("PSOP domain/role/context substitution")
        key = self.signer(role)
        verify_bytes(key.public, key.key_sha256, canonical({k: e[k] for k in e if k != "signature"}), b64(e["signature"]))
        p = e["payload"]
        if (not isinstance(p, dict) or set(p) != set(expected) | {"issued_at", "expires_at"}
                or canonical({k: p[k] for k in expected}) != canonical(expected)
                or type(p["issued_at"]) is not int or type(p["expires_at"]) is not int
                or not p["issued_at"] <= now < p["expires_at"]
                or not 0 < p["expires_at"] - p["issued_at"] <= 86400):
            raise PlanningError("PSOP exact binding or expiry mismatch")
        return Evidence({"role": role, "context": self.pin, "payload": p, "envelope_sha256": digest(raw)}, SEAL)

    def path(self, name):
        self.check()
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
            raise PlanningError("unsafe disposable member")
        p = self.root / name
        if p.is_symlink():
            raise PlanningError("symlinked disposable member")
        return p

    def close(self):
        self.check()
        shutil.rmtree(self.root)


def frozen_tree(path):
    return tree_inventory(path)


def require_evidence(value, context, role=None):
    context.check()
    if not isinstance(value, Evidence):
        raise PlanningError("verified PSOP evidence required")
    value.check()
    if value.data.get("context") != context.pin or role and value.data.get("role") != role:
        raise PlanningError("wrong PSOP evidence scope")
    return value.data
