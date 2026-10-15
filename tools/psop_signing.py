"""Ephemeral subkey-only metadata signing. No production signing entry point."""
import pathlib
import shutil
import subprocess
import uuid

from psop_context import Evidence, SEAL, require_evidence, frozen_tree
from v3_policy_profile import sha, canonical
from v3_backend_trust import digest
from v3_promotion_planner import PlanningError
from ro_repo import export_role_public_key, _sign_file_exact, require_secret_signing_subkey, validate_role_public_key

PRODUCTION = {"9A66A082D96374DA27D7538FB2186A6F2FD84CB3", "38CB87F6FBD645309432A6E22E02DEE8828B769B",
              "1715DDA529B9ADB46D47CB389A62B8F9026E75E5"}


class MetadataSigner:
    @classmethod
    def create(cls, context):
        obj = cls.__new__(cls)
        obj.context = context
        seed = context.path("ceremony-" + uuid.uuid4().hex)
        seed.mkdir(mode=0o700)
        obj.home = context.path("metadata-" + uuid.uuid4().hex)
        obj.home.mkdir(mode=0o700)
        obj.password = context.path("passphrase-" + uuid.uuid4().hex)
        obj.password.write_bytes(b"")
        obj.password.chmod(0o600)
        def gpg(home, *args, data=None):
            return subprocess.run(["gpg", "--no-options", "--homedir", str(home), "--batch",
                "--pinentry-mode", "loopback", "--passphrase-file", str(obj.password), *args],
                input=data, capture_output=True, check=True).stdout
        try:
            gpg(seed, "--quick-generate-key", "PSOP EPHEMERAL TEST <test@invalid>", "rsa2048", "cert", "1d")
            fingerprints = lambda: [s.split(":")[9] for s in gpg(seed, "--with-colons", "--list-keys").decode().splitlines() if s.startswith("fpr:")]
            primary = fingerprints()[0]
            gpg(seed, "--quick-add-key", primary, "rsa2048", "sign", "1d")
            obj.fingerprint = fingerprints()[1]
            gpg(obj.home, "--import", data=gpg(seed, "--export-secret-subkeys", obj.fingerprint + "!"))
            obj.public = export_role_public_key(obj.home, obj.fingerprint).encode()
        finally:
            subprocess.run(["gpgconf", "--homedir", str(seed), "--kill", "gpg-agent"], capture_output=True)
            shutil.rmtree(seed)
        obj.pin = digest(obj.public)
        obj.grant = context.envelope("source", {"metadata_sha256": obj.pin, "subkey": obj.fingerprint,
            "home": obj.home.name, "scope": "ephemeral-test-metadata-only"}, now=0, seconds=86400)
        obj.check()
        return obj

    def check(self):
        self.context.check()
        if self.home.parent != self.context.root or self.home.is_symlink() or self.fingerprint in PRODUCTION:
            raise PlanningError("production or unscoped signing material rejected")
        self.context.verify(self.grant, "source", {"metadata_sha256": self.pin, "subkey": self.fingerprint,
            "home": self.home.name, "scope": "ephemeral-test-metadata-only"}, now=1)
        require_secret_signing_subkey(self.home, self.fingerprint, require_isolated=True)
        if digest(self.public) != self.pin:
            raise PlanningError("metadata public key mismatch")


class SignedResult(Evidence):
    def check(self):
        super().check()
        self.unsigned.check()
        if frozen_tree(self.path) != self.data["inventory"]:
            raise PlanningError("signed result changed")


def sign_result(verified_result, approval, test_signer, *, context, now):
    from psop_result import UnsignedResult
    if not isinstance(verified_result, UnsignedResult) or not isinstance(test_signer, MetadataSigner):
        raise PlanningError("verified unsigned result and ephemeral metadata signer required")
    a = require_evidence(approval, context, "approved")
    require_evidence(verified_result, context)
    test_signer.check()
    if (test_signer.context.pin != context.pin or a["expiry"] <= now
            or a["payload"]["metadata_key"] != {"sha256": test_signer.pin, "fingerprint": test_signer.fingerprint}
            or a["payload"]["review"]["result_sha256"] != sha(verified_result.data["inventory"])):
        raise PlanningError("exact result/signing role approval mismatch")
    target = context.path("signed-" + uuid.uuid4().hex)
    shutil.copytree(verified_result.path, target)
    for path in sorted(target.rglob("*")):
        if path.is_file() and (path.name == "repomd.xml" or path.name == "psop-result-v1.json"):
            _sign_file_exact(path, test_signer.home, test_signer.fingerprint, test_signer.password)
            subprocess.run(["gpg", "--no-options", "--homedir", str(test_signer.home), "--batch", "--verify",
                            str(path) + ".asc", str(path)], check=True, capture_output=True)
    (target / "test-metadata-public.asc").write_bytes(test_signer.public)
    inventory = frozen_tree(target)
    before = {x["path"]: x["sha256"] for x in verified_result.data["inventory"]}
    if any(before[p] != digest((target / p).read_bytes()) for p in before):
        raise PlanningError("signing changed approved bytes")
    value = SignedResult({"context": context.pin, "result_sha256": sha(verified_result.data["inventory"]),
        "approval_sha256": approval.sha256, "inventory": inventory, "metadata_key_sha256": test_signer.pin,
        "publishable": False, "production_activation": "BLOCKED"}, SEAL)
    value.path, value.unsigned, value.approval = target, verified_result, approval
    return value
