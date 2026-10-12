"""Verified stable discovery and one-view DNF update, disposable client roots.

Fresh nonce-bound discovery from an independent signer selects a POST_VERIFIED
view. Immutable publication signatures are checked at issuance; a fresh discovery
signature authorizes current use after the original publication approval expires.
No production client configuration is modified by this milestone.
"""
import contextlib
import fcntl
import os
import pathlib
import secrets
import subprocess
import tempfile

from v3_backend_trust import canonical, digest, require_test_root, strict_json, verify_envelope
from v3_immutable_view import HTTPSReader, immutable_url
from v3_policy_profile import sha
from v3_promotion_planner import PlanningError


def discovery_payload(ledger, view, nonce, *, origin):
    state = ledger.inspect(view.descriptor["request"]["attempt_id"])
    attempt = state["attempt"]
    if (attempt["state"] != "POST_VERIFIED" or attempt["proofs"]["SIGNED"]["publication_sha256"] != view.envelope_sha256 or
            attempt["proofs"]["POST_VERIFIED"]["verification"]["publication_sha256"] != view.envelope_sha256 or state["head"]["last_verified"] != view.sha256 or
            state["head"]["digest"] != view.sha256 or not isinstance(nonce, str) or len(nonce) != 64):
        raise PlanningError("discovery requires current independently post-verified view")
    return {"nonce": nonce, "origin": origin, "generation": state["head"]["generation"],
            "result_stable_sha256": view.sha256, "publication_sha256": view.envelope_sha256,
            "attempt_id": view.descriptor["request"]["attempt_id"], "checkpoint": state["checkpoint"],
            "post_verification_sha256": sha(attempt["proofs"]["POST_VERIFIED"]), "publishable": False}


class Client:
    def __init__(self, root, *, origin, discovery_key, discovery_pin, publication_key, publication_pin, rpm_key_url, metadata_key_url, clock,
                 rpm_key_sha256=None, metadata_key_sha256=None):
        self.root = require_test_root(root)
        immutable_url(origin, "0" * 64, "x86_64")
        if any(not v.startswith("file:///") or any(c in v for c in "\n\r \t") for v in (rpm_key_url, metadata_key_url)):
            raise PlanningError("preinstalled independently provisioned RPM key required")
        self.origin, self.discovery_key, self.discovery_pin = origin, discovery_key, discovery_pin
        self.publication_key, self.publication_pin = publication_key, publication_pin
        self.rpm_key_url, self.metadata_key_url, self.clock = rpm_key_url, metadata_key_url, clock
        self.key_pins = (rpm_key_sha256, metadata_key_sha256)

    @contextlib.contextmanager
    def locked(self):
        path = self.root / "client.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def update(self, discovery, *, reader_factory=HTTPSReader, command=None):
        require_test_root(self.root)
        with self.locked():
            if command is not None:
                self._command(command)
            nonce = secrets.token_hex(32)
            raw = discovery(nonce)
            payload = strict_json(raw).get("payload", {})
            expected_keys = {"nonce", "origin", "generation", "result_stable_sha256", "publication_sha256", "attempt_id", "checkpoint", "post_verification_sha256", "publishable"}
            if (set(payload) != expected_keys | {"issued_at", "expires_at"} or payload["nonce"] != nonce or payload["origin"] != self.origin or
                    type(payload["generation"]) is not int or payload["generation"] < 1 or payload["publishable"] is not False or
                    not isinstance(payload["checkpoint"], dict) or set(payload["checkpoint"]) != {"seq", "sha256"} or
                    type(payload["checkpoint"]["seq"]) is not int or payload["checkpoint"]["seq"] < 1):
                raise PlanningError("invalid current stable discovery contract")
            verify_envelope(raw, role="client-discovery", public_key=self.discovery_key, key_sha256=self.discovery_pin,
                expected={k: payload[k] for k in expected_keys}, now=self.clock())
            if payload["expires_at"] - payload["issued_at"] > 3600:
                raise PlanningError("discovery exceeds bounded freshness")
            reader = reader_factory(self.origin, payload["result_stable_sha256"], payload["attempt_id"])
            publication = reader.publication()
            if digest(publication) != payload["publication_sha256"]:
                raise PlanningError("discovery/publication substitution")
            descriptor = strict_json(publication).get("payload", {})
            from ro_repo import validate_schema, ContractError
            try:
                validate_schema(descriptor, "immutable-publication-v3")
            except ContractError as exc:
                raise PlanningError("invalid immutable publication") from exc
            verify_envelope(publication, role="publication", public_key=self.publication_key, key_sha256=self.publication_pin,
                expected={k: v for k, v in descriptor.items() if k not in {"issued_at", "expires_at"}}, now=descriptor["issued_at"])
            if (descriptor["result_stable_sha256"] != payload["result_stable_sha256"] or sha(descriptor["inventory"]) != payload["result_stable_sha256"] or
                    descriptor["request"]["attempt_id"] != payload["attempt_id"] or descriptor["signing_key_sha256"] != self.publication_pin or
                    descriptor["baseurls"] != {arch: immutable_url(self.origin, payload["result_stable_sha256"], arch) for arch in ("x86_64", "aarch64", "source")}):
                raise PlanningError("immutable discovery view binding mismatch")
            for item in descriptor["inventory"]:
                path = pathlib.PurePosixPath(item["path"])
                if path.is_absolute() or ".." in path.parts or path.as_posix() != item["path"] or "\\" in item["path"]:
                    raise PlanningError("unsafe immutable client member")
                if digest(reader.read(item["path"])) != item["sha256"]:
                    raise PlanningError("incomplete/mixed client view")
            if self.clock() >= payload["expires_at"]:
                raise PlanningError("discovery expired during complete-view verification")
            state_path = self.root / "client-state.json"
            if state_path.is_symlink():
                raise PlanningError("unsafe client state")
            if state_path.exists():
                previous = strict_json(state_path.read_bytes())
                if (payload["generation"] < previous["generation"] or payload["checkpoint"]["seq"] < previous["checkpoint"]["seq"] or
                        payload["generation"] == previous["generation"] and payload["result_stable_sha256"] != previous["result_stable_sha256"] or
                        payload["checkpoint"]["seq"] == previous["checkpoint"]["seq"] and payload["checkpoint"] != previous["checkpoint"]):
                    raise PlanningError("client stable rollback/equivocation")
            repo = ("[ro-stable-v3]\nname=Ro-ASD verified stable\nenabled=1\nbaseurl=" +
                    immutable_url(self.origin, payload["result_stable_sha256"], "x86_64").replace("/x86_64", "/$basearch") +
                    "\ngpgcheck=1\nrepo_gpgcheck=1\nsslverify=1\nskip_if_unavailable=0\ngpgkey=" + self.rpm_key_url + " " + self.metadata_key_url + "\n")
            repos = self.root / "repos"
            repos.mkdir(exist_ok=True)
            if repos.is_symlink():
                raise PlanningError("unsafe client repo directory")
            # Merge public subkey packets sharing one OpenPGP primary identity.
            # DNF may deduplicate separate role URLs before importing the second
            # subkey. This changes no key identity, RPM or metadata signature.
            if command is not None:
                from urllib.parse import urlsplit, unquote
                raw_keys = []
                for url, pin in zip((self.rpm_key_url, self.metadata_key_url), self.key_pins):
                    parsed = urlsplit(url)
                    path = pathlib.Path(unquote(parsed.path))
                    if parsed.netloc or parsed.query or parsed.fragment or path.is_symlink() or not path.is_file():
                        raise PlanningError("missing preinstalled public signing root")
                    raw = path.read_bytes()
                    if pin is None or digest(raw) != pin:
                        raise PlanningError("preinstalled signing root pin mismatch")
                    raw_keys.append(raw)
                bundle = self.root / "signing-roots.asc"
                with tempfile.TemporaryDirectory(prefix=".public-keys-", dir=self.root) as temp:
                    home = pathlib.Path(temp)
                    input_path = home / "roots.asc"
                    input_path.write_bytes(b"\n".join(raw_keys))
                    subprocess.run(["gpg", "--no-options", "--homedir", str(home), "--batch", "--import", str(input_path)],
                                   check=True, capture_output=True, timeout=30)
                    merged = subprocess.run(["gpg", "--no-options", "--homedir", str(home), "--batch", "--armor", "--export"],
                                            check=True, capture_output=True, timeout=30).stdout
                self._atomic(bundle, merged)
                repo = repo.replace(self.rpm_key_url + " " + self.metadata_key_url, "file://" + str(bundle))
            self._atomic(repos / "ro-stable-v3.repo", repo.encode())
            # Pin selected discovery state before DNF. A failed transaction may
            # retry this view, but cannot silently switch to an older generation.
            self._atomic(state_path, canonical({k: payload[k] for k in ("generation", "result_stable_sha256", "checkpoint")}))
            if command is not None:
                # Caller supplies an explicitly reviewed disposable installroot
                # command. No automatic host package or disk writes are exposed.
                subprocess.run([*command, "--setopt=reposdir=" + str(repos), "--setopt=ro-stable-v3.gpgcheck=1",
                    "--setopt=ro-stable-v3.repo_gpgcheck=1", "--setopt=ro-stable-v3.sslverify=1"], check=True, timeout=1800)
            return {"scope": "v3-client-isolated-update", "publishable": False, "result_sha256": payload["result_stable_sha256"],
                    "generation": payload["generation"], "repo_sha256": digest(repo.encode()), "view_verification": "PASS",
                    "dnf": "UNVERIFIED" if command is None else "PASS", "production_activation": "BLOCKED"}

    def _command(self, command):
        if not isinstance(command, list) or not command or any(not isinstance(arg, str) for arg in command) or pathlib.Path(command[0]).name != "dnf5":
            raise PlanningError("reviewed DNF5 command required")
        roots = [arg.split("=", 1)[1] for arg in command if arg.startswith("--installroot=")]
        if len(roots) != 1 or not pathlib.Path(roots[0]).is_absolute() or self.root not in pathlib.Path(roots[0]).resolve().parents:
            raise PlanningError("DNF writes require a private disposable installroot")
        if any("gpgcheck" in arg or "sslverify" in arg or arg.startswith(("--no-gpg", "--config", "--setopt=reposdir")) for arg in command):
            raise PlanningError("client verification configuration cannot be overridden")

    @staticmethod
    def _atomic(path, raw):
        if path.is_symlink():
            raise PlanningError("unsafe client output")
        fd, name = tempfile.mkstemp(prefix=".client-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, path)
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            if os.path.exists(name):
                os.unlink(name)
