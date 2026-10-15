"""Layered PSOP fixtures: real crypto/Git/ledger, model RPMs in unit tests only."""
import copy
import functools
import gzip
import http.server
import pathlib
import shutil
import ssl
import subprocess
import threading
import types
import uuid

from psop_support import Fixture
from psop_context import frozen_tree, SEAL
from psop_signing import MetadataSigner, sign_result
from psop_result import UnsignedResult
from psop_authorization import approval_request, verify_approval
from psop_context import Evidence
from psop_client import Client, issue_descriptor
from v3_backend_trust import digest, test_workspace, canonical
from v3_policy_profile import sha


class DirectoryReader:
    def __init__(self, signed, publication, *, mutation=None):
        self.signed, self.raw, self.mutation = signed, publication, mutation

    def publication(self):
        return self.raw

    def read(self, path):
        raw = (self.signed.path / path).read_bytes()
        return raw if self.mutation is None else self.mutation(path, raw)


class TLSFixture:
    """Own loopback socket, private CA, no host trust-store edits."""
    def __init__(self, root, *, certificate_hostname="localhost"):
        self.root = pathlib.Path(root)
        self.public = self.root / "https-public";self.public.mkdir()
        cert, key = self.root / "tls.crt", self.root / "tls.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
            "-out", str(cert), "-days", "1", "-subj", "/CN=" + certificate_hostname, "-addext", "subjectAltName=DNS:" + certificate_hostname],
            check=True, capture_output=True)
        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=str(self.public)))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert, key)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.origin = "https://localhost:" + str(self.server.server_port)
        self.ca = {"path": str(cert), "sha256": digest(cert.read_bytes())}
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True);self.thread.start()

    def expose(self, gateway, signed, attempt):
        prefix = self.public / "psop/snapshots" / signed.data["result_sha256"]
        if not prefix.exists():shutil.copytree(signed.path, prefix)
        pubs = self.public / "psop/publications";pubs.mkdir(parents=True, exist_ok=True)
        p = gateway.ledger.inspect(attempt)["attempt"]["prepared"]
        raw = gateway._store._run(["cat-file", "blob", p["target_files"]["psop/publications/" + attempt + ".json"]])
        (pubs / (attempt + ".json")).write_bytes(raw)

    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join()


class ClientFixture(Fixture):
    """Real GPG metadata; fake RPM bytes, so tests explicitly mock RPM verifier.

    Actual RPM/header/DNF verification is never claimed by this unit fixture.
    tests/psop-fedora44-dnf5-e2e.py consumes PR-B's real RPM publisher instead.
    """
    def __init__(self):
        super().__init__()
        self.metadata = MetadataSigner.create(self.context)
        self.rpm = MetadataSigner.create(self.context)
        self.roots = {}
        for role, signer in (("rpm", self.rpm), ("metadata", self.metadata)):
            path = self.context.path(role + "-root");path.write_bytes(signer.public)
            self.roots[role] = {"path": str(path), "sha256": signer.pin, "fingerprint": signer.fingerprint}
        self.client_root = test_workspace()
        self.origin = "https://localhost:18443"
        self.client = self.make_client()

    def make_client(self, *, origin=None, ca=None, root=None, scope=None):
        key = self.context.signer("publication")
        return Client(root or self.client_root, origin=origin or self.origin, context=self.context.pin,
            publication_key=key.public, publication_pin=key.key_sha256, roots=self.roots, clock=lambda: self.now, ca=ca, scope=scope)

    def publication(self, *, version="1.0", previous=None, origin=None, seconds=300, scope=None):
        attempt = "client-" + uuid.uuid4().hex
        root = self.context.path("model-" + uuid.uuid4().hex);root.mkdir()
        packages = []
        for arch in ("noarch", "src"):
            filename = "fixture-" + version + "-1.fc44." + arch + ".rpm"
            raw = ("MODEL NOT RPM " + filename).encode()
            packages.append({"nevra": "fixture-0:" + version + "-1.fc44." + arch, "filename": filename,
                "architecture": arch, "producer_manifest_digest": "1" * 64, "producer_artifact_sha256": digest(raw),
                "published_signed_artifact_sha256": digest(raw)})
        for arch in ("x86_64", "aarch64", "source"):
            repo = root / "rpm" / arch;repo.mkdir(parents=True)
            entry = packages[1] if arch == "source" else packages[0]
            (repo / entry["filename"]).write_bytes(("MODEL NOT RPM " + entry["filename"]).encode())
            data = ('<metadata xmlns="http://linux.duke.edu/metadata/common"><package><location href="' + entry["filename"] + '"/>'
                    '<checksum type="sha256">' + entry["published_signed_artifact_sha256"] + '</checksum></package></metadata>').encode()
            md = repo / "repodata";md.mkdir();raw = gzip.compress(data, mtime=0)
            (md / "primary.xml.gz").write_bytes(raw)
            (md / "repomd.xml").write_text('<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><location href="repodata/primary.xml.gz"/>'
                '<checksum type="sha256">' + digest(raw) + '</checksum></data></repomd>')
        previous_result = None if previous is None else previous.signed.data["result_sha256"]
        manifest = {"domain": "psop-result-test-1", "plan_sha256": "2" * 64, "source_sha256": "3" * 64,
            "policy_sha256": sha(self.policy), "packages": packages, "parameters": {"source_date_epoch": self.now},
            "previous_stable_sha256": previous_result, "publishable": False, "rpm_signing_fingerprint": self.rpm.fingerprint}
        (root / "psop-result-v1.json").write_bytes(canonical(manifest))
        inventory = frozen_tree(root)
        unsigned = UnsignedResult({"context": self.context.pin, "inventory": inventory}, SEAL)
        unsigned.path, unsigned.prepared = root, types.SimpleNamespace(check=lambda: None)
        review = Evidence({"schema_version": 1, "domain": "psop-review-test-1", "context": self.context.pin,
            "profile": "psop-pages-stable", "source_pins": {"main_sha": "a" * 40, "pages_sha": "b" * 40},
            "inputs_sha256": "3" * 64, "history_sha256": "4" * 64, "genesis_sha256": "5" * 64 if previous is None else None,
            "previous_stable_sha256": previous_result, "policy_version": self.policy["version"], "policy_sha256": sha(self.policy),
            "plan_sha256": "2" * 64, "evidence_sha256": "6" * 64, "result_sha256": sha(inventory), "publishable": False}, SEAL)
        body = approval_request(review, self.identity, attempt=attempt, nonce=uuid.uuid4().hex, writer="psop-stable",
            expected_git=self.gateway._store.head(), metadata_key={"sha256": self.metadata.pin, "fingerprint": self.metadata.fingerprint})
        approval = verify_approval(self.context.envelope("approval", body, now=self.now, seconds=seconds),
            self.identity, review, self.policy, self.now, context=self.context)
        signed = sign_result(unsigned, approval, self.metadata, context=self.context, now=self.now)
        intent = self.gateway.prepare(signed, approval);self.gateway.admit(intent, approval);self.gateway.apply(attempt)
        descriptor = issue_descriptor(self.gateway, signed, approval, attempt, origin=origin or self.origin, now=self.now,
            previous=None if previous is None else previous.descriptor, seconds=seconds, scope=scope)
        record = self.ledger.inspect(attempt)["attempt"]["prepared"]
        raw = self.gateway._store._run(["cat-file", "blob", record["target_files"]["psop/publications/" + attempt + ".json"]])
        return types.SimpleNamespace(signed=signed, approval=approval, attempt=attempt, descriptor=descriptor,
                                     reader=DirectoryReader(signed, raw), packages=packages)

    def resign_descriptor(self, raw, **changes):
        from v3_backend_trust import strict_json
        d = strict_json(raw)["payload"];d.update(changes)
        return self.context.envelope("publication", {k: v for k, v in d.items() if k not in {"issued_at", "expires_at"}},
            now=d["issued_at"], seconds=d["expires_at"] - d["issued_at"])

    def close(self):
        for signer in (self.metadata, self.rpm):
            subprocess.run(["gpgconf", "--homedir", str(signer.home), "--kill", "gpg-agent"], capture_output=True)
        shutil.rmtree(self.client_root)
        super().close()
