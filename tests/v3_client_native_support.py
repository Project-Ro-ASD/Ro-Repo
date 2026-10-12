"""Actual HTTPS discovery/DNF transactions with signed synthetic RPM fixtures."""
import functools
import hashlib
import http.server
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from v3_backend_support import Keys, Fixture, NOW
from v3_backend_trust import TestSigner, canonical
from v3_client_update import Client, discovery_payload
from v3_immutable_view import HTTPSReader


def exercise(first, second, rpm_key, metadata_key, work, evidence):
    if not any(pathlib.Path(p).is_file() for p in ("/run/.containerenv", "/.dockerenv")):
        raise RuntimeError("Native client test requires a disposable container")
    keys = Keys()
    fixtures = []
    web_server = None
    try:
        observer = TestSigner(keys.root, "discovery")
        fixtures = [Fixture(keys, attempt="client-release-one", result_source=first),
                    Fixture(keys, attempt="client-release-two", result_source=second)]
        public = work / "client-https"
        public.mkdir()
        for fx in fixtures:
            fx.complete(origin="https://localhost")
            # These synthetic authorization envelopes bind actual signed RPM
            # inventory. They make no claim of real application acceptance.
            raw = fx.view.envelope
            # Test-only discovery advertises two successive views; independent
            # synthetic ledgers cannot represent real production continuity.
            view_path = public / "v3/views" / fx.result.sha256
            shutil.copytree(fx.source, view_path)
            pubs = public / "v3/publications"
            pubs.mkdir(exist_ok=True)
            (pubs / (fx.attempt + ".json")).write_bytes(raw)
        cert, private = work / "client-server.crt", work / "client-server.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(private), "-out", str(cert),
            "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
        anchor = pathlib.Path("/etc/pki/ca-trust/source/anchors/v3-client-disposable.crt")
        shutil.copyfile(cert, anchor)
        subprocess.run(["update-ca-trust"], check=True, capture_output=True)
        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass
        web_server = http.server.ThreadingHTTPServer(("127.0.0.1", 443), functools.partial(Handler, directory=str(public)))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, private)
        web_server.socket = ctx.wrap_socket(web_server.socket, server_side=True)
        thread = threading.Thread(target=web_server.serve_forever, daemon=True)
        thread.start()
        root = fixtures[0].root
        signer = keys.signers["publication"]
        client = Client(root, origin="https://localhost", discovery_key=observer.public, discovery_pin=observer.key_sha256,
            publication_key=signer.public, publication_pin=signer.key_sha256,
            rpm_key_url="file://" + str(rpm_key), metadata_key_url="file://" + str(metadata_key), clock=lambda: NOW,
            rpm_key_sha256=hashlib.sha256(rpm_key.read_bytes()).hexdigest(), metadata_key_sha256=hashlib.sha256(metadata_key.read_bytes()).hexdigest())
        receipts = []
        installroot = root / "dnf-root"
        (installroot / "etc").mkdir(parents=True)
        shutil.copyfile("/etc/os-release", installroot / "etc/os-release")
        for index, fx in enumerate(fixtures, 1):
            def discovery(nonce):
                payload = discovery_payload(fx.ledger, fx.view, nonce, origin="https://localhost")
                payload["generation"] = index
                payload["checkpoint"] = {"seq": index*100, "sha256": str(index)*64}
                return observer.envelope("client-discovery", {**payload, "issued_at": NOW, "expires_at": NOW + 60})
            command = ["dnf5", "-y", "--installroot=" + str(installroot), "--releasever=44", "--setopt=install_weak_deps=False",
                "--setopt=cachedir=" + str(root / "cache"), "--setopt=logdir=" + str(root / "logs"),
                "--disable-repo=*", "--enable-repo=ro-stable-v3", "install" if index == 1 else "upgrade", "ro-assist"]
            receipts.append(client.update(discovery, reader_factory=HTTPSReader, command=command))
            installed = subprocess.run(["rpm", "--root", str(installroot), "-q", "ro-assist", "--qf", "%{VERSION}"], check=True, capture_output=True).stdout
            if installed != str(index).encode() + b".0":
                raise AssertionError("normal DNF client did not discover/install successive stable version")
        (evidence / "client-discovery-dnf.json").write_bytes(canonical({"scope": "v3-native-client-synthetic-acceptance", "publishable": False,
            "https_complete_views": "PASS", "signed_metadata": "PASS", "install_and_future_upgrade": "PASS", "receipts": receipts,
            "production_discovery_service": "UNVERIFIED", "real_applications": "UNVERIFIED", "production_activation": "BLOCKED"}))
    finally:
        if web_server is not None:
            web_server.shutdown()
            web_server.server_close()
        for fx in fixtures:
            fx.close()
        keys.close()
