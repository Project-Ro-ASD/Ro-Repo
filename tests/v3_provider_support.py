"""Disposable HTTP protocol doubles backed by actual Git objects.

Not live GitHub/Pages acceptance. No network outside loopback, real repository
write, deployment, production key, beta-history timestamp or success is implied.
"""
import base64
import http.server
import socket
import threading
import urllib.parse

from v3_backend_trust import b64, canonical, digest, encode, strict_json
from v3_pages_backend import IsolatedGitStore
from v3_provider_transport import ProviderTransport
from v3_promotion_planner import PlanningError


class ProtocolServer:
    def __init__(self, fx, keys):
        self.fx, self.keys = fx, keys
        self.store = IsolatedGitStore(fx.root)
        self.initial = self.store._cas({"rpm/fedora/44/beta/signed.asc": b"preserve beta signature",
            "publications/fedora/44/beta/101/publication-v1.json.asc": b"preserve historical signature"}, None)
        self.calls, self.handlers = [], {}
        self.truncated, self.lose_cas, self.corrupt_blob, self.repo_id = False, False, False, 123
        outer = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                self.handle_request("GET")
            def do_POST(self):
                self.handle_request("POST")
            def handle_request(self, method):
                if self.headers.get("Authorization") != "Bearer disposable-test-only":
                    self.send_error(401)
                    return
                path = urllib.parse.urlsplit(self.path).path
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                body = None if not raw else strict_json(raw)
                outer.calls.append((method, path, body))
                try:
                    response = outer.respond(method, path, body)
                    status, result = response[:2]
                    headers = {} if len(response) == 2 else response[2]
                    if path == "/graphql" and outer.lose_cas:
                        outer.lose_cas = False
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                except PlanningError:
                    status, result = 422, {"message": "rejected"}
                    headers = {}
                data = canonical(result)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(data)
        self.http = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.transport = ProviderTransport.rehearsal("http://127.0.0.1:" + str(self.http.server_port),
            lambda: ("disposable-test-only", fx.now + 30), lambda: fx.now, root=fx.root)

    def close(self):
        self.http.shutdown()
        self.thread.join(3)
        self.http.server_close()

    def respond(self, method, path, body):
        if path in self.handlers:
            return self.handlers[path](method, body)
        prefix = "/repos/test/disposable"
        if path == prefix:
            return 200, {"id": self.repo_id, "node_id": "R_test", "full_name": "test/disposable"}
        if path == prefix + "/git/ref/heads/isolated-storage":
            return 200, {"ref": "refs/heads/isolated-storage", "object": {"type": "commit", "sha": self.store.head()}}
        if path.startswith(prefix + "/git/commits/"):
            commit = path.rsplit("/", 1)[1]
            tree = self.store._run(["rev-parse", commit + "^{tree}"]).decode().strip()
            parents = self.store._run(["show", "-s", "--format=%P", commit]).decode().strip().split()
            return 200, {"sha": commit, "tree": {"sha": tree}, "parents": [{"sha": p} for p in parents]}
        if path.startswith(prefix + "/git/trees/"):
            tree = path.rsplit("/", 1)[1]
            files = self.store._files(tree)
            return 200, {"sha": tree, "truncated": self.truncated, "tree": [
                {"path": p, "type": "blob", "mode": "100644", "sha": s} for p, s in files.items()]}
        if path.startswith(prefix + "/git/blobs/"):
            sha = path.rsplit("/", 1)[1]
            raw = self.store._run(["cat-file", "blob", sha])
            if self.corrupt_blob:
                raw = b"corrupt"
            return 200, {"sha": sha, "size": len(raw), "encoding": "base64", "content": base64.b64encode(raw).decode()}
        if path == prefix + "/git/blobs":
            raw = base64.b64decode(body["content"], validate=True)
            sha = self.store._run(["hash-object", "-w", "--stdin"], data=raw).decode().strip()
            return 201, {"sha": sha}
        if path == prefix + "/git/trees":
            return 201, {"sha": self.store._tree({e["path"]: e["sha"] for e in body["tree"]})}
        if path == prefix + "/git/commits":
            args = ["commit-tree", body["tree"]]
            for parent in body["parents"]:
                args.extend(["-p", parent])
            return 201, {"sha": self.store._run(args, data=body["message"].encode()).decode().strip()}
        if path == "/graphql":
            value = body["variables"]["input"]
            update = value["refUpdates"][0]
            if update["force"] is not False or update["name"] != "refs/heads/isolated-storage" or value["repositoryId"] != "R_test":
                raise PlanningError("invalid CAS request")
            self.store._run(["update-ref", update["name"], update["afterOid"], update["beforeOid"]])
            return 200, {"data": {"updateRefs": {"clientMutationId": value["clientMutationId"]}}}
        return 404, {"message": "absent; not evidence"}

    def envelope(self, signer, role, payload):
        return strict_json(signer.envelope(role, {**payload, "issued_at": self.fx.now, "expires_at": self.fx.now + 60}))

    def approval_services(self):
        def approve(method, body):
            return 200, self.envelope(self.keys.signers["approval"], "human-approval", {**body, "reviewer_id": "456"})
        def witness(method, body):
            if "decision" not in body:
                body = {**body, "decision": "approved"}
            return 200, self.envelope(self.keys.signers["witness"], "protected-environment-witness",
                                      {k: v for k, v in body.items() if k != "approval"})
        self.handlers["/v1/approval"], self.handlers["/v1/witness"] = approve, witness

    def signing_service(self, signer):
        def sign(method, body):
            raw = b64(body["data"])
            return 200, {"nonce": body["nonce"], "sha256": digest(raw), "key_sha256": signer.key_sha256,
                         "signature": encode(signer.sign(raw))}
        self.handlers["/v1/sign"] = sign
