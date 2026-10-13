"""Real GitHub REST object protocol and GraphQL expected-head staging CAS.

Live reads are supported. Every live mutation remains BLOCKED. Write protocol
execution is restricted to a loopback disposable server. GitHub CAS cannot
enforce outbox lease expiry or fence delayed Pages deployments.
"""
import base64
import datetime as dt
import hashlib
import pathlib
import re

from v3_backend_evidence import Authorization
from v3_backend_trust import digest, require_test_root, verify_envelope
from v3_immutable_view import StagedView
from v3_provider_transport import ProviderTransport
from v3_promotion_planner import PlanningError


def oid(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{40}", value):
        raise PlanningError("exact Git object identity required")
    return value


def member(path):
    if (not isinstance(path, str) or not path or pathlib.PurePosixPath(path).is_absolute() or
            ".." in pathlib.PurePosixPath(path).parts or "\\" in path or
            pathlib.PurePosixPath(path).as_posix() != path or any(ord(c) < 32 for c in path)):
        raise PlanningError("unsafe Git member")
    return path


def blob_oid(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


class GitHubStorage:
    def __init__(self, transport, *, repository, repository_id, node_id, ref):
        if (not isinstance(transport, ProviderTransport) or transport.origin != "https://api.github.com" or
                not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or
                type(repository_id) is not int or repository_id < 1 or not isinstance(node_id, str) or not node_id or
                not isinstance(ref, str) or not re.fullmatch(r"refs/heads/[A-Za-z0-9_-]+", ref)):
            raise PlanningError("independently pinned GitHub repository ID/node/ref required")
        self.transport, self.repository, self.repository_id = transport, repository, repository_id
        self.node_id, self.ref, self.test_root = node_id, ref, None
        self.base = "/repos/" + repository

    @classmethod
    def rehearsal(cls, transport, *, root, **pins):
        root = require_test_root(root)
        if transport.test_root != root:
            raise PlanningError("GitHub protocol writes require disposable loopback transport")
        # Validate exactly the same pins as live configuration.
        validator = ProviderTransport("https://api.github.com", transport.credential, transport.clock)
        value = cls(validator, **pins)
        value.transport, value.test_root = transport, root
        return value

    def _write_guard(self):
        if self.test_root is None:
            raise PlanningError("live GitHub mutation BLOCKED; provider fencing and separate cutover required")
        require_test_root(self.test_root)

    def identity(self):
        value = self.transport.request("GET", self.base)
        if (value.get("id") != self.repository_id or value.get("node_id") != self.node_id or
                value.get("full_name") != self.repository):
            raise PlanningError("GitHub repository identity changed")

    def head(self):
        self.identity()
        value = self.transport.request("GET", self.base + "/git/ref/" + self.ref[5:])
        if value.get("ref") != self.ref or value.get("object", {}).get("type") != "commit":
            raise PlanningError("exact existing storage ref required; missing ref is not empty-stable proof")
        return oid(value["object"]["sha"])

    def files(self, commit):
        value = self.transport.request("GET", self.base + "/git/commits/" + oid(commit))
        if value.get("sha") != commit:
            raise PlanningError("GitHub commit substitution")
        tree = oid(value.get("tree", {}).get("sha"))
        value = self.transport.request("GET", self.base + "/git/trees/" + tree + "?recursive=1")
        if value.get("sha") != tree or value.get("truncated") is not False or not isinstance(value.get("tree"), list):
            raise PlanningError("incomplete GitHub inventory; never infer absence from truncation")
        files, seen = {}, set()
        for entry in value["tree"]:
            path = member(entry.get("path"))
            if path in seen:
                raise PlanningError("duplicate Git tree member")
            seen.add(path)
            oid(entry.get("sha"))
            if entry.get("type") == "tree" and entry.get("mode") == "040000":
                continue
            if entry.get("type") != "blob" or entry.get("mode") != "100644":
                raise PlanningError("unsafe Git inventory mode")
            files[path] = entry["sha"]
        return files

    def blob(self, sha):
        value = self.transport.request("GET", self.base + "/git/blobs/" + oid(sha))
        if value.get("sha") != sha or value.get("encoding") != "base64" or not isinstance(value.get("content"), str):
            raise PlanningError("invalid GitHub blob response")
        try:
            raw = base64.b64decode(value["content"].replace("\n", ""), validate=True)
        except ValueError:
            raise PlanningError("invalid GitHub blob encoding") from None
        if value.get("size") != len(raw) or blob_oid(raw) != sha:
            raise PlanningError("Git blob bytes differ from object identity")
        return raw

    def empty_history(self, commit, *, limit=10000):
        """Fail closed on stable in ANY reachable ancestor, including deletions.

        Unreachable/force-deleted history needs the independent storage observer
        and repository retention audit; this scan alone is not an empty proof.
        """
        pending, visited = [oid(commit)], {}
        while pending:
            current = pending.pop()
            if current in visited:
                continue
            if len(visited) >= limit:
                raise PlanningError("storage ancestry exceeds complete bootstrap scan bound")
            files = self.files(current)
            for path in files:
                if (path == "v3/stable.json" or path.startswith(("rpm/fedora/44/stable/",
                        "publications/fedora/44/stable/", "channels/stable/"))):
                    raise PlanningError("real stable history exists; protected import required")
            visited[current] = files
            value = self.transport.request("GET", self.base + "/git/commits/" + current)
            if value.get("sha") != current or not isinstance(value.get("parents"), list):
                raise PlanningError("incomplete storage ancestry")
            pending.extend(oid(parent.get("sha")) for parent in value["parents"])
        from v3_backend_trust import canonical
        return digest(canonical(visited))

    def _cas(self, expected, target, request_id):
        self._write_guard()
        query = "mutation($input:UpdateRefsInput!){updateRefs(input:$input){clientMutationId}}"
        result = self.transport.request("POST", "/graphql", {"query": query, "variables": {"input": {
            "repositoryId": self.node_id, "clientMutationId": request_id,
            "refUpdates": [{"name": self.ref, "beforeOid": oid(expected), "afterOid": oid(target), "force": False}]}}})
        if result.get("errors") or result.get("data", {}).get("updateRefs", {}).get("clientMutationId") != request_id:
            raise PlanningError("provider expected-head CAS rejected; reconcile exact commit")
        if self.head() != target:
            raise PlanningError("Git head changed after CAS; independent reconciliation required")

    def stage(self, view, approval, *, expected, publication_key, publication_pin, now):
        self._write_guard()
        oid(expected)
        if not isinstance(view, StagedView) or not isinstance(approval, Authorization):
            raise PlanningError("verified signed staging and protected approval required")
        def fresh():
            clock = self.transport.clock()
            if (not now <= clock < min(approval.expiry, view.descriptor["expires_at"]) or
                    approval.sha256 != view.descriptor["authorization_sha256"] or
                    approval.payload["request"] != view.descriptor["request"] or
                    view.descriptor["inventory"] != view.result.inventory or
                    view.descriptor["result_stable_sha256"] != view.sha256 or
                    approval.payload["request"]["result_stable_sha256"] != view.sha256 or
                    view.descriptor["signing_key_sha256"] != publication_pin):
                raise PlanningError("expired/substituted staging authorization")
            view.check()
        fresh()
        verify_envelope(view.envelope, role="publication", public_key=publication_key, key_sha256=publication_pin,
            expected={k: v for k, v in view.descriptor.items() if k not in {"issued_at", "expires_at"}}, now=now)
        attempt = view.descriptor["request"]["attempt_id"]
        additions = {"v3/views/" + view.sha256 + "/" + member(i["path"]): (view.path / "payload" / i["path"]).read_bytes()
                     for i in view.result.inventory}
        additions["v3/publications/" + attempt + ".json"] = view.envelope
        original = self.files(expected)
        files = dict(original)
        for path, raw in additions.items():
            sha = blob_oid(raw)
            if path in files and files[path] != sha:
                raise PlanningError("immutable Git history replacement rejected")
            files[path] = sha
        for path in files:
            if any(parent.as_posix() in files for parent in pathlib.PurePosixPath(path).parents if parent.as_posix() != "."):
                raise PlanningError("Git file/directory collision")
        current = self.head()
        if files == original:
            if current != expected:
                raise PlanningError("stale Git staging base")
            fresh()
            self._cas(expected, expected, view.envelope_sha256)
            return self._receipt(view, expected)
        # Immutable object POSTs can leave orphan objects after response loss.
        # They never advertise stable authority. Commit data is deterministic.
        for path, raw in sorted(additions.items()):
            if path in original:
                continue
            fresh()
            result = self.transport.request("POST", self.base + "/git/blobs", {
                "content": base64.b64encode(raw).decode(), "encoding": "base64"})
            if result.get("sha") != files[path]:
                raise PlanningError("uploaded Git blob identity differs")
        fresh()
        tree = self.transport.request("POST", self.base + "/git/trees", {"tree": [
            {"path": p, "mode": "100644", "type": "blob", "sha": s} for p, s in sorted(files.items())]})
        tree_sha = oid(tree.get("sha"))
        stamp = dt.datetime.fromtimestamp(view.descriptor["issued_at"], dt.timezone.utc).isoformat()
        author = {"name": "Ro V3 immutable staging", "email": "v3-staging@invalid", "date": stamp}
        fresh()
        commit = self.transport.request("POST", self.base + "/git/commits", {
            "message": "V3 immutable staging " + view.envelope_sha256, "tree": tree_sha, "parents": [expected],
            "author": author, "committer": author})
        target = oid(commit.get("sha"))
        stored_commit = self.transport.request("GET", self.base + "/git/commits/" + target)
        if (stored_commit.get("sha") != target or stored_commit.get("tree", {}).get("sha") != tree_sha or
                not isinstance(stored_commit.get("parents"), list) or
                [parent.get("sha") for parent in stored_commit["parents"]] != [expected]):
            raise PlanningError("provider staged commit changed expected history ancestry")
        if self.files(target) != files:
            raise PlanningError("provider staged tree lost historical bytes")
        for path, raw in additions.items():
            if self.blob(files[path]) != raw:
                raise PlanningError("provider staged bytes differ")
        fresh()
        # An exact deterministic commit identifies a lost successful response;
        # clientMutationId alone is NOT a GitHub idempotency guarantee.
        current = self.head()
        if current == target:
            self._cas(target, target, view.envelope_sha256)
        elif current == expected:
            self._cas(expected, target, view.envelope_sha256)
        else:
            raise PlanningError("stale Git head; refusing blind staging replay")
        return self._receipt(view, target)

    @staticmethod
    def _receipt(view, commit):
        return {"git_commit": commit, "result_stable_sha256": view.sha256,
                "publication_sha256": view.envelope_sha256, "publishable": False,
                "deployment": "UNVERIFIED", "production_activation": "BLOCKED"}

    def advertise(self, *args, **kwargs):
        raise PlanningError("GitHub stable advertisement BLOCKED: CAS does not fence expired provider requests")


class GitHubPages:
    def __init__(self, storage):
        self.storage = storage

    def status(self, deployment_id):
        if not isinstance(deployment_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", deployment_id):
            raise PlanningError("exact Pages deployment identity required")
        self.storage.identity()
        return self.storage.transport.request("GET", self.storage.base + "/pages/deployments/" + deployment_id)

    def request(self, *args, **kwargs):
        raise PlanningError("Pages deployment BLOCKED: no provider-enforced fence/lease deadline or durable idempotency contract")
