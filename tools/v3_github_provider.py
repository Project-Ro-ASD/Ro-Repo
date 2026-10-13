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

    @classmethod
    def disposable_acceptance(cls, transport, *, root, operator_authorized, **pins):
        """Explicit operator-only cloud TEST route; production remains blocked.

        Never called by CI or this work item. The dedicated repository must be
        precreated/marked by the operator and the broker must select ONLY it.
        """
        root = require_test_root(root)
        if (operator_authorized is not True or
                not re.fullmatch(r"[A-Za-z0-9_.-]+/ro-v3-disposable-[a-z0-9-]+", pins.get("repository", "")) or
                pins.get("ref") != "refs/heads/disposable-pages"):
            raise PlanningError("explicit dedicated disposable cloud repository authorization required")
        value = cls(transport, **pins)
        value.identity()
        metadata = transport.request("GET", value.base)
        installation = transport.request("GET", "/installation/repositories?per_page=100")
        if (metadata.get("description") != "RO V3 DISPOSABLE PROVIDER ACCEPTANCE ONLY" or
                installation.get("total_count") != 1 or
                [r.get("id") for r in installation.get("repositories", [])] != [value.repository_id]):
            raise PlanningError("dedicated test marker and single-repository GitHub App credential required")
        value.test_root = root
        return value

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

    def stage(self, view, approval, *, expected, publication_key, publication_pin, now, before_cas=None):
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
        commit = self._append(additions, expected=expected, request_id=view.envelope_sha256,
                              issued_at=view.descriptor["issued_at"], fresh=fresh, before_cas=before_cas)
        return self._receipt(view, commit)

    def _append(self, additions, *, expected, request_id, issued_at, fresh, before_cas=None):
        self._write_guard()
        oid(expected)
        for path in additions:
            member(path)
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
            if before_cas:
                before_cas(expected, expected)
            self._cas(expected, expected, request_id)
            return expected
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
        stamp = dt.datetime.fromtimestamp(issued_at, dt.timezone.utc).isoformat()
        author = {"name": "Ro V3 immutable staging", "email": "v3-staging@invalid", "date": stamp}
        fresh()
        commit = self.transport.request("POST", self.base + "/git/commits", {
            "message": "V3 immutable staging " + request_id, "tree": tree_sha, "parents": [expected],
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
            if before_cas:
                before_cas(target, target)
            self._cas(target, target, request_id)
        elif current == expected:
            if before_cas:
                before_cas(expected, target)
            self._cas(expected, target, request_id)
        else:
            raise PlanningError("stale Git head; refusing blind staging replay")
        return target

    def advertise_immutable(self, view, approval, remote, signer, *, expected, generation, now, before_cas=None):
        """Append a signed advertisement; never overwrite v3/stable.json."""
        self._write_guard()
        from v3_immutable_view import RemoteVerification
        if (not isinstance(view, StagedView) or not isinstance(approval, Authorization) or not isinstance(remote, RemoteVerification) or
                type(generation) is not int or generation < 1 or remote.data["phase"] != "pre" or remote.data["git_commit"] != expected or
                remote.data["result_stable_sha256"] != view.sha256 or remote.data["publication_sha256"] != view.envelope_sha256 or
                signer.key_sha256 != view.descriptor["signing_key_sha256"] or approval.sha256 != view.descriptor["authorization_sha256"]):
            raise PlanningError("exact protected immutable advertisement prerequisites required")
        def fresh():
            view.check()
            current = self.transport.clock()
            if not now <= current < min(approval.expiry, view.descriptor["expires_at"]) or not 0 <= current-remote.data["verified_at"] <= 60:
                raise PlanningError("immutable advertisement authority/observation expired")
        fresh()
        files = self.files(expected)
        publication = "v3/publications/" + view.descriptor["request"]["attempt_id"] + ".json"
        if publication not in files or self.blob(files[publication]) != view.envelope:
            raise PlanningError("staged publication envelope missing")
        for item in view.result.inventory:
            path = "v3/views/" + view.sha256 + "/" + member(item["path"])
            if path not in files or digest(self.blob(files[path])) != item["sha256"]:
                raise PlanningError("staged immutable bytes differ")
        payload = {"result_stable_sha256": view.sha256, "publication_sha256": view.envelope_sha256,
            "authorization_sha256": approval.sha256, "previous_stable_sha256": approval.payload["request"]["previous_stable_sha256"],
            "staged_git_commit": expected, "baseurls": view.descriptor["baseurls"], "publishable": False,
            "generation": generation, "issued_at": now, "expires_at": int(approval.expiry)}
        raw = signer.envelope("stable-advertisement", payload)
        verify_envelope(raw, role="stable-advertisement", public_key=signer.public, key_sha256=signer.key_sha256,
            expected={k:v for k,v in payload.items() if k not in {"issued_at", "expires_at"}}, now=now)
        path = "v3/advertisements/" + approval.sha256 + ".json"
        commit = self._append({path:raw}, expected=expected, request_id=digest(raw), issued_at=now, fresh=fresh, before_cas=before_cas)
        return {"git_commit":commit, "advertisement_sha256":digest(raw), "advertisement_path":path,
                "publishable":False, "deployment":"UNVERIFIED", "production_activation":"BLOCKED"}

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
