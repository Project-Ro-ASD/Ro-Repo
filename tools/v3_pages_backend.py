"""Git CAS staging/advertisement rehearsal for the immutable Pages protocol.

Every writable Git repository is created under a private disposable test root.
There is no remote, push, Actions deploy or pages-storage write operation.
Git CAS proves commit serialization, not atomic CDN visibility.
"""
import os
import pathlib
import re
import subprocess

from v3_backend_evidence import Authorization
from v3_backend_trust import TestSigner, canonical, digest, require_test_root, strict_json, verify_envelope
from v3_immutable_view import RemoteVerification, StagedView
from v3_promotion_planner import PlanningError


class IsolatedGitStore:
    def __init__(self, root):
        self.root = require_test_root(root)
        self.git = self.root / "storage.git"
        if self.git.is_symlink():
            raise PlanningError("unsafe isolated Git storage")
        if not self.git.exists():
            self._run(["init", "--bare", str(self.git)], external=True)
        config = self._run(["config", "--get-regexp", r"^remote\..*\.url$"], optional=True)
        if config:
            raise PlanningError("isolated Git storage must have no remote")

    def _run(self, args, *, data=None, optional=False, external=False):
        require_test_root(self.root)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.root),
               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
               "GIT_AUTHOR_NAME": "V3 TEST ONLY", "GIT_AUTHOR_EMAIL": "test@invalid",
               "GIT_COMMITTER_NAME": "V3 TEST ONLY", "GIT_COMMITTER_EMAIL": "test@invalid",
               "GIT_AUTHOR_DATE": "2026-10-11T12:00:00Z", "GIT_COMMITTER_DATE": "2026-10-11T12:00:00Z"}
        command = ["git", *([] if external else ["--git-dir", str(self.git)]), *args]
        result = subprocess.run(command, input=data, capture_output=True, env=env, timeout=30)
        if result.returncode and not optional:
            raise PlanningError("isolated Git CAS/operation failed")
        return result.stdout

    def head(self):
        value = self._run(["rev-parse", "--verify", "refs/heads/isolated-storage"], optional=True).decode().strip()
        return value or None

    def _files(self, commit):
        if commit is None:
            return {}
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise PlanningError("invalid exact Git base")
        result = {}
        for entry in self._run(["ls-tree", "-rz", commit]).split(b"\0"):
            if entry:
                info, path = entry.split(b"\t", 1)
                mode, kind, blob = info.split()
                if mode != b"100644" or kind != b"blob":
                    raise PlanningError("unsafe immutable Git tree member")
                result[path.decode()] = blob.decode()
        return result

    def _tree(self, files):
        nodes = {}
        for path, blob in files.items():
            parts = pathlib.PurePosixPath(path).parts
            current = nodes
            for part in parts[:-1]:
                current = current.setdefault(part, {})
            if parts[-1] in current:
                raise PlanningError("ambiguous Git tree")
            current[parts[-1]] = blob
        def write(node):
            entries = []
            for name, value in sorted(node.items()):
                kind, mode, oid = ("tree", "040000", write(value)) if isinstance(value, dict) else ("blob", "100644", value)
                entries.append((mode + " " + kind + " " + oid + "\t" + name).encode() + b"\0")
            return self._run(["mktree", "-z"], data=b"".join(entries)).decode().strip()
        return write(nodes)

    def _cas(self, additions, expected, *, mutable=()):
        if self.head() != expected:
            raise PlanningError("Git stable-base CAS conflict")
        files = self._files(expected)
        for path, raw in additions.items():
            relative = pathlib.PurePosixPath(path)
            if relative.is_absolute() or ".." in relative.parts or "\\" in path or relative.as_posix() != path:
                raise PlanningError("unsafe Pages destination")
            blob = self._run(["hash-object", "-w", "--stdin"], data=raw).decode().strip()
            if path in files and files[path] != blob and path not in mutable:
                raise PlanningError("immutable Pages history replacement")
            files[path] = blob
        tree = self._tree(files)
        if expected is not None and self._run(["rev-parse", expected + "^{tree}"]).decode().strip() == tree:
            # Even an exact retry must linearize against concurrent ref writers.
            self._run(["update-ref", "refs/heads/isolated-storage", expected, expected])
            return expected
        commit = self._run(["commit-tree", tree, *([] if expected is None else ["-p", expected])], data=b"V3 isolated immutable view\n").decode().strip()
        self._run(["update-ref", "refs/heads/isolated-storage", commit, expected or "0" * 40])
        return commit

    def stage(self, view, *, expected):
        if not isinstance(view, StagedView):
            raise PlanningError("signed immutable view required")
        view.check()
        additions = {"v3/views/" + view.sha256 + "/" + item["path"]: (view.path / "payload" / item["path"]).read_bytes() for item in view.result.inventory}
        attempt = view.descriptor["request"]["attempt_id"]
        additions["v3/publications/" + attempt + ".json"] = view.envelope
        view.check()
        return {"scope": "v3-pages-isolated-staging", "publishable": False, "git_commit": self._cas(additions, expected),
                "result_stable_sha256": view.sha256, "publication_sha256": view.envelope_sha256, "cdn_atomicity": "UNVERIFIED"}

    immutable_advertisements = False

    def advertisement_path(self, view):
        return "v3/stable.json"

    def advertise(self, view, approval, remote, signer, *, expected, previous_digest, now, generation=None):
        if (not isinstance(view, StagedView) or not isinstance(approval, Authorization) or
                not isinstance(remote, RemoteVerification) or not isinstance(signer, TestSigner) or
                now >= approval.expiry or approval.sha256 != view.descriptor["authorization_sha256"] or
                remote.data["phase"] != "pre" or remote.data["result_stable_sha256"] != view.sha256 or
                remote.data["publication_sha256"] != view.envelope_sha256 or remote.data["git_commit"] != expected or
                not 0 <= now - remote.data["verified_at"] <= 60 or signer.key_sha256 != view.descriptor["signing_key_sha256"]):
            raise PlanningError("verified exact protected publication prerequisites required")
        files = self._files(expected)
        pointer = self.advertisement_path(view)
        old = None
        if pointer in files:
            old_raw = self._run(["cat-file", "blob", files[pointer]])
            old_payload = strict_json(old_raw)["payload"]
            # Historical approval expiry does not invalidate the already
            # published immutable record; validate its signature at issuance.
            verify_envelope(old_raw, role="stable-advertisement", public_key=signer.public,
                            key_sha256=signer.key_sha256, expected={k: v for k, v in old_payload.items() if k not in {"issued_at", "expires_at"}}, now=old_payload["issued_at"])
            old = old_payload["result_stable_sha256"]
        if self.immutable_advertisements:
            if type(generation) is not int or generation < 1:
                raise PlanningError("exact ledger intent generation required for immutable advertisement")
            old = previous_digest
        if old != previous_digest or approval.payload["request"]["previous_stable_sha256"] != previous_digest:
            raise PlanningError("signed stable advertisement base conflict")
        # Independently verify staging bytes in this exact commit, before any
        # mutable advertisement. No partial upload can become stable authority.
        for item in view.result.inventory:
            path = "v3/views/" + view.sha256 + "/" + item["path"]
            if path not in files or digest(self._run(["cat-file", "blob", files[path]])) != item["sha256"]:
                raise PlanningError("Git staged immutable payload missing/corrupt")
        record = {"result_stable_sha256": view.sha256, "publication_sha256": view.envelope_sha256,
                  "authorization_sha256": approval.sha256, "previous_stable_sha256": previous_digest,
                  "staged_git_commit": expected, "baseurls": view.descriptor["baseurls"], "publishable": False,
                  "generation": generation if self.immutable_advertisements else (1 if old is None else old_payload["generation"] + 1),
                  "issued_at": now, "expires_at": int(approval.expiry)}
        raw = signer.envelope("stable-advertisement", record)
        verify_envelope(raw, role="stable-advertisement", public_key=signer.public,
                        key_sha256=signer.key_sha256,
                        expected={k: v for k, v in record.items() if k not in {"issued_at", "expires_at"}}, now=now)
        commit = self._cas({pointer: raw}, expected, mutable=() if self.immutable_advertisements else (pointer,))
        return {"git_commit": commit, "advertisement_sha256": digest(raw), "publishable": False,
                "remote_post_verification": "UNVERIFIED", "production_activation": "BLOCKED"}


class GitReader:
    """Read the actual isolated Git tree, including signed stable advertisement."""
    def __init__(self, store, view):
        self.store, self.view = store, view
        self.commit = store.head()

    def check_deployment(self, expected):
        if self.commit is None or self.commit != expected or self.store.head() != self.commit:
            raise PlanningError("Git deployment identity/ref changed during verification")

    def _read(self, path):
        files = self.store._files(self.commit)
        if path not in files:
            raise FileNotFoundError(path)
        return self.store._run(["cat-file", "blob", files[path]])

    def read(self, path):
        return self._read("v3/views/" + self.view.sha256 + "/" + path)

    def publication(self):
        return self._read("v3/publications/" + self.view.descriptor["request"]["attempt_id"] + ".json")

    def advertisement(self):
        return self._read(self.store.advertisement_path(self.view))


class ImmutableBranchStore(IsolatedGitStore):
    """Disposable branch protocol: signed intent records are append-only.

    Only independent signed discovery selects a POST_VERIFIED generation.
    No mutable stable pointer is added to the Pages tree.
    """
    immutable_advertisements = True

    def advertisement_path(self, view):
        return "v3/advertisements/" + view.descriptor["authorization_sha256"] + ".json"
