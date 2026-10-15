"""Single local-only writer gateway. No GitHub transport or production target API."""
import configparser
import contextlib
import fcntl
import os
import re

from psop_context import Evidence, SEAL, require_evidence
from psop_outbox import Outbox, Backend
from v3_pages_backend import IsolatedGitStore
from v3_fenced_publisher import FencedPublisher
from v3_backend_trust import canonical, digest, strict_json
from v3_policy_profile import sha
from v3_promotion_planner import PlanningError


class PreparedIntent(Evidence):
    def check(self):
        super().check()
        self.signed.check()


class LocalTransport(IsolatedGitStore):
    def __init__(self, context):
        self.context = context
        context.check()
        fresh = not (context.root / "storage.git").exists()
        super().__init__(context.root)
        self.epoch_file = context.root / "psop-transport-epoch"
        if fresh:
            self.epoch_file.write_text("0")
        self.check()

    def check(self):
        self.context.check()
        if self.git != self.context.root / "storage.git" or self.git.is_symlink():
            raise PlanningError("substituted storage backend")
        for p in self.git.rglob("*"):
            if p.is_symlink():
                raise PlanningError("symlinked Git backend")
        config = configparser.ConfigParser()
        config.read(self.git / "config")
        if set(config.sections()) != {"core"} or set(config["core"]) != {"repositoryformatversion", "filemode", "bare"} or config["core"]["bare"] != "true":
            raise PlanningError("remote/credential/hook/include Git configuration rejected")
        if (self.git / "objects/info/alternates").exists() or any(not p.name.endswith(".sample") for p in (self.git / "hooks").iterdir()):
            raise PlanningError("external object store or executable Git hook rejected")
        if self.epoch_file.is_symlink() or not re.fullmatch(r"[0-9]+", self.epoch_file.read_text()):
            raise PlanningError("missing/unsafe durable transport epoch")

    @contextlib.contextmanager
    def exclusive(self):
        self.check()
        path = self.context.root / "psop-transport-lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            self.check()
            yield
        finally:
            os.close(fd)

    def epoch(self):
        self.check()
        return int(self.epoch_file.read_text())

    def apply(self, p):
        with self.exclusive():
            if self.epoch() != p["transport_epoch"]:
                raise PlanningError("drained transport request fenced")
            self.verify_objects(p)
            parents = self._run(["show", "-s", "--format=%P", p["target_git"]]).decode().split()
            if parents != ([] if p["expected_git"] is None else [p["expected_git"]]):
                raise PlanningError("non-fast-forward prepared target rejected")
            self._run(["update-ref", "refs/heads/isolated-storage", p["target_git"], p["expected_git"] or "0" * 40])

    def verify_objects(self, p):
        self.check()
        if self._files(p["target_git"]) != p["target_files"]:
            raise PlanningError("provider outcome UNKNOWN or target tree mismatch")
        for path, expected in p["file_sha256"].items():
            if digest(self._run(["cat-file", "blob", p["target_files"][path]])) != expected:
                raise PlanningError("committed payload mismatch")

    def verify_target(self, p, *, historical=False):
        self.verify_objects(p)
        if historical:
            current = self._files(self.head())
            if any(current.get(path) != blob for path, blob in p["target_files"].items()):
                raise PlanningError("previous immutable publication bytes missing from current branch")
            self._run(["merge-base", "--is-ancestor", p["target_git"], self.head()])
        elif self.head() != p["target_git"]:
            raise PlanningError("provider outcome UNKNOWN or unexpected HEAD")

    def drain(self, binding, checkpoint, *, now):
        """Native local flock+epoch proof; no analogous GitHub guarantee claimed."""
        with self.exclusive():
            if self.head() != binding["expected_git"] or binding["expected_git"] == binding["target_git"]:
                raise PlanningError("committed/changed request cannot be aborted")
            epoch = self.epoch() + 1
            with self.epoch_file.open("w") as stream:
                stream.write(str(epoch)); stream.flush(); os.fsync(stream.fileno())
            return self.context.envelope("drain", {"binding": binding, "checkpoint": checkpoint,
                "epoch": epoch, "writers_fenced": True, "requests_drained": True,
                "transaction_not_committed": True}, now=now, seconds=60)


class Gateway:
    def __init__(self, ledger, context):
        context.check()
        if ledger.context.pin != context.pin:
            raise PlanningError("gateway realm mismatch")
        self.context, self.ledger = context, ledger
        self._store = LocalTransport(context)
        self.backend = Backend(ledger)
        self.outbox = Outbox(self.backend)
        # Admission, storage-wide IN_FLIGHT exclusion and exact-target durable
        # confirmation reuse the unchanged V3 fenced publisher implementation.
        self._publisher = FencedPublisher(self.backend, self._store)

    def prepare(self, signed, approval):
        from psop_signing import SignedResult
        if not isinstance(signed, SignedResult):
            raise PlanningError("verified signed PSOP result required")
        s, a = require_evidence(signed, self.context), require_evidence(approval, self.context, "approved")
        self._store.check()
        self.ledger._fresh(a["expiry"])
        if s["approval_sha256"] != approval.sha256 or a["payload"]["expected_git"] != self._store.head():
            raise PlanningError("signed result or expected Git base mismatch")
        expected = self._store.head()
        files = self._store._files(expected)
        previous = dict(files)
        prefix = "psop/snapshots/" + s["result_sha256"] + "/"
        additions = {prefix + f["path"]: (signed.path / f["path"]).read_bytes() for f in s["inventory"]}
        descriptor = {"context": self.context.pin, "writer": a["payload"]["writer"],
            "result_sha256": s["result_sha256"], "signed_inventory": s["inventory"],
            "approval_sha256": approval.sha256, "review": a["payload"]["review"],
            "metadata_key": a["payload"]["metadata_key"], "production_activation": "BLOCKED", "publishable": False}
        raw = self.context.envelope("publication", descriptor, now=self.ledger.clock())
        additions["psop/publications/" + a["payload"]["attempt"] + ".json"] = raw
        for path, data in additions.items():
            blob = self._store._run(["hash-object", "-w", "--stdin"], data=data).decode().strip()
            if path in files and files[path] != blob:
                raise PlanningError("immutable snapshot/history replacement rejected")
            files[path] = blob
        tree = self._store._tree(files)
        target = self._store._run(["commit-tree", tree, *([] if expected is None else ["-p", expected])],
                                  data=b"PSOP DISPOSABLE ONLY\n").decode().strip()
        if any(files.get(path) != blob for path, blob in previous.items()):
            raise PlanningError("prior Beta/snapshot/history bytes changed")
        value = PreparedIntent({"context": self.context.pin, "approval_sha256": approval.sha256,
            "result_sha256": s["result_sha256"], "publication_sha256": digest(raw),
            "expected_git": expected, "target_git": target, "target_files": files,
            "file_sha256": {path: digest(self._store._run(["cat-file", "blob", blob])) for path, blob in files.items()},
            "transport_epoch": self._store.epoch(), "publishable": False}, SEAL)
        value.signed = signed
        return value

    def admit(self, prepared, approval, *, inject=None):
        if not isinstance(prepared, PreparedIntent):
            raise PlanningError("verified prepared PSOP intent required")
        require_evidence(prepared, self.context)
        if self._store.head() != prepared.data["expected_git"]:
            raise PlanningError("Git base changed before admission")
        self._store.verify_objects(prepared.data)
        return self.outbox.enqueue(prepared, approval, inject=inject)

    def apply(self, attempt, *, owner="worker", inject=lambda _: None):
        record = self.ledger.inspect(attempt)["attempt"]
        job = record["proofs"]["OUTBOX"]
        if record["state"] in {"COMPLETE", "COMMITTED_EXPIRED"}:
            self._store.verify_target(record["prepared"], historical=True)
            return self.receipt(attempt)
        if job["receipts"].get("provider_intent"):
            raise PlanningError("existing provider intent requires reconciliation, never blind retry")
        fence = self.outbox.claim(attempt, owner)
        p = record["prepared"]
        self._store.check()
        self._publisher._admit(attempt, owner, fence, "psop-local-stage", p["expected_git"], p["target_git"])
        self.outbox.locked(attempt, owner, fence, "request-time",
            lambda db, value, job: job["receipts"].setdefault("requested_at", self.ledger.clock()))
        try:
            inject("after-durable-intent")
            self._store.apply(p)
            inject("after-git-cas")
        except BaseException:
            self._mark_unknown(attempt)
            raise
        return self.reconcile(attempt)

    def _mark_unknown(self, attempt):
        def change(db):
            value = self.ledger.attempt(db, attempt)
            value["state"] = "UNKNOWN"
            self.ledger.put_attempt(db, value)
        self.ledger.execute("psop-unknown", attempt, change)

    def reconcile(self, attempt):
        record = self.ledger.inspect(attempt)["attempt"]
        p = record["prepared"]
        if record["state"] in {"COMPLETE", "COMMITTED_EXPIRED"}:
            self._store.verify_target(p, historical=True)
            return self.receipt(attempt)
        self._store.verify_target(p)
        self._publisher.reconcile(attempt)
        def complete(db):
            value = self.ledger.attempt(db, attempt)
            job = value["proofs"]["OUTBOX"]
            expired = self.ledger.clock() >= value["approval"]["expiry"]
            value["state"] = "COMMITTED_EXPIRED" if expired else "COMPLETE"
            value["proofs"]["observed_at"] = self.ledger.clock()
            job["status"] = "FAILED" if expired else "COMPLETE"
            if not expired and value["approval"]["payload"]["writer"] in {"psop-stable", "v2-stable"}:
                head = self.ledger.head(db)
                if head["digest"] != value["approval"]["payload"]["review"]["previous_stable_sha256"]:
                    raise PlanningError("stable base changed at reconciliation")
                head.update(digest=p["result_sha256"], generation=head["generation"] + 1)
                db.execute("UPDATE head SET body=? WHERE id=1", (canonical(head).decode(),))
            self.ledger.put_attempt(db, value)
        self.ledger.execute("psop-confirm-local-tree", attempt, complete)
        return self.receipt(attempt)

    def abort_noncommit(self, attempt, proof_raw):
        from v3_backend_trust import strict_json
        state = self.ledger.inspect(attempt)
        record = state["attempt"]
        intent = record["proofs"]["OUTBOX"]["receipts"].get("provider_intent")
        if not intent or intent["status"] != "IN_FLIGHT":
            raise PlanningError("unresolved exact intent required")
        body = strict_json(proof_raw).get("payload", {})
        expected = {"binding": intent["binding"], "checkpoint": state["checkpoint"],
            "epoch": body.get("epoch"), "writers_fenced": True, "requests_drained": True,
            "transaction_not_committed": True}
        self.context.verify(proof_raw, "drain", expected, now=self.ledger.clock())
        with self._store.exclusive():
            if (type(body["epoch"]) is not int or body["epoch"] != self._store.epoch()
                    or body["epoch"] <= record["prepared"]["transport_epoch"]
                    or self._store.head() != intent["binding"]["expected_git"]):
                raise PlanningError("provider not independently fenced/drained/noncommitted")
            def change(db):
                if self.ledger._integrity(db) != state["checkpoint"]:
                    raise PlanningError("stale independent drain checkpoint")
                value = self.ledger.attempt(db, attempt)
                value["state"] = "ABORTED"
                value["proofs"]["OUTBOX"]["status"] = "FAILED"
                value["proofs"]["OUTBOX"]["receipts"]["provider_intent"]["status"] = "ABORTED"
                self.ledger.put_attempt(db, value)
            self.ledger.execute("psop-drained-noncommit", attempt, change)
        return self.receipt(attempt)

    def receipt(self, attempt):
        from psop_receipts import receipt
        return receipt(self.ledger, attempt)
