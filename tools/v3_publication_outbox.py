"""Audited publication jobs on the existing ledger; disposable providers only.

An outbox is part of the signed attempt state, so authorization, replay, CAS,
leases and receipts survive restart together. External calls remain separate
from the DB commit. Reconciliation reads exact signed bytes after response loss.
Provider implementations must enforce fencing at their own mutation boundary.
"""
import copy
import re

from v3_backend_trust import canonical, digest, strict_json, verify_envelope
from v3_immutable_view import verify_remote
from v3_pages_backend import IsolatedGitStore, GitReader
from v3_promotion_planner import PlanningError


class Outbox:
    def __init__(self, backend):
        self.backend, self.ledger = backend, backend.ledger

    def enqueue(self, view, approval, expected_git):
        view.check()
        attempt = view.descriptor["request"]["attempt_id"]
        if expected_git is not None and not re.fullmatch(r"[0-9a-f]{40}", expected_git):
            raise PlanningError("exact Git base required")
        immutable = {"result_sha256": view.sha256, "publication_sha256": view.envelope_sha256,
                     "authorization_sha256": approval.sha256, "expected_git": expected_git}
        def change(db):
            value = self.ledger.attempt(db, attempt)
            if "OUTBOX" in value["proofs"]:
                old = value["proofs"]["OUTBOX"]
                if old["immutable"] != immutable:
                    raise PlanningError("conflicting outbox idempotency key")
                return old
            if (value["state"] != "STAGED" or approval.sha256 != value["proofs"]["AUTHORIZED"]["authorization_sha256"] or
                    view.envelope_sha256 != value["proofs"]["SIGNED"]["publication_sha256"]):
                raise PlanningError("outbox requires exact authorized signed staging")
            self.backend._fresh(approval.expiry)
            job = {"immutable": immutable, "fence": 0, "owner": None, "lease_until": 0,
                   "status": "PENDING", "receipts": {}}
            value["proofs"]["OUTBOX"] = job
            self.ledger.put_attempt(db, value)
            return job
        return self.ledger.execute("outbox-enqueue", attempt, change)[0]

    def claim(self, attempt, owner, *, seconds=30):
        if not isinstance(owner, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", owner) or type(seconds) is not int or not 1 <= seconds <= 60:
            raise PlanningError("invalid worker lease")
        def change(db):
            value = self.ledger.attempt(db, attempt)
            job = value["proofs"].get("OUTBOX")
            if job is None or job["status"] in {"COMPLETE", "FAILED"} or value["state"] == "FAILED":
                raise PlanningError("no runnable outbox job")
            now = self.ledger.clock()
            if job["lease_until"] > now:
                raise PlanningError("outbox is leased; no concurrent worker")
            self.backend._fresh(value["proofs"]["AUTHORIZED"]["expires_at"])
            job.update(fence=job["fence"] + 1, owner=owner, lease_until=now + seconds)
            self.ledger.put_attempt(db, value)
            return job["fence"]
        return self.ledger.execute("outbox-claim", attempt, change)[0]

    def locked(self, attempt, owner, fence, operation, call):
        """Serialize each provider mutation with lease/fence checks and audit.

        Calls can succeed externally then lose their response. They must be
        repeatable by exact signed object identity; no blind pointer retry.
        """
        checked = []
        def change(db):
            value = self.ledger.attempt(db, attempt)
            job = value["proofs"]["OUTBOX"]
            self._guard(value, owner, fence)
            result = call(db, value, job)
            self._guard(value, owner, fence, allow_complete=True)
            self.ledger.put_attempt(db, value)
            checked.append(value)
            return result
        # Remote audit/checkpoint signing can itself outlast a lease. The ledger
        # calls this guard again after signing and immediately before DB commit.
        return self.ledger.execute("outbox-" + operation, attempt, change,
            guard=lambda:self._guard(checked[0], owner, fence, allow_complete=True))[0]

    def deployment_identity(self, attempt, owner, fence, *, phase, git_commit):
        """Durably bind a deployment request BEFORE contacting any provider.

        This identity survives lease turnover; it supplies no deployment proof
        and does not imply the Pages API implements idempotency or fencing.
        """
        if phase not in {"pre", "post"} or not isinstance(git_commit, str) or not re.fullmatch(r"[a-f0-9]{40}", git_commit):
            raise PlanningError("exact deployment phase/commit required")
        def save(db, value, job):
            binding = {"attempt_id": attempt, "phase": phase, "git_commit": git_commit,
                "result_stable_sha256": job["immutable"]["result_sha256"],
                "publication_sha256": job["immutable"]["publication_sha256"],
                "authorization_sha256": job["immutable"]["authorization_sha256"]}
            request = {"idempotency_key": digest(canonical(binding)), "binding": binding}
            records = job["receipts"].setdefault("deployment_requests", {})
            if phase in records and records[phase] != request:
                raise PlanningError("conflicting durable deployment request identity")
            records[phase] = request
            return copy.deepcopy(request)
        return self.locked(attempt, owner, fence, "deployment-identity", save)

    def _guard(self, value, owner, fence, allow_complete=False):
        job = value["proofs"]["OUTBOX"]
        if (job["owner"] != owner or job["fence"] != fence or self.ledger.clock() >= job["lease_until"] or
                job["status"] == "FAILED" or job["status"] == "COMPLETE" and not allow_complete or value["state"] == "FAILED"):
            raise PlanningError("stale outbox worker/fence")
        self.backend._fresh(value["proofs"]["AUTHORIZED"]["expires_at"])


class SimulatedDeployment:
    """Reproducible local provider. Signed witness is explicitly test evidence."""
    def __init__(self, store, attest):
        self.store, self.attest = store, attest

    def verify(self, view, commit, *, now, ledger=None, signer=None):
        deployment = self.attest("deployment", {"result_stable_sha256": view.sha256,
            "publication_sha256": view.envelope_sha256, "git_commit": commit,
            "deployment_id": "simulated-" + commit})
        return verify_remote(view, GitReader(self.store, view), deployment, now=now, post_ledger=ledger,
            advertisement_key=None if signer is None else signer.public,
            advertisement_key_sha256=None if signer is None else signer.key_sha256)


class Coordinator:
    def __init__(self, backend, store, deployment):
        if not isinstance(store, IsolatedGitStore):
            raise PlanningError("production publication orchestration remains BLOCKED")
        self.backend, self.store, self.deployment = backend, store, deployment
        self.outbox = Outbox(backend)

    def run(self, view, approval, signer, *, owner, fence, inject=lambda _: None):
        attempt = view.descriptor["request"]["attempt_id"]
        now = self.backend.ledger.clock
        # Never reconstruct authorization from persisted JSON. The caller must
        # reverify its original envelopes after a restart; deadlines still apply.
        if approval.sha256 != view.descriptor["authorization_sha256"]:
            raise PlanningError("outbox authorization substitution")
        def stage(db, value, job):
            view.check()
            inject("before-git-stage")
            files = self.store._files(self.store.head())
            path = "v3/publications/" + attempt + ".json"
            if path in files:
                raw = self.store._run(["cat-file", "blob", files[path]])
                if raw != view.envelope:
                    raise PlanningError("staging response-loss conflict")
                # stage performs a no-op CAS and complete immutable comparison.
                receipt = self.store.stage(view, expected=self.store.head())
            else:
                receipt = self.store.stage(view, expected=job["immutable"]["expected_git"])
            inject("after-git-stage")
            job["receipts"]["stage"] = receipt
            return receipt["git_commit"]
        value = self.backend.ledger.inspect(attempt)["attempt"]
        if value["state"] == "POST_VERIFIED":
            if value["proofs"]["OUTBOX"]["status"] != "COMPLETE":
                def finish(db, value, job):
                    job["status"] = "COMPLETE"
                    job["receipts"]["post"] = value["proofs"]["POST_VERIFIED"]["verification"]
                self.outbox.locked(attempt, owner, fence, "complete-reconcile", finish)
            return self.backend.ledger.inspect(attempt)
        if value["state"] not in {"STAGED", "REMOTE_VERIFIED", "PUBLISHED"}:
            raise PlanningError("outbox cannot skip publication states")
        if value["state"] == "STAGED":
            commit = self.outbox.locked(attempt, owner, fence, "stage", stage)
            remote = self.deployment.verify(view, commit, now=now())
            self.backend.remotely_verified(attempt, remote)
            inject("after-pre-verification")
        value = self.backend.ledger.inspect(attempt)["attempt"]
        if value["state"] == "REMOTE_VERIFIED":
            self.outbox.locked(attempt, owner, fence, "intent-check", lambda db, value, job: None)
            self.backend.publish(attempt, approval)
            inject("after-db-intent")
        def advertise(db, value, job):
            head = self.backend.ledger.head(db)
            if head["digest"] != view.sha256 or head["generation"] != value["base_generation"] + 1:
                raise PlanningError("publication intent no longer owns stable CAS")
            remote_data = value["proofs"]["REMOTE_VERIFIED"]["verification"]
            current = self.store.head()
            reader = GitReader(self.store, view)
            try:
                raw = reader.advertisement()
            except FileNotFoundError:
                raw = None
            parsed = None if raw is None else strict_json(raw)["payload"]
            if parsed is not None and parsed.get("authorization_sha256") == approval.sha256:
                expected = {"result_stable_sha256": view.sha256, "publication_sha256": view.envelope_sha256,
                    "authorization_sha256": approval.sha256, "previous_stable_sha256": view.descriptor["request"]["previous_stable_sha256"],
                    "staged_git_commit": remote_data["git_commit"], "baseurls": view.descriptor["baseurls"],
                    "publishable": False, "generation": head["generation"]}
                verify_envelope(raw, role="stable-advertisement", public_key=signer.public,
                    key_sha256=signer.key_sha256, expected=expected, now=now())
                # Fences are checked under the common DB lock. Confirm actual
                # immutable payload even when a prior commit response was lost.
                self.store.stage(view, expected=current)
                receipt = {"git_commit": current, "advertisement_sha256": digest(raw), "reconciled": True}
            else:
                from v3_immutable_view import RemoteVerification
                from v3_backend_trust import TOKEN
                remote = RemoteVerification(copy.deepcopy(remote_data), TOKEN)
                receipt = self.store.advertise(view, approval, remote, signer, expected=remote_data["git_commit"],
                    previous_digest=view.descriptor["request"]["previous_stable_sha256"], now=now(), generation=head["generation"])
            inject("after-git-advertisement")
            job["receipts"]["advertisement"] = receipt
            job["status"] = "ADVERTISED"
            return receipt["git_commit"]
        commit = self.outbox.locked(attempt, owner, fence, "advertise", advertise)
        remote = self.deployment.verify(view, commit, now=now(), ledger=self.backend.ledger, signer=signer)
        inject("after-post-verification")
        self.backend.post_verified(attempt, remote)
        def complete(db, value, job):
            job["status"] = "COMPLETE"
            job["receipts"]["post"] = remote.data
        self.outbox.locked(attempt, owner, fence, "complete", complete)
        return self.backend.ledger.inspect(attempt)
