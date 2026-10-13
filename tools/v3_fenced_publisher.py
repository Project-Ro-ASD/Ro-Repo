"""Sole-writer admission boundary using existing signed ledger and outbox.

Workers hold no Git credentials. Their lease/fence is checked transactionally
at admission and immediately before the exact Git CAS becomes a durable service
intent. A committed service intent survives the worker lease; it is NOT a new
worker action. Unknown requests block all successors, including beta writers.
GitHub cannot fence an already admitted request's authorization deadline, or a
late Pages build. End-to-end production activation therefore remains BLOCKED.
"""
from v3_backend_trust import canonical, digest, strict_json
from v3_publication_outbox import Outbox
from v3_promotion_planner import PlanningError


class FencedPublisher:
    def __init__(self, backend, storage):
        self.backend, self.storage, self.outbox = backend, storage, Outbox(backend)

    def _available(self, db, attempt):
        for (raw,) in db.execute("SELECT body FROM attempts").fetchall():
            value = strict_json(raw)
            pending = value["proofs"].get("OUTBOX", {}).get("receipts", {}).get("provider_intent")
            if pending and pending["status"] == "IN_FLIGHT":
                raise PlanningError("unresolved provider intent blocks the whole storage writer realm")

    def _admit(self, attempt, owner, fence, phase, expected, target):
        def save(db, value, job):
            self._available(db, attempt)
            prior = job["receipts"].get("provider_intent")
            if prior and prior["phase"] == phase:
                raise PlanningError("reconcile the existing phase; do not replace its identity")
            binding = {"attempt_id":attempt, "phase":phase, "expected_git":expected, "target_git":target,
                "publication_sha256":job["immutable"]["publication_sha256"],
                "authorization_sha256":job["immutable"]["authorization_sha256"]}
            job["receipts"]["provider_intent"] = {"binding":binding, "idempotency_key":digest(canonical(binding)),
                "status":"IN_FLIGHT", "phase":phase, "worker_fence":fence, "worker_owner":owner,
                "admitted_at":self.backend.ledger.clock(), "lease_until":job["lease_until"]}
        self.outbox.locked(attempt, owner, fence, "provider-admit", save)

    def stage(self, view, approval, signer, *, owner, fence):
        attempt = view.descriptor["request"]["attempt_id"]
        def check(db, value, job):
            self._available(db, attempt)
            if value["state"] != "STAGED" or approval.sha256 != job["immutable"]["authorization_sha256"]:
                raise PlanningError("only exact staged outbox work can enter the publisher")
        self.outbox.locked(attempt, owner, fence, "provider-check", check)
        job = self.backend.ledger.inspect(attempt)["attempt"]["proofs"]["OUTBOX"]
        prior = job["receipts"].get("provider_intent")
        if prior and prior["phase"] == "stage" and prior["status"] == "CONFIRMED":
            if self.storage.head() != prior["binding"]["target_git"]:
                raise PlanningError("confirmed staging head changed")
            view.check()
            return self.storage._receipt(view, prior["binding"]["target_git"])
        receipt = self.storage.stage(view, approval, expected=job["immutable"]["expected_git"],
            publication_key=signer.public, publication_pin=signer.key_sha256, now=self.backend.ledger.clock(),
            before_cas=lambda old,new:self._admit(attempt, owner, fence, "stage", old, new))
        self.reconcile(attempt)
        return receipt

    def advertise(self, view, approval, remote, signer, *, owner, fence):
        attempt = view.descriptor["request"]["attempt_id"]
        def check(db, value, job):
            self._available(db, attempt)
            head = self.backend.ledger.head(db)
            if (value["state"] != "PUBLISHED" or head["digest"] != view.sha256 or
                    head["generation"] != value["base_generation"]+1 or approval.sha256 != job["immutable"]["authorization_sha256"]):
                raise PlanningError("exact publication intent required at sole writer boundary")
            return head["generation"]
        generation = self.outbox.locked(attempt, owner, fence, "provider-intent-check", check)
        prior = self.backend.ledger.inspect(attempt)["attempt"]["proofs"]["OUTBOX"]["receipts"].get("provider_intent")
        if prior and prior["phase"] == "advertisement" and prior["status"] == "CONFIRMED":
            return self.storage.advertisement_receipt(view, approval, remote, signer,
                commit=prior["binding"]["target_git"], generation=generation, now=self.backend.ledger.clock())
        receipt = self.storage.advertise_immutable(view, approval, remote, signer, expected=remote.data["git_commit"],
            generation=generation, now=self.backend.ledger.clock(),
            before_cas=lambda old,new:self._admit(attempt, owner, fence, "advertisement", old, new))
        self.reconcile(attempt)
        return receipt

    def reconcile(self, attempt):
        """A base head is never evidence that a lost request will not arrive."""
        record = self.backend.ledger.inspect(attempt)["attempt"]
        intent = record["proofs"]["OUTBOX"]["receipts"].get("provider_intent")
        if intent is None:
            raise PlanningError("missing durable provider intent")
        observed = self.storage.head()
        if observed != intent["binding"]["target_git"]:
            raise PlanningError("provider outcome unknown/changed; no retry or successor authority")
        def confirm(db, value):
            current = value["proofs"]["OUTBOX"]["receipts"]["provider_intent"]
            if current != intent:
                raise PlanningError("provider intent changed during reconciliation")
            current["status"] = "CONFIRMED"
        def change(db):
            value = self.backend.ledger.attempt(db, attempt)
            confirm(db, value)
            self.backend.ledger.put_attempt(db, value)
            return value["proofs"]["OUTBOX"]["receipts"]["provider_intent"]
        return self.backend.ledger.execute("provider-confirm", attempt, change)[0]

    def abort_noncommit(self, view, approval, *, observation_raw, observation_key, observation_pin):
        """Resolve UNKNOWN only with a fresh independently proven drained abort.

        This verifier does not create drain evidence. Native GitHub lacks that
        guarantee; an observer unable to prove it must refuse to sign.
        """
        from v3_backend_evidence import Authorization
        from v3_backend_trust import key_identity, verify_envelope
        from v3_immutable_view import StagedView
        if not isinstance(view, StagedView) or not isinstance(approval, Authorization):
            raise PlanningError("original verified publication capabilities required for abort binding")
        view.check()
        attempt=view.descriptor["request"]["attempt_id"]
        state=self.backend.ledger.inspect(attempt)
        intent=state["attempt"]["proofs"]["OUTBOX"]["receipts"].get("provider_intent")
        if (not intent or intent["status"]!="IN_FLIGHT" or approval.sha256!=intent["binding"]["authorization_sha256"] or
                view.envelope_sha256!=intent["binding"]["publication_sha256"] or self.backend.ledger.clock()<intent["lease_until"]):
            raise PlanningError("only an expired, unresolved exact provider intent can be independently aborted")
        roots={key_identity(self.backend.ledger.audit_key),view.descriptor["signing_key_identity"],
               approval.payload["approval_key_identity"],approval.payload["witness_key_identity"]}
        if key_identity(observation_key) in roots:
            raise PlanningError("independent provider abort observer required")
        expected={"provider_intent":intent["binding"],"checkpoint":state["checkpoint"],
            "writers_fenced":True,"requests_drained":True,"transaction_not_committed":True}
        observation=verify_envelope(observation_raw,role="restore-observation",public_key=observation_key,
            key_sha256=observation_pin,expected=expected,now=self.backend.ledger.clock())
        if not 0<=self.backend.ledger.clock()-observation.payload["issued_at"]<=60:
            raise PlanningError("stale provider abort evidence")
        def guard():
            if (self.backend.ledger.clock()>=observation.payload["expires_at"] or
                    self.storage.head()!=intent["binding"]["expected_git"] or
                    intent["binding"]["expected_git"]==intent["binding"]["target_git"]):
                raise PlanningError("provider abort cannot discard committed/changed/undrained work")
        guard()
        def change(db):
            value=self.backend.ledger.attempt(db,attempt)
            current=value["proofs"]["OUTBOX"]["receipts"]["provider_intent"]
            if current!=intent or self.backend.ledger._integrity(db)!=state["checkpoint"]:
                raise PlanningError("stale provider abort checkpoint/intent")
            current["status"]="ABORTED"
            current["abort_observation_sha256"]=observation.sha256
            self.backend.ledger.put_attempt(db,value)
            return current
        return self.backend.ledger.execute("provider-independent-abort",attempt,change,guard=guard)[0]

    def activate_production(self):
        raise PlanningError("production BLOCKED: independent writer custody/cutover, request drain and Pages ordering acceptance required")


def rehearsal_server(publisher, registry, credentials):
    """Loopback acceptance daemon; worker tokens never carry Git credentials.

    Production TLS/mTLS/identity ingress is deliberately not activated. Registry
    values are verified in-process capabilities, never deserialized from HTTP.
    """
    import hmac
    import http.server
    from v3_backend_trust import require_test_root
    require_test_root(publisher.storage.test_root)
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            owner = None
            auth = self.headers.get("Authorization", "")
            now = publisher.backend.ledger.clock()
            for candidate, entry in credentials.items():
                if now < entry["expires_at"] and hmac.compare_digest(auth, "Bearer " + entry["token"]):
                    owner = candidate
                    break
            status, result = 403, {"error":"worker authentication rejected"}
            if owner is not None:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if self.path != "/v1/stage" or not 0 < length <= 4096:
                        raise PlanningError("bounded publisher stage request required")
                    body = strict_json(self.rfile.read(length))
                    if (not isinstance(body, dict) or set(body) != {"attempt_id", "fence"} or
                            type(body["fence"]) is not int or body["fence"] < 1 or body["attempt_id"] not in registry):
                        raise PlanningError("closed publisher request identity required")
                    view, approval, signer = registry[body["attempt_id"]]
                    result = publisher.stage(view, approval, signer, owner=owner, fence=body["fence"])
                    status = 200
                except (PlanningError, ValueError):
                    status, result = 422, {"error":"publisher rejected stale/unverified/unknown work"}
                except Exception:
                    status, result = 503, {"error":"provider outcome unknown; reconcile durable intent"}
            raw = canonical(result)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
    return http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
