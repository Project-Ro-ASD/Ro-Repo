"""Protected V3 publication state machine on the durable signed ledger.

Only isolated adapters execute in this milestone. Each successful publication
is a CAS advertisement of a remotely verified immutable view. POST_VERIFIED is
distinct from PUBLISHED: no local pointer operation proves CDN success.
"""
import copy

from v3_authorization import ID
from v3_backend_evidence import Authorization, Evidence, bindings
from v3_backend_trust import canonical, strict_json
from v3_immutable_view import VerifiedResult, StagedView, RemoteVerification
from v3_integration import verify_proposal
from v3_policy_profile import require_complete, sha
from v3_group_validation import stable_set_digest
from v3_promotion_planner import PlanningError

STATES = ("PROPOSED", "VERIFIED", "COMPOSED", "TESTED", "AWAITING_APPROVAL", "AUTHORIZED",
          "SIGNED", "STAGED", "REMOTE_VERIFIED", "PUBLISHED", "POST_VERIFIED")


class Backend:
    def __init__(self, ledger):
        if ledger.adapter.scope not in {"isolated-sqlite", "isolated-postgresql"}:
            raise PlanningError("production activation BLOCKED")
        self.ledger = ledger

    def create(self, proposal, plan, registry, attempt, *, operation="promote"):
        verify_proposal(proposal)
        if not isinstance(attempt, str) or not ID.fullmatch(attempt) or operation not in {"promote", "recover"}:
            raise PlanningError("invalid immutable attempt")
        policy = require_complete(plan, registry)
        if (sha(policy) != proposal["policy_sha256"] or plan["promotion_group"] != proposal["promotion_group"] or
                plan["selected_group_packages"] != proposal["candidate_identity"]["packages"] or
                stable_set_digest(plan) != proposal["stable_set_sha256"]):
            raise PlanningError("proposal/plan/registry divergence")
        immutable = {"proposal": proposal, "plan_sha256": sha(plan), "operation": operation}
        def change(db):
            row = db.execute("SELECT body FROM attempts WHERE id=?", (attempt,)).fetchone()
            if row:
                old = strict_json(row[0])
                if old["immutable"] != immutable:
                    raise PlanningError("conflicting immutable attempt replay")
                return old
            head = self.ledger.head(db)
            if proposal["previous_stable_sha256"] != head["digest"]:
                raise PlanningError("stale stable base")
            if operation == "recover":
                target = db.execute("SELECT body FROM views WHERE digest=?", (proposal["result_stable_sha256"],)).fetchone()
                if target is None or strict_json(target[0])["state"] != "POST_VERIFIED":
                    raise PlanningError("recovery requires previously verified immutable history")
            value = {"schema_version": 3, "scope": "v3-backend-isolated-attempt", "publishable": False,
                     "attempt_id": attempt, "state": "PROPOSED", "immutable": copy.deepcopy(immutable),
                     "base_generation": head["generation"], "proofs": {}, "failure": None}
            from ro_repo import validate_schema
            validate_schema(value, "backend-attempt-v3")
            db.execute("INSERT INTO attempts(id,body) VALUES(?,?)", (attempt, canonical(value).decode()))
            return value
        return self.ledger.execute("create-" + operation, attempt, change)[0]

    def _transition(self, attempt, target, proof, validate, *, inject=None):
        if target not in STATES[1:]:
            raise PlanningError("unsupported transition")
        def change(db):
            value = self.ledger.attempt(db, attempt)
            if target in value["proofs"]:
                if value["proofs"][target] != proof:
                    raise PlanningError("conflicting transition replay")
                return value
            expected = STATES[STATES.index(target) - 1]
            if value["state"] != expected:
                raise PlanningError("illegal publication transition: " + value["state"] + " -> " + target)
            validate(db, value)
            value["state"] = target
            value["proofs"][target] = copy.deepcopy(proof)
            self.ledger.put_attempt(db, value)
            return value
        return self.ledger.execute(target, attempt, change, inject=inject)[0]

    def verified(self, attempt, evidence):
        if not isinstance(evidence, Evidence) or self.ledger.clock() >= evidence.expiry:
            raise PlanningError("fresh authenticated evidence required")
        def validate(db, value):
            if evidence.data["bindings"] != bindings(value["immutable"]["proposal"]):
                raise PlanningError("evidence substitution")
        return self._transition(attempt, "VERIFIED", {"evidence_sha256": evidence.sha256}, validate)

    def composed(self, attempt, result):
        if not isinstance(result, VerifiedResult):
            raise PlanningError("cryptographically verified complete result required")
        result.check()
        def validate(db, value):
            if result.sha256 != value["immutable"]["proposal"]["result_stable_sha256"] or result.plan_sha256 != value["immutable"]["plan_sha256"]:
                raise PlanningError("complete result substitution")
        return self._transition(attempt, "COMPOSED", {"result_stable_sha256": result.sha256, "preflight_sha256": result.receipt}, validate)

    def tested(self, attempt, evidence):
        if not isinstance(evidence, Evidence) or self.ledger.clock() >= evidence.expiry:
            raise PlanningError("fresh authenticated acceptance required")
        def validate(db, value):
            if value["proofs"]["VERIFIED"]["evidence_sha256"] != evidence.sha256:
                raise PlanningError("test evidence substitution")
        return self._transition(attempt, "TESTED", {"evidence_sha256": evidence.sha256}, validate)

    def awaiting_approval(self, attempt):
        return self._transition(attempt, "AWAITING_APPROVAL", {"gate": "exact-protected-approval"}, lambda db, value: None)

    def authorized(self, attempt, approval, *, inject=None):
        if not isinstance(approval, Authorization) or self.ledger.clock() >= approval.expiry:
            raise PlanningError("fresh verified protected authorization required")
        def validate(db, value):
            from v3_authorization import request
            payload = approval.payload
            proposal = value["immutable"]["proposal"]
            op = value["immutable"]["operation"]
            target = proposal["result_stable_sha256"] if op == "recover" else None
            if (payload["request"] != request(proposal, attempt, operation=op, target_verified_sha256=target) or
                    payload["authenticated_evidence_sha256"] != value["proofs"]["TESTED"]["evidence_sha256"]):
                raise PlanningError("approval does not bind this tested attempt")
            head = self.ledger.head(db)
            if head["digest"] != proposal["previous_stable_sha256"] or head["generation"] != value["base_generation"]:
                raise PlanningError("stable CAS conflict before approval consumption")
            for kind, identity in (("approval", payload["approval_sha256"]), ("witness", payload["witness_sha256"]),
                                   ("jwt-jti", payload["jti"]), ("authorization", approval.sha256)):
                self.ledger.consume(db, kind, identity, attempt)
            if inject:
                inject("after-authorization-consumption")
        return self._transition(attempt, "AUTHORIZED", {"authorization_sha256": approval.sha256, "expires_at": approval.expiry}, validate, inject=inject)

    def signed(self, attempt, view):
        if not isinstance(view, StagedView):
            raise PlanningError("verified signed publication envelope required")
        view.check()
        def validate(db, value):
            if (view.sha256 != value["immutable"]["proposal"]["result_stable_sha256"] or
                    view.descriptor["authorization_sha256"] != value["proofs"]["AUTHORIZED"]["authorization_sha256"] or
                    self.ledger.clock() >= value["proofs"]["AUTHORIZED"]["expires_at"]):
                raise PlanningError("signing result/approval substitution or expiry")
        return self._transition(attempt, "SIGNED", {"publication_sha256": view.envelope_sha256,
                                "signing_key_sha256": view.descriptor["signing_key_sha256"]}, validate)

    def staged(self, attempt, view):
        if not isinstance(view, StagedView):
            raise PlanningError("immutable staging capability required")
        view.check()
        def validate(db, value):
            if value["proofs"]["SIGNED"]["publication_sha256"] != view.envelope_sha256:
                raise PlanningError("staged envelope substitution")
        return self._transition(attempt, "STAGED", {"publication_sha256": view.envelope_sha256, "result_stable_sha256": view.sha256}, validate)

    def remotely_verified(self, attempt, remote):
        return self._remote(attempt, "REMOTE_VERIFIED", remote)

    def _remote(self, attempt, target, remote):
        if not isinstance(remote, RemoteVerification):
            raise PlanningError("independent remote byte verification required")
        def validate(db, value):
            if (remote.data["result_stable_sha256"] != value["immutable"]["proposal"]["result_stable_sha256"] or
                    remote.data["publication_sha256"] != value["proofs"]["SIGNED"]["publication_sha256"] or
                    not 0 <= self.ledger.clock() - remote.data["verified_at"] <= 60):
                raise PlanningError("stale/substituted remote verification")
            if target == "POST_VERIFIED":
                head = self.ledger.head(db)
                if remote.data["phase"] != "post" or remote.data["advertised_generation"] != head["generation"] or head["digest"] != remote.data["result_stable_sha256"] or head["generation"] != value["base_generation"] + 1:
                    raise PlanningError("publication changed before post-verification")
                existing = db.execute("SELECT body FROM views WHERE digest=?", (head["digest"],)).fetchone()
                record = {"state": "POST_VERIFIED", "result_stable_sha256": head["digest"],
                          "first_attempt": attempt, "verification": remote.data}
                if existing is None:
                    db.execute("INSERT INTO views(digest,body) VALUES(?,?)", (head["digest"], canonical(record).decode()))
                head["last_verified"] = head["digest"]
                db.execute("UPDATE head SET body=? WHERE id=1", (canonical(head).decode(),))
            elif remote.data["phase"] != "pre":
                raise PlanningError("pre-publication byte verification required")
        return self._transition(attempt, target, {"verification": remote.data}, validate)

    def publish(self, attempt, approval, *, inject=None):
        if not isinstance(approval, Authorization) or self.ledger.clock() >= approval.expiry:
            raise PlanningError("fresh protected authorization required at advertisement")
        def validate(db, value):
            if approval.sha256 != value["proofs"]["AUTHORIZED"]["authorization_sha256"]:
                raise PlanningError("publication approval substitution")
            head = self.ledger.head(db)
            proposal = value["immutable"]["proposal"]
            if head["digest"] != proposal["previous_stable_sha256"] or head["generation"] != value["base_generation"]:
                raise PlanningError("stable CAS conflict at advertisement")
            updated = {"digest": proposal["result_stable_sha256"], "generation": head["generation"] + 1,
                       "last_verified": head["last_verified"]}
            db.execute("UPDATE head SET body=? WHERE id=1", (canonical(updated).decode(),))
            if inject:
                inject("after-advertisement")
        return self._transition(attempt, "PUBLISHED", {"authorization_sha256": approval.sha256}, validate, inject=inject)

    def post_verified(self, attempt, remote):
        return self._remote(attempt, "POST_VERIFIED", remote)

    def fail(self, attempt, reason):
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1024:
            raise PlanningError("invalid failure diagnosis")
        def change(db):
            value = self.ledger.attempt(db, attempt)
            if value["state"] in {"POST_VERIFIED", "FAILED"}:
                raise PlanningError("terminal attempt cannot be rewritten")
            value["failure"] = {"stage": value["state"], "reason": reason,
                                "needs_fresh_recovery": value["state"] == "PUBLISHED"}
            value["state"] = "FAILED"
            self.ledger.put_attempt(db, value)
            return value
        return self.ledger.execute("FAILED", attempt, change)[0]
