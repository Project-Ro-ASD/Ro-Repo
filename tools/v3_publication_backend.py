"""Protected V3 publication state machine on the durable signed ledger.

Only isolated adapters execute in this milestone. Each successful publication
is a CAS advertisement of a remotely verified immutable view. POST_VERIFIED is
distinct from PUBLISHED: no local pointer operation proves CDN success.
"""
import copy

from v3_authorization import ID
from v3_backend_evidence import Authorization, Evidence, bindings
from v3_backend_trust import canonical, strict_json, key_identity
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
            if operation == "promote" and head["digest"] != head["last_verified"]:
                raise PlanningError("unverified advertisement requires recovery before another promotion")
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

    def _transition(self, attempt, target, proof, validate, *, inject=None, guard=None):
        if target not in STATES[1:]:
            raise PlanningError("unsupported transition")
        changed = []
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
            changed.append(value)
            return value
        check = None if guard is None else lambda: guard(changed[0])
        return self.ledger.execute(target, attempt, change, inject=inject, guard=check)[0]

    def _fresh(self, expires_at):
        if self.ledger.clock() >= expires_at:
            raise PlanningError("authority expired before transaction completion")

    def _fresh_remote(self, verification):
        if not 0 <= self.ledger.clock() - verification["verified_at"] <= 60:
            raise PlanningError("stale remote verification at advertisement")

    def verified(self, attempt, evidence):
        if not isinstance(evidence, Evidence) or self.ledger.clock() >= evidence.expiry:
            raise PlanningError("fresh authenticated evidence required")
        def validate(db, value):
            if evidence.data["bindings"] != bindings(value["immutable"]["proposal"]):
                raise PlanningError("evidence substitution")
        return self._transition(attempt, "VERIFIED", {"evidence_sha256": evidence.sha256}, validate,
                                guard=lambda value: self._fresh(evidence.expiry))

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
        return self._transition(attempt, "TESTED", {"evidence_sha256": evidence.sha256}, validate,
                                guard=lambda value: self._fresh(evidence.expiry))

    def awaiting_approval(self, attempt):
        return self._transition(attempt, "AWAITING_APPROVAL", {"gate": "exact-protected-approval"}, lambda db, value: None)

    def authorized(self, attempt, approval, *, inject=None):
        if not isinstance(approval, Authorization) or self.ledger.clock() >= approval.expiry:
            raise PlanningError("fresh verified protected authorization required")
        def validate(db, value):
            from v3_authorization import request
            payload = approval.payload
            if key_identity(self.ledger.audit_key) in {payload["approval_key_identity"], payload["witness_key_identity"]}:
                raise PlanningError("canonical audit/authorization key role collision")
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
        return self._transition(attempt, "AUTHORIZED", {"authorization_sha256": approval.sha256, "expires_at": approval.expiry}, validate, inject=inject,
                                guard=lambda value: self._fresh(approval.expiry))

    def signed(self, attempt, view):
        if not isinstance(view, StagedView):
            raise PlanningError("verified signed publication envelope required")
        view.check()
        def validate(db, value):
            if (view.sha256 != value["immutable"]["proposal"]["result_stable_sha256"] or
                    view.descriptor["signing_key_identity"] == key_identity(self.ledger.audit_key) or
                    view.descriptor["authorization_sha256"] != value["proofs"]["AUTHORIZED"]["authorization_sha256"] or
                    self.ledger.clock() >= value["proofs"]["AUTHORIZED"]["expires_at"]):
                raise PlanningError("signing result/approval substitution or expiry")
        return self._transition(attempt, "SIGNED", {"publication_sha256": view.envelope_sha256,
                                "signing_key_sha256": view.descriptor["signing_key_sha256"]}, validate,
                                guard=lambda value: self._fresh(view.descriptor["expires_at"]))

    def staged(self, attempt, view):
        if not isinstance(view, StagedView):
            raise PlanningError("immutable staging capability required")
        view.check()
        def validate(db, value):
            self._fresh(value["proofs"]["AUTHORIZED"]["expires_at"])
            if value["proofs"]["SIGNED"]["publication_sha256"] != view.envelope_sha256:
                raise PlanningError("staged envelope substitution")
        return self._transition(attempt, "STAGED", {"publication_sha256": view.envelope_sha256, "result_stable_sha256": view.sha256}, validate,
                                guard=lambda value: self._fresh(view.descriptor["expires_at"]))

    def remotely_verified(self, attempt, remote):
        return self._remote(attempt, "REMOTE_VERIFIED", remote)

    def _remote(self, attempt, target, remote):
        if not isinstance(remote, RemoteVerification):
            raise PlanningError("independent remote byte verification required")
        def validate(db, value):
            self._fresh(value["proofs"]["AUTHORIZED"]["expires_at"])
            if (remote.data["result_stable_sha256"] != value["immutable"]["proposal"]["result_stable_sha256"] or
                    remote.data["publication_sha256"] != value["proofs"]["SIGNED"]["publication_sha256"] or
                    not 0 <= self.ledger.clock() - remote.data["verified_at"] <= 60):
                raise PlanningError("stale/substituted remote verification")
            if target == "POST_VERIFIED":
                self.ledger._integrity(db, remote.data["advertisement_checkpoint"])
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
        def guard(value):
            self._fresh_remote(remote.data)
            self._fresh(value["proofs"]["AUTHORIZED"]["expires_at"])
        return self._transition(attempt, target, {"verification": remote.data}, validate, guard=guard)

    def publish(self, attempt, approval, *, inject=None):
        if not isinstance(approval, Authorization) or self.ledger.clock() >= approval.expiry:
            raise PlanningError("fresh protected authorization required at advertisement")
        def validate(db, value):
            self._fresh_remote(value["proofs"]["REMOTE_VERIFIED"]["verification"])
            if approval.sha256 != value["proofs"]["AUTHORIZED"]["authorization_sha256"]:
                raise PlanningError("publication approval substitution")
            head = self.ledger.head(db)
            proposal = value["immutable"]["proposal"]
            resumed = value["immutable"]["operation"] == "resume-first"
            if resumed and (head["digest"] != proposal["result_stable_sha256"] or
                    head["generation"] != value["base_generation"] + 1 or head["last_verified"] is not None):
                raise PlanningError("first-publication intent changed before authorized resume")
            if not resumed and (head["digest"] != proposal["previous_stable_sha256"] or head["generation"] != value["base_generation"]):
                raise PlanningError("stable CAS conflict at advertisement")
            updated = {"digest": proposal["result_stable_sha256"], "generation": head["generation"] if resumed else head["generation"] + 1,
                       "last_verified": head["last_verified"]}
            db.execute("UPDATE head SET body=? WHERE id=1", (canonical(updated).decode(),))
            if inject:
                inject("after-advertisement")
        def guard(value):
            self._fresh(approval.expiry)
            self._fresh_remote(value["proofs"]["REMOTE_VERIFIED"]["verification"])
        return self._transition(attempt, "PUBLISHED", {"authorization_sha256": approval.sha256}, validate, inject=inject, guard=guard)

    def post_verified(self, attempt, remote):
        return self._remote(attempt, "POST_VERIFIED", remote)

    def first_resume_binding(self, predecessor):
        state = self.ledger.inspect(predecessor)
        value = state["attempt"]
        return self._first_resume_binding(value, state["head"], state["checkpoint"])

    @staticmethod
    def _first_resume_binding(value, head, checkpoint):
        inherited = value["immutable"].get("resume") if value["immutable"]["operation"] == "resume-first" else None
        resumable = value["state"] in {"AUTHORIZED", "SIGNED", "STAGED", "REMOTE_VERIFIED", "PUBLISHED", "FAILED"}
        # An ordinary losing attempt cannot adopt another publisher's equal
        # digest. It must itself have committed PUBLISHED. A child can inherit
        # that same proven intent even if it expires before its first signature.
        owns_intent = "PUBLISHED" in value["proofs"] if inherited is None else "REAUTHORIZED" in value["proofs"]
        if (value["immutable"]["proposal"]["previous_stable_sha256"] is not None or
                not resumable or not owns_intent or
                head != {"digest": value["immutable"]["proposal"]["result_stable_sha256"],
                                  "generation": value["base_generation"] + 1, "last_verified": None}):
            raise PlanningError("only an unfinished first-publication intent can be reauthorized")
        return {"predecessor": value["attempt_id"], "checkpoint": checkpoint,
            "authorization_sha256": value["proofs"]["AUTHORIZED"]["authorization_sha256"],
            "publication_sha256": value["proofs"].get("SIGNED", {}).get("publication_sha256") or inherited["publication_sha256"],
            "storage_commit": value["proofs"].get("REMOTE_VERIFIED", {}).get("verification", {}).get("git_commit") or inherited["storage_commit"]}

    def reauthorize_first(self, attempt, evidence, result, approval, *, observation_raw, observation_key, observation_pin):
        """Append a fresh child attempt; never rewrite original signed proofs.

        A drained/fenced independent observer must authorize the exact old audit
        tip. Fresh human/witness authorization explicitly binds resume-first.
        The existing intent generation is adopted, never reset or made verified.
        """
        from v3_backend_evidence import authorization_request
        from v3_backend_trust import canonical, verify_envelope
        if (not isinstance(evidence, Evidence) or not isinstance(result, VerifiedResult) or
                not isinstance(approval, Authorization) or not isinstance(attempt, str) or not ID.fullmatch(attempt)):
            raise PlanningError("fresh verified first-publication reauthorization prerequisites required")
        self._fresh(min(evidence.expiry, approval.expiry))
        resume = approval.payload["request"].get("resume")
        if not isinstance(resume, dict):
            raise PlanningError("explicit resume-first protected authorization required")
        old_state = self.ledger.inspect(resume.get("predecessor"))
        old = old_state["attempt"]
        proposal = old["immutable"]["proposal"]
        expected = authorization_request(proposal, attempt, evidence, operation="resume-first", resume=resume)
        if (any(approval.payload.get(k) != v for k,v in expected.items()) or
                result.sha256 != proposal["result_stable_sha256"] or result.plan_sha256 != old["immutable"]["plan_sha256"]):
            raise PlanningError("reauthorization changed exact tested result")
        identities = {approval.payload["approval_key_identity"], approval.payload["witness_key_identity"], key_identity(self.ledger.audit_key)}
        if len(identities) != 3 or key_identity(observation_key) in identities:
            raise PlanningError("independent recovery observer/approval/witness/audit roots required")
        observation = verify_envelope(observation_raw, role="restore-observation", public_key=observation_key,
            key_sha256=observation_pin, expected={"resume": resume, "writers_fenced": True, "requests_drained": True}, now=self.ledger.clock())
        if not 0 <= self.ledger.clock() - observation.payload["issued_at"] <= 60:
            raise PlanningError("stale first-publication recovery observation")
        result.check()
        immutable = {"proposal": copy.deepcopy(proposal), "plan_sha256": result.plan_sha256,
                     "operation": "resume-first", "resume": copy.deepcopy(resume)}
        def change(db):
            existing = db.execute("SELECT body FROM attempts WHERE id=?", (attempt,)).fetchone()
            if existing is not None:
                value = strict_json(existing[0])
                if value["immutable"] != immutable or value["proofs"]["AUTHORIZED"]["authorization_sha256"] != approval.sha256:
                    raise PlanningError("conflicting reauthorization replay")
                return value
            predecessor = self.ledger.attempt(db, resume["predecessor"])
            checkpoint = self.ledger._integrity(db)
            if checkpoint != resume["checkpoint"] or self._first_resume_binding(predecessor, self.ledger.head(db), checkpoint) != resume:
                raise PlanningError("stale/substituted recovery checkpoint")
            if self.ledger.clock() < predecessor["proofs"]["AUTHORIZED"]["expires_at"]:
                raise PlanningError("original authority still active; do not fork publication authority")
            for kind, identity in (("approval", approval.payload["approval_sha256"]), ("witness", approval.payload["witness_sha256"]),
                    ("jwt-jti", approval.payload["jti"]), ("authorization", approval.sha256), ("first-resume-parent", resume["predecessor"])):
                self.ledger.consume(db, kind, identity, attempt)
            value = {"schema_version": 3, "scope": "v3-backend-isolated-attempt", "publishable": False,
                "attempt_id": attempt, "state": "AUTHORIZED", "immutable": immutable, "base_generation": predecessor["base_generation"],
                "proofs": {"VERIFIED": {"evidence_sha256": evidence.sha256},
                    "COMPOSED": {"result_stable_sha256": result.sha256, "preflight_sha256": result.receipt},
                    "TESTED": {"evidence_sha256": evidence.sha256}, "AWAITING_APPROVAL": {"gate": "exact-protected-approval"},
                    "AUTHORIZED": {"authorization_sha256": approval.sha256, "expires_at": approval.expiry},
                    "REAUTHORIZED": {"observation_sha256": observation.sha256, "resume": resume}}, "failure": None}
            from ro_repo import validate_schema
            validate_schema(value, "backend-attempt-v3")
            db.execute("INSERT INTO attempts(id,body) VALUES(?,?)", (attempt, canonical(value).decode()))
            return value
        def guard():
            self._fresh(min(evidence.expiry, approval.expiry, observation.payload["expires_at"]))
            result.check()
        return self.ledger.execute("reauthorize-first", attempt, change, guard=guard)[0]

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
