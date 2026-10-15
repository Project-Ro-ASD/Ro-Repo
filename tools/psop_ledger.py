"""PSOP state/domain adapter over the existing signed V3 transaction engine."""
from psop_context import require_evidence
from v3_backend_ledger import Ledger as V3Ledger, SQLiteAdapter
from v3_backend_trust import canonical, strict_json
from v3_promotion_planner import PlanningError


class Ledger(V3Ledger):
    def __init__(self, context, *, clock):
        context.check()
        self.context = context
        if (context.root / "storage.git").exists() and not (context.root / "psop-ledger.sqlite").is_file():
            raise PlanningError("missing durable ledger; refusing realm reinitialization")
        signer = context.signer("audit")
        super().__init__(SQLiteAdapter(context.root, "psop-ledger.sqlite"), signer,
                         audit_key=signer.public, audit_key_sha256=signer.key_sha256, clock=clock)
        def bind(db):
            h = self.head(db)
            if "psop_context" in h and h["psop_context"] != context.pin:
                raise PlanningError("ledger belongs to a different realm/issuer")
            h["psop_context"] = context.pin
            db.execute("UPDATE head SET body=? WHERE id=1", (canonical(h).decode(),))
        self.execute("psop-bind-context", None, bind)

    @staticmethod
    def attempt(db, attempt):
        row = db.execute("SELECT body FROM attempts WHERE id=?", (attempt,)).fetchone()
        if row is None:
            raise PlanningError("unknown PSOP attempt")
        value = strict_json(row[0])
        if (set(value) != {"domain", "attempt_id", "state", "proofs", "prepared", "approval", "created_at"}
                or value["domain"] != "psop-attempt-test-1"):
            raise PlanningError("PSOP ledger domain substitution")
        return value

    @staticmethod
    def put_attempt(db, value):
        db.execute("UPDATE attempts SET body=? WHERE id=?", (canonical(value).decode(), value["attempt_id"]))

    def enqueue(self, prepared, approval, *, inject=None):
        p = require_evidence(prepared, self.context)
        a = require_evidence(approval, self.context, "approved")
        if p["approval_sha256"] != approval.sha256 or p["context"] != self.context.pin:
            raise PlanningError("prepared approval/context mismatch")
        if (p["result_sha256"] != a["payload"]["review"]["result_sha256"]
                or p["expected_git"] != a["payload"]["expected_git"]):
            raise PlanningError("approval result/target binding mismatch")
        attempt = a["payload"]["attempt"]
        def change(db):
            for (raw,) in db.execute("SELECT body FROM attempts").fetchall():
                prior = strict_json(raw)
                if prior["proofs"]["OUTBOX"]["status"] not in {"COMPLETE", "FAILED"}:
                    raise PlanningError("pending/UNKNOWN intent blocks the whole writer realm")
            if self.clock() >= a["expiry"]:
                raise PlanningError("expired approval")
            if self.head(db)["digest"] != a["payload"]["review"]["previous_stable_sha256"]:
                raise PlanningError("stable base changed")
            self.consume(db, "psop-nonce", a["payload"]["nonce"], attempt)
            value = {"domain": "psop-attempt-test-1", "attempt_id": attempt, "state": "STAGED",
                "prepared": p, "approval": a, "created_at": self.clock(), "proofs": {
                    "AUTHORIZED": {"authorization_sha256": approval.sha256, "expires_at": a["expiry"]},
                    "SIGNED": {"publication_sha256": p["publication_sha256"]},
                    "OUTBOX": {"immutable": {"result_sha256": p["result_sha256"],
                        "publication_sha256": p["publication_sha256"], "authorization_sha256": approval.sha256,
                        "expected_git": p["expected_git"]}, "fence": 0, "owner": None,
                        "lease_until": 0, "status": "PENDING", "receipts": {}}}}
            db.execute("INSERT INTO attempts(id,body) VALUES(?,?)", (attempt, canonical(value).decode()))
            return value
        return self.execute("psop-atomic-consume-enqueue", attempt, change, inject=inject,
                            guard=lambda: self._fresh(a["expiry"]))[0]

    def _fresh(self, expiry):
        self.context.check()
        if self.clock() >= expiry:
            raise PlanningError("expired PSOP authorization")

    def adopt_test_base(self, inputs, history, proof_raw):
        """Explicit authenticated import of a synthetic prior Stable, not cutover."""
        i, h = require_evidence(inputs, self.context), require_evidence(history, self.context)
        if i["previous_stable_sha256"] is None or h["status"] != "PASS_TEST_ONLY":
            raise PlanningError("verified nonempty test base/history required")
        proof = self.context.verify(proof_raw, "genesis", {"scope": "synthetic-test-base-import",
            "inputs_sha256": inputs.sha256, "history_sha256": history.sha256,
            "previous_stable_sha256": i["previous_stable_sha256"]}, now=self.clock())
        def change(db):
            head = self.head(db)
            if head["generation"] or head["digest"] is not None or db.execute("SELECT count(*) FROM attempts").fetchone()[0]:
                raise PlanningError("existing ledger cannot be initialized again")
            self.consume(db, "psop-base-import", proof.sha256, "test-base")
            head.update(digest=i["previous_stable_sha256"], generation=1)
            db.execute("UPDATE head SET body=? WHERE id=1", (canonical(head).decode(),))
        self.execute("psop-explicit-test-base-import", None, change)
