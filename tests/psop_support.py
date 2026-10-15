"""Synthetic gateway unit fixtures, not RPM/preflight/E2E acceptance."""
import copy
import shutil
import types
import uuid

from psop_context import Context, Evidence, SEAL, frozen_tree
from psop_result import UnsignedResult
from psop_signing import SignedResult
from psop_authorization import approval_request, verify_approval
from psop_ledger import Ledger
from psop_storage_gateway import Gateway
from v3_policy_profile import sha
from v3_backend_trust import canonical

NOW = 1792065600


class Fixture:
    def __init__(self):
        self.context = Context.create()
        self.now = NOW
        self.ledger = Ledger(self.context, clock=lambda: self.now)
        self.gateway = Gateway(self.ledger, self.context)
        self.policy = {"version": "test-policy-1"}
        self.identity = {"issuer": self.context.descriptor["origin"] + "/issuer",
            "repository": self.context.descriptor["repository"], "actor": "42", "run_id": "101", "run_attempt": "1"}

    def job(self, *, attempt=None, nonce=None, writer="psop-stable", previous=None, expiry=300):
        attempt = attempt or "attempt-" + uuid.uuid4().hex
        nonce = nonce or "nonce-" + uuid.uuid4().hex
        root = self.context.path("unit-result-" + uuid.uuid4().hex)
        root.mkdir()
        (root / "payload").write_text("synthetic gateway test " + attempt)
        inventory = frozen_tree(root)
        unsigned = UnsignedResult({"context": self.context.pin, "inventory": inventory}, SEAL)
        unsigned.path, unsigned.prepared = root, types.SimpleNamespace(check=lambda: None)
        review = Evidence({"schema_version": 1, "domain": "psop-review-test-1", "context": self.context.pin,
            "profile": "psop-pages-stable", "source_pins": {"main_sha": "a" * 40, "pages_sha": "b" * 40},
            "inputs_sha256": "1" * 64, "history_sha256": "2" * 64, "genesis_sha256": "3" * 64,
            "previous_stable_sha256": previous, "policy_version": self.policy["version"],
            "policy_sha256": sha(self.policy), "plan_sha256": "4" * 64, "evidence_sha256": "5" * 64,
            "result_sha256": sha(inventory), "publishable": False}, SEAL)
        body = approval_request(review, self.identity, attempt=attempt, nonce=nonce, writer=writer,
            expected_git=self.gateway._store.head(), metadata_key={"sha256": "6" * 64, "fingerprint": "A" * 40})
        raw = self.context.envelope("approval", body, now=self.now, seconds=expiry)
        approval = verify_approval(raw, self.identity, review, self.policy, self.now, context=self.context)
        signed = SignedResult({"context": self.context.pin, "result_sha256": sha(inventory),
            "approval_sha256": approval.sha256, "inventory": inventory, "metadata_key_sha256": "6" * 64,
            "publishable": False, "production_activation": "BLOCKED"}, SEAL)
        signed.path, signed.unsigned, signed.approval = root, unsigned, approval
        prepared = self.gateway.prepare(signed, approval)
        return types.SimpleNamespace(attempt=attempt, nonce=nonce, signed=signed, approval=approval,
                                     prepared=prepared, review=review, raw=raw, body=body)

    def reopen(self):
        self.context = Context(self.context.root, self.context.pin)
        self.ledger = Ledger(self.context, clock=lambda: self.now)
        self.gateway = Gateway(self.ledger, self.context)

    def close(self):
        shutil.rmtree(self.context.root)
