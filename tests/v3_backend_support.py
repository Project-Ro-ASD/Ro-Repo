"""Disposable synthetic identity fixtures; never real application acceptance."""
import copy
import datetime as dt
import pathlib
import shutil
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "tools"))
from v3_backend_trust import TestSigner, test_workspace, canonical, digest, encode, verify_oidc, verify_envelope
from v3_backend_evidence import bindings, verify_evidence, authorization_request, verify_protected
from v3_backend_ledger import Ledger, SQLiteAdapter
from v3_publication_backend import Backend
from v3_immutable_view import IsolatedStore, verify_attested_result, verify_remote, DirectoryReader
from v3_integration import proposal, tree_inventory
from v3_policy_profile import sha, BASE, DESKTOP
from v3_promotion_planner import plan
from test_v3_integration import REGISTRY
from test_v3_promotion_planner import assist, dolphin, snapshot

NOW = int(dt.datetime(2026, 10, 11, 12, tzinfo=dt.timezone.utc).timestamp())


class Keys:
    def __init__(self):
        self.root = test_workspace()
        self.signers = {role: TestSigner(self.root, role) for role in ("oidc", "evidence", "approval", "witness", "publication", "audit")}
        signer = self.signers["oidc"]
        output = subprocess.run(["openssl", "rsa", "-in", str(signer.private), "-noout", "-modulus"], check=True, capture_output=True, text=True).stdout.strip()
        modulus = bytes.fromhex(output.split("=", 1)[1])
        self.jwks = canonical({"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test-key", "n": encode(modulus), "e": encode(b"\x01\x00\x01")}]})

    def close(self):
        shutil.rmtree(self.root)

    def attestation(self, role, expected, now=NOW, signer_role="evidence", duration=500):
        signer = self.signers[signer_role]
        raw = signer.envelope(role, {**expected, "issued_at": now, "expires_at": now + duration})
        return verify_envelope(raw, role=role, public_key=signer.public, key_sha256=signer.key_sha256, expected=expected, now=now)

    def oidc(self, attempt="attempt-1", changes=None, header=None, signer=None):
        pins = {"aud": "ro-repo-v3", "sub": "repo:Project-Ro-ASD/Ro-Repo:environment:v3-stable", "repository": "Project-Ro-ASD/Ro-Repo",
                "repository_id": "1159460821", "repository_owner_id": "248876122", "ref": "refs/heads/main", "sha": "a" * 40,
                "workflow_ref": "Project-Ro-ASD/Ro-Repo/.github/workflows/v3.yml@refs/heads/main", "workflow_sha": "a" * 40,
                "job_workflow_ref": "Project-Ro-ASD/Ro-Repo/.github/workflows/v3-signer.yml@" + "a" * 40,
                "job_workflow_sha": "a" * 40, "environment": "v3-stable", "event_name": "workflow_dispatch", "runner_environment": "github-hosted",
                "run_id": "1001", "run_attempt": "1", "actor_id": "123"}
        claims = {**pins, "iss": "https://token.actions.githubusercontent.com", "iat": NOW, "nbf": NOW, "exp": NOW + 300, "jti": "jti-" + attempt}
        claims.update(changes or {})
        head = encode(canonical(header or {"alg": "RS256", "kid": "test-key", "typ": "JWT"}))
        body = encode(canonical(claims))
        raw = head + "." + body + "." + encode((signer or self.signers["oidc"]).sign((head + "." + body).encode()))
        return raw, pins

    def workload(self, attempt="attempt-1"):
        raw, pins = self.oidc(attempt)
        return verify_oidc(raw, self.jwks, jwks_sha256=digest(self.jwks), pins=pins, now=NOW, fetched_at=NOW)


class Fixture:
    def __init__(self, keys, *, attempt="attempt-1", version="0.2.5", previous=None, previous_digest=None, retained=False, result_source=None, mode="normal", operation="promote"):
        self.keys, self.attempt, self.now, self.operation = keys, attempt, NOW, operation
        self.root = test_workspace()
        self.source = self.root / "repo-f44-20261011-099"
        self.source.mkdir()
        if result_source:
            shutil.copytree(result_source, self.source, dirs_exist_ok=True)
        else:
            (self.source / "test-payload").write_text("SYNTHETIC; not actual RPMs; " + version)
        self.registry = copy.deepcopy(REGISTRY)
        self.plan = plan(snapshot("repo-f44-20261011-001", assist(version) + dolphin()), previous, self.registry, "ro-assist")
        arches = sorted({p["architecture"] for p in self.plan["resulting_stable_packages"]} - {"src"})
        required = BASE | (DESKTOP if retained else set())
        from test_v3_group_validation import mkclaim
        small = {**self.plan, "selected_group_packages": [{"architecture": a} for a in arches]}
        self.claim = mkclaim(small, required)
        self.claim["candidate_sha256"] = self.plan["candidate_sha256"]
        self.claim["stable_base_snapshot_id"] = self.plan["stable_base_snapshot_id"]
        self.claim["beta_snapshot_id"] = self.plan["candidate_snapshot_id"]
        for check in self.claim["checks"]:
            check["candidate_sha256"] = self.plan["candidate_sha256"]
        history = [{"publication_run": "101", "published_at": "2026-10-01T12:00:00Z", "promotion_group": "ro-assist", "candidate_sha256": self.plan["candidate_sha256"]}]
        self.proposal = proposal(self.plan, self.registry, history, [{"release_id": 123, "source_commit": "a" * 40, "source_repository": "Project-Ro-ASD/test-only"}],
                                 now="2026-10-11T12:00:00Z", mode=mode, reason="test security update" if mode == "fast-track" else None,
                                 previous_sha256=previous_digest, result_sha256=sha(tree_inventory(self.source)), evidence={"group-validation-claim": sha(self.claim)})
        common = bindings(self.proposal)
        self.expectations = {
            "source": {**common, "candidate_identity": self.proposal["candidate_identity"], "producer_repository": "Project-Ro-ASD/test-only", "producer_commits": ["a" * 40], "signer_workflow": self.proposal["candidate_identity"]["policy"]["trusted_signer_workflow"]},
            "beta-history": {**common, "first_seen": self.proposal["first_seen"]},
            "tests": {**common, "claim_sha256": sha(self.claim), "required_tests": sorted(required), "architectures": arches,
                      "groups": ["ro-assist", "ro-kde-dolphin"] if retained else ["ro-assist"], "result": "PASS",
                      "application_acceptance": "PASS", "logs": {"test-only": "b" * 64}, "execution": {a: "native" for a in arches}}}
        self.attestations = {r: keys.attestation(r, expected) for r, expected in self.expectations.items()}
        self.evidence = verify_evidence(self.proposal, self.plan, self.registry, self.claim, self.attestations, now=NOW)
        self.workload = keys.workload(attempt)
        self.preflight = keys.attestation("result-preflight", {"proposal_sha256": self.proposal["proposal_sha256"], "result_stable_sha256": self.proposal["result_stable_sha256"], "stable_set_sha256": self.proposal["stable_set_sha256"], "plan_sha256": sha(self.plan), "rpm_signatures": "PASS", "metadata_signatures": "PASS", "srpm_closure": "PASS"})
        self.result = verify_attested_result(self.source, self.proposal, self.plan, self.preflight, now=NOW)
        self.ledger = Ledger(SQLiteAdapter(self.root), keys.signers["audit"], audit_key=keys.signers["audit"].public,
                             audit_key_sha256=keys.signers["audit"].key_sha256, clock=lambda: self.now)
        self.backend = Backend(self.ledger)
        self.approval_args = self.approval_inputs()
        self.approval = verify_protected(self.proposal, attempt, self.evidence, self.workload, **self.approval_args)

    def approval_inputs(self, operation=None):
        operation = operation or self.operation
        target = self.proposal["result_stable_sha256"] if operation == "recover" else None
        expected = authorization_request(self.proposal, self.attempt, self.evidence, operation=operation, target=target)
        signer = self.keys.signers["approval"]
        raw = signer.envelope("human-approval", {**expected, "reviewer_id": "456", "issued_at": NOW, "expires_at": NOW + 300})
        approved = verify_envelope(raw, role="human-approval", public_key=signer.public, key_sha256=signer.key_sha256,
                                   expected={**expected, "reviewer_id": "456"}, now=NOW)
        witness = self.keys.signers["witness"]
        witness_raw = witness.envelope("protected-environment-witness", {**expected, "approval_sha256": approved.sha256,
                     "workload_token_sha256": self.workload.token_sha256, "environment": self.workload.claims["environment"],
                     "environment_config_sha256": "f" * 64, "run_id": self.workload.claims["run_id"], "run_attempt": self.workload.claims["run_attempt"],
                     "reviewer_id": "456", "decision": "approved", "issued_at": NOW, "expires_at": NOW + 300})
        return dict(approval_raw=raw, witness_raw=witness_raw, approval_key=signer.public, approval_key_sha256=signer.key_sha256,
                    witness_key=witness.public, witness_key_sha256=witness.key_sha256, allowed_reviewer_ids={"456"},
                    environment_config_sha256="f" * 64, now=NOW, operation=operation, target=target)

    def advance(self, to="AWAITING_APPROVAL"):
        from v3_publication_backend import STATES
        self.backend.create(self.proposal, self.plan, self.registry, self.attempt, operation=self.operation)
        if to == "PROPOSED":
            return
        for state, call in (("VERIFIED", lambda: self.backend.verified(self.attempt, self.evidence)),
                            ("COMPOSED", lambda: self.backend.composed(self.attempt, self.result)),
                            ("TESTED", lambda: self.backend.tested(self.attempt, self.evidence)),
                            ("AWAITING_APPROVAL", lambda: self.backend.awaiting_approval(self.attempt)),
                            ("AUTHORIZED", lambda: self.backend.authorized(self.attempt, self.approval))):
            call()
            if to == state:
                return

    def stage(self):
        self.view = IsolatedStore(self.root).stage(self.result, self.approval, self.keys.signers["publication"],
                    origin="https://test.invalid", audit_key_sha256=self.keys.signers["audit"].key_sha256, now=NOW)
        self.backend.signed(self.attempt, self.view)
        self.backend.staged(self.attempt, self.view)
        self.deployment = self.keys.attestation("deployment", {"result_stable_sha256": self.result.sha256,
                              "publication_sha256": self.view.envelope_sha256, "git_commit": "a" * 40, "deployment_id": "test-deployment"})
        self.remote = verify_remote(self.view, DirectoryReader(self.view), self.deployment, now=NOW)
        self.backend.remotely_verified(self.attempt, self.remote)

    def complete(self):
        self.advance("AUTHORIZED")
        self.stage()
        self.backend.publish(self.attempt, self.approval)
        self.remote = self.verify_post()
        self.backend.post_verified(self.attempt, self.remote)

    def verify_post(self):
        head = self.ledger.inspect()["head"]
        payload = {"result_stable_sha256": self.view.sha256, "publication_sha256": self.view.envelope_sha256,
                   "authorization_sha256": self.approval.sha256,
                   "previous_stable_sha256": self.proposal["previous_stable_sha256"],
                   "generation": head["generation"], "baseurls": self.view.descriptor["baseurls"], "publishable": False,
                   "staged_git_commit": "a"*40, "issued_at": NOW, "expires_at": NOW+300}
        signer = self.keys.signers["publication"]
        (self.view.path / "stable-advertisement.json").write_bytes(signer.envelope("stable-advertisement", payload))
        return verify_remote(self.view, DirectoryReader(self.view), self.deployment, now=NOW, post_ledger=self.ledger,
                             advertisement_key=signer.public, advertisement_key_sha256=signer.key_sha256)

    def close(self):
        shutil.rmtree(self.root)
