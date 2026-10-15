"""PSOP full selected+retained plan; V3 policy/composer/preflight remain intact."""
import uuid

from psop_context import Evidence, SEAL, require_evidence
from v3_promotion_planner import plan, PlanningError
from v3_policy_profile import sha, require_complete
from v3_promotion_policy import evaluate
from v3_group_validation import validate_claim
from v3_backend_trust import digest
from v3_stable_composer import compose
from v3_rpm_preflight import verify


class PreparedPlan(Evidence):
    def check(self):
        super().check()
        self.inputs.check()
        from psop_context import frozen_tree
        if frozen_tree(self.composition) != self.inventory:
            raise PlanningError("composed bytes changed")


def prepare(inputs, group, registry, evidence, *, history, genesis, context, now):
    i, h = require_evidence(inputs, context), require_evidence(history, context)
    if (i["group"] != group or i["registry_sha256"] != sha(registry)
            or i["archive_sha256"] != h["archive"]["archive_sha256"] or h["status"] != "PASS_TEST_ONLY"):
        raise PlanningError("verified history/registry/group required; publication BLOCKED")
    if i["previous_stable_sha256"] is None:
        g = require_evidence(genesis, context)
        if g.get("inputs_sha256") != inputs.sha256 or g.get("history_sha256") != history.sha256:
            raise PlanningError("explicit bound genesis required")
    elif genesis is not None:
        raise PlanningError("genesis cannot replace an existing stable base")
    p = plan(i["manifests"]["beta"], i["manifests"].get("stable"), registry, group)
    if h["candidate_sha256"] != p["candidate_sha256"]:
        raise PlanningError("history availability belongs to a different candidate")
    policy = require_complete(p, registry)
    first = h["first_seen"]
    dwell = evaluate(p, [{**first, "promotion_group": group, "candidate_sha256": p["candidate_sha256"]}],
                     policy["risk_class"], "normal", now)
    if not dwell["dwell_met"]:
        raise PlanningError("canonical 7/14 day dwell not met")
    claim = evidence["claim"]
    assessment = validate_claim(p, registry, claim)
    if claim["tested_at"] > now:
        raise PlanningError("future test claim")
    from v3_promotion_policy import _time
    context.verify(evidence["attestation"], "tests", {"claim_sha256": sha(claim), "plan_sha256": sha(p),
        "scope": "synthetic-model-only", "required_tests": assessment["required_tests"],
        "architectures": assessment["architectures"], "production_test_authority": False}, now=int(_time(now).timestamp()))
    output = context.path("composition-" + uuid.uuid4().hex)
    compose(inputs.paths["beta"], inputs.paths.get("stable"), registry, group, output)
    preflight = verify(output, inputs.paths["rpm_key"], i["roots"]["rpm"]["sha256"])
    from psop_context import frozen_tree
    value = PreparedPlan({"context": context.pin, "inputs_sha256": inputs.sha256,
        "history_sha256": history.sha256, "genesis_sha256": None if genesis is None else genesis.sha256,
        "policy": policy, "plan": p, "dwell": dwell, "preflight": preflight,
        "evidence_sha256": sha({"claim": claim, "attestation_sha256": digest(evidence["attestation"])}),
        "production_test_authority": False, "publishable": False}, SEAL)
    value.composition, value.inputs, value.inventory = output, inputs, frozen_tree(output)
    return value
