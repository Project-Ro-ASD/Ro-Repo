"""Legacy compatibility preserves signed bytes; observations never grant dwell."""
from psop_context import Evidence, SEAL, frozen_tree, require_evidence
from v3_signed_beta_history import signed_archive_bundle
from v3_promotion_policy import _time
from v3_policy_profile import sha
from v3_promotion_planner import PlanningError


class VerifiedArchive(Evidence):
    def check(self):
        super().check()
        if (frozen_tree(self.publications), frozen_tree(self.snapshots)) != self.inventory:
            raise PlanningError("signed archive bytes changed")


class HistoryAssessment(Evidence):
    def check(self):
        super().check()
        self.archive.check()


def read_archive(publications, snapshots, registry, group, key, key_sha256, now, *, context):
    before = (frozen_tree(publications), frozen_tree(snapshots))
    value = signed_archive_bundle(publications, snapshots, registry, group, key, key_sha256,
                                  now, legacy_compatibility=True)
    if before != (frozen_tree(publications), frozen_tree(snapshots)):
        raise PlanningError("history changed during verification")
    result = VerifiedArchive({"context": context.pin, "signed_records": value["signed_publications"], "untrusted_first_seen": value["legacy_observations"],
            "archive_sha256": sha(before), "registry_sha256": sha(registry), "group": group,
            "production_dwell": "BLOCKED", "unproven_intervals": True, "publishable": False}, SEAL)
    result.publications, result.snapshots, result.inventory = publications, snapshots, before
    return result


def availability_request(archive, candidate, first_seen):
    archive = archive.data if isinstance(archive, VerifiedArchive) else archive
    return {"archive_sha256": archive["archive_sha256"], "candidate_sha256": candidate,
            "promotion_group": archive["group"], "first_seen": first_seen,
            "covered_publication_runs": sorted(p["publication_run"] for p in archive["signed_records"]),
            "coverage_complete": True, "scope": "synthetic-test-availability"}


def assess_history(signed_archive, api_observations, availability_evidence, *, context, candidate, now):
    archive_capability = signed_archive
    signed_archive = require_evidence(signed_archive, context)
    def result(body):
        value = HistoryAssessment(body, SEAL)
        value.archive = archive_capability
        return value
    # API records are retained as observations, never used as authentication.
    base = {"context": context.pin, "archive": signed_archive, "observed_api": api_observations,
            "candidate_sha256": candidate,
            "production_dwell": "BLOCKED", "status": "BLOCKED", "first_seen": None,
            "unproven_intervals": True, "publishable": False}
    if availability_evidence is None:
        return result(base)
    from v3_backend_trust import strict_json
    payload = strict_json(availability_evidence).get("payload", {})
    first = payload.get("first_seen")
    matching = [p for p in signed_archive["signed_records"] if p["candidate_sha256"] == candidate]
    match = next((p for p in matching if p["publication_run"] == (first or {}).get("publication_run")), None)
    if (not isinstance(first, dict) or set(first) != {"publication_run", "published_at"} or match is None
            or _time(first["published_at"]) < _time(match["published_at"]) or _time(first["published_at"]) > _time(now)):
        raise PlanningError("availability is not bound to an exact signed candidate publication")
    proof = context.verify(availability_evidence, "availability", availability_request(signed_archive, candidate, first),
                           now=int(_time(now).timestamp()))
    return result({**base, "status": "PASS_TEST_ONLY", "first_seen": first, "unproven_intervals": False,
                   "availability_sha256": proof.sha256})
