"""Offline V3 dwell/fast-track decision helper.

Input publications and approvals are UNTRUSTED metadata until independently
verified by the production signing/promotion workflow. No publishing authority.
"""
import datetime as dt
import re

from v3_promotion_planner import PlanningError, plan

SHA = re.compile(r"^[0-9a-f]{64}$")
RUN = re.compile(r"^[1-9][0-9]*$")

def _time(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PlanningError("timestamps must be canonical UTC Z")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PlanningError("invalid UTC timestamp") from exc
    if parsed.utcoffset() != dt.timedelta(0):
        raise PlanningError("non-UTC timestamp")
    return parsed

def _identity(candidate):
    """Stable identity across newer snapshots of the same signed artifact set."""
    if not isinstance(candidate, dict) or not SHA.fullmatch(candidate.get("candidate_sha256", "")):
        raise PlanningError("invalid candidate digest")
    if not isinstance(candidate.get("promotion_group"), str) or not candidate["promotion_group"]:
        raise PlanningError("missing promotion group")
    return (candidate["promotion_group"], candidate["candidate_sha256"])

def first_seen(candidate, history, now):
    """Find oldest *claimed* beta publication for exact candidate identity.

    Each history entry is an externally verified record's metadata envelope:
    publication_run, published_at, promotion_group, candidate_sha256.
    A producer must independently prove every record's signature, snapshot
    membership, timestamp and archival immutability before using this result.
    """
    group, digest = _identity(candidate)
    moment = _time(now)
    if not isinstance(history, list) or not history:
        raise PlanningError("missing beta history")
    runs = set()
    matching = []
    for row in history:
        if not isinstance(row, dict) or set(row) != {"publication_run", "published_at", "promotion_group", "candidate_sha256"}:
            raise PlanningError("malformed beta history entry")
        run = row["publication_run"]
        if not isinstance(run, str) or not RUN.fullmatch(run) or run in runs:
            raise PlanningError("duplicate or invalid publication run")
        runs.add(run)
        if not isinstance(row["promotion_group"], str) or not row["promotion_group"] or not isinstance(row["candidate_sha256"], str) or not SHA.fullmatch(row["candidate_sha256"]):
            raise PlanningError("invalid publication identity")
        t = _time(row["published_at"])
        if t > moment:
            raise PlanningError("future-dated beta history")
        if row["promotion_group"] == group and row["candidate_sha256"] == digest:
            matching.append((t, run))
    if not matching:
        raise PlanningError("candidate has no beta publication evidence")
    t, run = min(matching)
    return {"first_published_at": t.isoformat().replace("+00:00", "Z"), "first_publication_run": run}

def evaluate(candidate, history, risk_class, mode, now, *, reason=None):
    """Return policy assessment; NEVER grant approval or permission to publish."""
    group, digest = _identity(candidate)
    if risk_class not in {"normal-app", "critical-desktop", "critical-system"}:
        raise PlanningError("unsupported risk class")
    if mode not in {"normal", "fast-track"}:
        raise PlanningError("unsupported promotion mode")
    if reason is not None and not isinstance(reason, str):
        raise PlanningError("invalid reason")
    if mode == "fast-track" and (not reason or not reason.strip()):
        raise PlanningError("fast-track requires a non-empty reason")
    if mode == "normal" and reason is not None:
        raise PlanningError("normal promotion cannot request an override reason")
    first = first_seen(candidate, history, now)
    start, current = _time(first["first_published_at"]), _time(now)
    required = 14 if risk_class == "critical-system" else 7
    age = (current - start).total_seconds()
    dwell_met = age >= required * 86400
    return {
        "scope": "offline-v3-untrusted-policy-assessment",
        "promotion_group": group,
        "candidate_sha256": digest,
        "risk_class": risk_class,
        "mode": mode,
        "reason": reason.strip() if mode == "fast-track" else None,
        "first_published_at": first["first_published_at"],
        "first_publication_run": first["first_publication_run"],
        "minimum_beta_days": required,
        "earliest_normal_promotion": (start + dt.timedelta(days=required)).isoformat().replace("+00:00", "Z"),
        "dwell_met": dwell_met,
        "dwell_exception_requested": mode == "fast-track" and not dwell_met,
        "ready_for_review": dwell_met or mode == "fast-track",
        "approval_granted": False,
        "test_evidence_verified": False,
        "signature_verified": False,
        "publishable": False,
    }
