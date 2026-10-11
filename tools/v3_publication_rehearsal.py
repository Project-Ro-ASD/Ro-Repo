"""Disposable local-only V3 staging/recovery state machine, never Pages.

Immutable snapshot trees + a locked, atomic state file provide local CAS and
idempotence. This deliberately has no Git, signing, HTTP write, deployment or
production backend. Its local atomicity does not establish Pages/CDN atomicity.
"""
import contextlib
import fcntl
import json
import os
import pathlib
import shutil
import tempfile

from v3_authorization import verify_signed, ID
from v3_integration import tree_inventory, verify_proposal
from v3_policy_profile import canonical, sha
from v3_promotion_planner import PlanningError
from v3_promotion_policy import _time

SCOPE = "v3-disposable-publication-rehearsal"


def _atomic(path, value):
    if path.is_symlink():
        raise PlanningError("symlinked state file")
    fd, filename = tempfile.mkstemp(prefix=".v3-state-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(filename, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        pathlib.Path(filename).unlink(missing_ok=True)


def initialize(root):
    root = pathlib.Path(root)
    if root.exists() or root.is_symlink():
        raise PlanningError("rehearsal requires a new disposable directory")
    root.mkdir(parents=True)
    (root / "snapshots").mkdir()
    (root / "lock").touch()
    _atomic(root / "state.json", {"scope": SCOPE, "current": None, "attempts": {},
                                  "used_approvals": [], "verified_snapshots": [], "audit": []})


@contextlib.contextmanager
def _locked(root):
    root = pathlib.Path(root)
    if root.is_symlink() or not root.is_dir():
        raise PlanningError("missing disposable rehearsal")
    for name in ("state.json", "lock", "snapshots"):
        if (root / name).is_symlink() or not (root / name).exists():
            raise PlanningError("unsafe rehearsal state")
    with (root / "lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads((root / "state.json").read_bytes())
        if state.get("scope") != SCOPE:
            raise PlanningError("production paths are forbidden")
        yield root, state


def _event(state, attempt, phase, **details):
    prior = sha(state["audit"][-1]) if state["audit"] else None
    state["audit"].append({"attempt_id": attempt, "phase": phase, "previous_event_sha256": prior,
                           **details})


def begin(root, value, result_tree, approval_directory, attempt, *, key, key_sha256, now,
          operation="promote"):
    verify_proposal(value)
    if not isinstance(attempt, str) or not ID.fullmatch(attempt):
        raise PlanningError("invalid attempt")
    with _locked(root) as (root, state):
        target = value["result_stable_sha256"]
        known = target if target in state["verified_snapshots"] else None
        try:
            approval = verify_signed(value, approval_directory, attempt, key, key_sha256, now=now,
                                     operation=operation, target_verified_sha256=known if operation == "recover" else None)
        except PlanningError:
            _event(state, attempt, "authorization-rejected")
            _atomic(root / "state.json", state)
            raise
        prior = state["attempts"].get(attempt)
        binding = {"proposal_sha256": value["proposal_sha256"], "approval_sha256": approval["approval_sha256"]}
        if prior is not None:
            if any(prior[k] != v for k, v in binding.items()):
                raise PlanningError("conflicting duplicate publication attempt")
            if prior["phase"] in {"staged", "completed"}:
                return dict(prior)
            raise PlanningError("interrupted or failed attempt requires fresh authorization")
        if approval["approval_sha256"] in state["used_approvals"]:
            raise PlanningError("replayed approval")
        record = {**binding, "result_sha256": target, "base_sha256": value["previous_stable_sha256"],
                  "expires_at": approval["expires_at"], "phase": "attempted", "operation": operation}
        state["attempts"][attempt] = record
        state["used_approvals"].append(approval["approval_sha256"])
        _event(state, attempt, "attempted", operation=operation)
        _atomic(root / "state.json", state)
        try:
            if state["current"] != record["base_sha256"]:
                raise PlanningError("stale stable base or concurrent publication")
            inventory = tree_inventory(result_tree)
            if sha(inventory) != target:
                raise PlanningError("tampered or incomplete result tree")
            dest = root / "snapshots" / target
            if dest.exists():
                if tree_inventory(dest) != inventory:
                    raise PlanningError("immutable historical snapshot was altered")
            else:
                with tempfile.TemporaryDirectory(prefix=".v3-stage-", dir=root) as temporary:
                    stage = pathlib.Path(temporary) / "snapshot"
                    shutil.copytree(result_tree, stage, symlinks=True)
                    if tree_inventory(stage) != inventory:
                        raise PlanningError("snapshot changed during staging")
                    for path in stage.rglob("*"):
                        if path.is_file():
                            with path.open("rb") as stream:
                                os.fsync(stream.fileno())
                    stage.rename(dest)
            record["phase"] = "staged"
            _event(state, attempt, "staged", result_sha256=target)
            _atomic(root / "state.json", state)
        except Exception as exc:
            record["phase"] = "failed"
            _event(state, attempt, "failed", reason=type(exc).__name__)
            _atomic(root / "state.json", state)
            raise
        return dict(record)


def finish(root, attempt, *, now):
    with _locked(root) as (root, state):
        record = state["attempts"].get(attempt)
        if record is None:
            raise PlanningError("unknown attempt")
        if record["phase"] == "completed":
            if sha(tree_inventory(root / "snapshots" / record["result_sha256"])) != record["result_sha256"]:
                raise PlanningError("completed historical snapshot was altered")
            return dict(record)
        try:
            if record["phase"] != "staged":
                raise PlanningError("interrupted/failed staging")
            if _time(now) >= _time(record["expires_at"]):
                raise PlanningError("approval expired before publication")
            if state["current"] != record["base_sha256"]:
                raise PlanningError("stale stable base or concurrent publication")
            if sha(tree_inventory(root / "snapshots" / record["result_sha256"])) != record["result_sha256"]:
                raise PlanningError("partial or tampered staged snapshot")
            # The whole view has been verified before the one atomic local
            # pointer update. State and completed receipt commit together.
            state["current"] = record["result_sha256"]
            if state["current"] not in state["verified_snapshots"]:
                state["verified_snapshots"].append(state["current"])
            record["phase"] = "completed"
            _event(state, attempt, "completed", complete_local_view_verified=True,
                   production_published=False)
            _atomic(root / "state.json", state)
            return dict(record)
        except Exception as exc:
            record["phase"] = "failed"
            _event(state, attempt, "failed", reason=type(exc).__name__)
            _atomic(root / "state.json", state)
            raise


def audit(root):
    with _locked(root) as (root, state):
        prior = None
        for entry in state["audit"]:
            if entry["previous_event_sha256"] != prior:
                raise PlanningError("audit chain modified")
            prior = sha(entry)
        for snapshot in state["verified_snapshots"]:
            if sha(tree_inventory(root / "snapshots" / snapshot)) != snapshot:
                raise PlanningError("verified historical snapshot modified")
        return {"scope": SCOPE, "current": state["current"], "attempts": state["attempts"],
                "audit_event_count": len(state["audit"]), "publishable": False}
