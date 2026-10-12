"""Explicit disposable PostgreSQL integration; never silently skipped."""
import argparse
import json
import multiprocessing
import pathlib
import sys
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from v3_backend_support import Keys, Fixture, NOW
from v3_backend_ledger import Ledger, PostgreSQLAdapter
from v3_publication_backend import Backend
from v3_immutable_view import verify_remote, DirectoryReader
from v3_promotion_planner import PlanningError
from v3_backend_evidence import verify_protected
from test_v3_promotion_planner import snapshot, assist


def capture(provider):
    """Fault-test backup of this disposable database only."""
    with provider.transaction() as db:
        return {name: db.execute("SELECT * FROM " + name).fetchall()
                for name in ("head", "attempts", "consumed", "views", "events")}


def restore(provider, saved):
    with provider.transaction() as db:
        for name, rows in saved.items():
            db.execute("DELETE FROM " + name)
            for row in rows:
                db.execute("INSERT INTO " + name + " VALUES(" + ",".join("?" for _ in row) + ")", row)


def reject(call):
    try:
        call()
    except PlanningError:
        return
    raise AssertionError("unsafe PostgreSQL operation unexpectedly accepted")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=55432)
    parser.add_argument("--dbname", default="ro_v3_test_backend")
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--password", default="")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = pathlib.Path(args.output)
    if output.exists():
        raise PlanningError("immutable provider evidence already exists")
    keys = Keys()
    fixtures = []
    try:
        fixtures = [Fixture(keys, attempt="postgres-runner-1"), Fixture(keys, attempt="postgres-runner-2", version="0.2.6")]
        provider = PostgreSQLAdapter(host="127.0.0.1", port=args.port, dbname=args.dbname, user=args.user, password=args.password)
        ledger = Ledger(provider, keys.signers["audit"], audit_key=keys.signers["audit"].public,
                        audit_key_sha256=keys.signers["audit"].key_sha256, clock=lambda: NOW)
        if ledger.inspect()["head"]["generation"] != 0:
            raise PlanningError("PostgreSQL integration requires a fresh disposable database")
        initial_backup = capture(provider)
        for fx in fixtures:
            fx.ledger, fx.backend = ledger, Backend(ledger)
            fx.advance("AUTHORIZED")
            fx.stage()
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        def writer(fixture):
            try:
                fixture.backend.publish(fixture.attempt, fixture.approval)
                queue.put(("published", fixture.attempt))
            except PlanningError:
                queue.put(("conflict", fixture.attempt))
        processes = [context.Process(target=writer, args=(fx,)) for fx in fixtures]
        for process in processes:
            process.start()
        for process in processes:
            process.join(45)
            if process.exitcode != 0:
                raise PlanningError("PostgreSQL writer process failed")
        results = [queue.get(timeout=5) for _ in processes]
        if sorted(r[0] for r in results) != ["conflict", "published"]:
            raise PlanningError("independent PostgreSQL CAS allowed multiple stable writers")
        winner = next(fx for fx in fixtures if ("published", fx.attempt) in results)
        post = winner.verify_post()
        winner.backend.post_verified(winner.attempt, post)
        status = ledger.inspect(winner.attempt)
        # Crash within a transaction cannot clear consumed approvals.
        before = status["checkpoint"]
        def die(point):
            import os
            if point == "after-audit":
                os._exit(17)
        process = context.Process(target=lambda: ledger.execute("crash-test", winner.attempt,
                     lambda db: db.execute("DELETE FROM consumed"), inject=die))
        process.start()
        process.join(30)
        if process.exitcode != 17 or ledger.inspect()["checkpoint"] != before:
            raise PlanningError("PostgreSQL interruption did not atomically preserve replay/audit")
        # Real provider checks, beyond the original happy-path/CAS evidence.
        version = "0.2.5" if winner is fixtures[0] else "0.2.6"
        fresh = Fixture(keys, attempt="postgres-negative", version="0.2.7",
                        previous=snapshot("repo-f44-20261011-099", assist(version)), previous_digest=winner.result.sha256)
        fixtures.append(fresh)
        fresh.ledger, fresh.backend = ledger, Backend(ledger)
        fresh.advance()
        unchanged = ledger.inspect(fresh.attempt)
        for point in ("after-authorization-consumption", "before-audit", "after-audit"):
            def crash(stage):
                if stage == point:
                    raise RuntimeError("crash " + point)
            try:
                fresh.backend.authorized(fresh.attempt, fresh.approval, inject=crash)
            except RuntimeError:
                pass
            else:
                raise AssertionError("PostgreSQL fault injection did not interrupt")
            if ledger.inspect(fresh.attempt) != unchanged:
                raise AssertionError("interrupted consumption/audit changed PostgreSQL authority")
        fresh.workload = winner.workload
        replay = verify_protected(fresh.proposal, fresh.attempt, fresh.evidence, fresh.workload, **fresh.approval_inputs())
        reject(lambda: fresh.backend.authorized(fresh.attempt, replay))
        if ledger.inspect(fresh.attempt) != unchanged:
            raise AssertionError("replay rejection changed PostgreSQL authority")
        with mock.patch.object(ledger.signer, "sign", side_effect=keys.signers["approval"].sign):
            reject(lambda: fresh.backend.authorized(fresh.attempt, fresh.approval))
        if ledger.inspect(fresh.attempt) != unchanged:
            raise AssertionError("invalid signer committed PostgreSQL authority")
        sign = ledger.signer.sign
        clock = {"now": NOW}
        def late_signature(data):
            raw = sign(data)
            clock["now"] = NOW + 300
            return raw
        with mock.patch.object(ledger, "clock", side_effect=lambda: clock["now"]), mock.patch.object(ledger.signer, "sign", side_effect=late_signature):
            reject(lambda: fresh.backend.authorized(fresh.attempt, fresh.approval))
        if ledger.inspect(fresh.attempt) != unchanged:
            raise AssertionError("expired transaction committed PostgreSQL authority")
        latest = capture(provider)
        checkpoint = ledger.inspect()["checkpoint"]
        for fault in ("corrupt-event", "delete-tail", "delete-events", "delete-head", "delete-replay"):
            with provider.transaction() as db:
                if fault == "corrupt-event":
                    db.execute("UPDATE events SET signature=? WHERE seq=1", ("AAAA",))
                elif fault == "delete-tail":
                    db.execute("DELETE FROM events WHERE seq=?", (checkpoint["seq"],))
                elif fault == "delete-events":
                    db.execute("DELETE FROM events")
                elif fault == "delete-head":
                    db.execute("DELETE FROM head")
                else:
                    db.execute("DELETE FROM consumed")
            reject(lambda: ledger.inspect())
            restore(provider, latest)
            ledger.inspect(checkpoint=checkpoint)
        reject(lambda: ledger.inspect(checkpoint={"seq": checkpoint["seq"], "sha256": "0" * 64}))
        restore(provider, initial_backup)
        ledger.inspect()  # Local signatures cannot detect a complete valid old backup.
        reject(lambda: ledger.inspect(checkpoint=checkpoint))
        restore(provider, latest)
        ledger.inspect(checkpoint=checkpoint)
        # Recovery and promotion must compete on the same generation CAS.
        recovery = Fixture(keys, attempt="postgres-recovery", version=version, result_source=winner.source,
                        previous=snapshot("repo-f44-20261011-099", assist(version)),
                        previous_digest=winner.result.sha256, operation="recover")
        promotion = Fixture(keys, attempt="postgres-promotion", version="0.2.8",
                        previous=snapshot("repo-f44-20261011-099", assist(version)), previous_digest=winner.result.sha256)
        fixtures.extend((recovery, promotion))
        for fx in (recovery, promotion):
            fx.ledger, fx.backend = ledger, Backend(ledger)
            fx.advance("AUTHORIZED")
            fx.stage()
        processes = [context.Process(target=writer, args=(fx,)) for fx in (recovery, promotion)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(45)
            if process.exitcode != 0:
                raise AssertionError("recovery/promotion PostgreSQL writer failed")
        mixed_results = [queue.get(timeout=5) for _ in processes]
        if sorted(r[0] for r in mixed_results) != ["conflict", "published"]:
            raise AssertionError("recovery/promotion did not share PostgreSQL CAS")
        mixed_winner = next(fx for fx in (recovery, promotion) if ("published", fx.attempt) in mixed_results)
        mixed_winner.backend.post_verified(mixed_winner.attempt, mixed_winner.verify_post())
        with provider.transaction() as db:
            version = db.execute("SHOW server_version").fetchone()[0]
            count = db.execute("SELECT COUNT(*) FROM consumed").fetchone()[0]
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({"scope": "v3-postgresql-isolated-acceptance", "publishable": False,
                 "server_version": version, "cas": "PASS", "independent_processes": "PASS", "process_death": "PASS",
                 "replay_consumptions": count, "audit_integrity": "PASS", "post_verification": "PASS",
                 "replay_rejection": "PASS", "invalid_signer_atomic_rollback": "PASS",
                 "expiry_atomic_rollback": "PASS", "corruption_and_truncation": "PASS",
                 "consumption_audit_crash_boundaries": "PASS", "concurrent_recovery_promotion": "PASS",
                 "checkpoint_substitution": "PASS", "valid_old_backup_with_external_checkpoint": "PASS",
                 "valid_old_backup_without_external_checkpoint": "UNDETECTABLE",
                 "external_ha_durability": "UNVERIFIED", "production_activation": "BLOCKED",
                 "checkpoint": ledger.inspect()["checkpoint"]}, sort_keys=True, indent=2) + "\n")
        print("PASS: real PostgreSQL CAS, independent runners, process death, signed audit; production BLOCKED")
    finally:
        for fixture in fixtures:
            fixture.close()
        keys.close()


if __name__ == "__main__":
    main()
