"""Explicit disposable PostgreSQL integration; never silently skipped."""
import argparse
import json
import multiprocessing
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from v3_backend_support import Keys, Fixture, NOW
from v3_backend_ledger import Ledger, PostgreSQLAdapter
from v3_publication_backend import Backend
from v3_immutable_view import verify_remote, DirectoryReader
from v3_promotion_planner import PlanningError


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
        post = verify_remote(winner.view, DirectoryReader(winner.view), winner.deployment, now=NOW, post_ledger=ledger)
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
        with provider.transaction() as db:
            version = db.execute("SHOW server_version").fetchone()[0]
            count = db.execute("SELECT COUNT(*) FROM consumed").fetchone()[0]
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({"scope": "v3-postgresql-isolated-acceptance", "publishable": False,
                 "server_version": version, "cas": "PASS", "independent_processes": "PASS", "process_death": "PASS",
                 "replay_consumptions": count, "audit_integrity": "PASS", "post_verification": "PASS",
                 "external_ha_durability": "UNVERIFIED", "production_activation": "BLOCKED",
                 "checkpoint": ledger.inspect()["checkpoint"]}, sort_keys=True, indent=2) + "\n")
        print("PASS: real PostgreSQL CAS, independent runners, process death, signed audit; production BLOCKED")
    finally:
        for fixture in fixtures:
            fixture.close()
        keys.close()


if __name__ == "__main__":
    main()
