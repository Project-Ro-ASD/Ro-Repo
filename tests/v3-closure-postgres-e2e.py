"""Actual verify-full/restricted-role acceptance; no production connections."""
import argparse
import json
import multiprocessing
import pathlib
import sys
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from v3_backend_support import Keys, Fixture, NOW
from v3_backend_ledger import Ledger
from v3_postgresql_production import ProductionPostgreSQLAdapter, initialize_empty_rehearsal
from v3_backend_trust import digest, TestSigner
from v3_pages_finalization_support import fresh_authority
from v3_publication_backend import Backend
from v3_promotion_planner import PlanningError


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ca", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()
    output = pathlib.Path(args.output)
    if output.exists():
        raise PlanningError("immutable TLS evidence already exists")
    keys = Keys()
    fixtures = []
    try:
        config = dict(host="localhost", port=55432, dbname="ro_v3_test_tls", user="ro_v3_writer", schema="ro_v3",
            sslrootcert=args.ca, sslrootcert_sha256=digest(pathlib.Path(args.ca).read_bytes()), application_name="ro_v3_test")
        adapter = ProductionPostgreSQLAdapter.rehearsal(config, password="disposable-test-only", root=keys.root)
        empty = keys.attestation("empty-stable", {"database": config["dbname"], "schema": config["schema"], "storage_commit": "a"*40,
            "inventory_sha256": "b"*64, "remote_sha256": "c"*64, "stable_absent": True, "writer_exclusive": True})
        initialize_empty_rehearsal(adapter, keys.signers["audit"], empty, audit_key=keys.signers["audit"].public,
            audit_key_sha256=keys.signers["audit"].key_sha256, now=NOW)
        clock = {"now": NOW}
        ledger = Ledger(adapter, keys.signers["audit"], audit_key=keys.signers["audit"].public,
                        audit_key_sha256=keys.signers["audit"].key_sha256, clock=lambda: clock["now"])
        fixtures = [Fixture(keys, attempt="tls-writer-one"), Fixture(keys, attempt="tls-writer-two", version="0.2.6")]
        for fx in fixtures:
            fx.ledger, fx.backend = ledger, Backend(ledger)
            fx.advance("AUTHORIZED")
            fx.stage()
        context = multiprocessing.get_context("fork")
        queue = context.Queue()
        def writer(fx):
            try:
                fx.backend.publish(fx.attempt, fx.approval)
                queue.put("won")
            except PlanningError:
                queue.put("conflict")
        processes = [context.Process(target=writer, args=(fx,)) for fx in fixtures]
        for process in processes:
            process.start()
        for process in processes:
            process.join(45)
            if process.exitcode != 0:
                raise AssertionError("TLS writer process failed")
        if sorted(queue.get(timeout=3) for _ in processes) != ["conflict", "won"]:
            raise AssertionError("TLS restricted ledger admitted concurrent writers")
        before = ledger.inspect()
        class Crash(Exception):
            pass
        def mutate(db):
            db.execute("UPDATE head SET body=? WHERE id=1", ('{}',))
            raise Crash()
        try:
            ledger.execute("crash", None, mutate)
        except Crash:
            pass
        if ledger.inspect() != before:
            raise AssertionError("TLS rollback did not preserve audit state")
        # The winning first intent has no prior POST_VERIFIED stable. Exercise
        # genuine new authorization and append-only child under real restricted
        # PostgreSQL permissions; never reset or replace the original attempt.
        winner = next(fx for fx in fixtures if fx.result.sha256 == before["head"]["digest"])
        original = ledger.inspect(winner.attempt)["attempt"]
        clock["now"] = NOW + 301
        winner.now = clock["now"]
        resume = winner.backend.first_resume_binding(winner.attempt)
        evidence, result, approval = fresh_authority(winner, "tls-fresh-first", operation="resume-first", resume=resume)
        observer = TestSigner(keys.root, "tls-first-recovery")
        raw = observer.envelope("restore-observation", {"resume":resume, "writers_fenced":True, "requests_drained":True,
            "issued_at":clock["now"], "expires_at":clock["now"]+60})
        child = winner.backend.reauthorize_first("tls-fresh-first", evidence, result, approval,
            observation_raw=raw, observation_key=observer.public, observation_pin=observer.key_sha256)
        if child["state"] != "AUTHORIZED" or ledger.inspect(winner.attempt)["attempt"] != original or ledger.inspect()["head"] != before["head"]:
            raise AssertionError("fresh PostgreSQL first recovery changed original signed history or intent generation")
        # Verify permissions independently with actual denied operations.
        import psycopg
        for statement in ("DELETE FROM events", "UPDATE consumed SET attempt='forged'", "TRUNCATE views", "CREATE TABLE unauthorized(id int)"):
            try:
                with adapter.transaction() as db:
                    db.execute(statement)
            except psycopg.errors.InsufficientPrivilege:
                pass
            else:
                raise AssertionError("writer accepted forbidden operation")
        bad_ca = keys.root / "wrong-ca.pem"
        import subprocess
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(keys.root / "wrong-ca.key"),
            "-out", str(bad_ca), "-days", "1", "-subj", "/CN=wrong"], check=True, capture_output=True)
        wrong = ProductionPostgreSQLAdapter.rehearsal({**config, "sslrootcert": str(bad_ca), "sslrootcert_sha256": digest(bad_ca.read_bytes())},
            password="test", root=keys.root)
        try:
            with wrong.transaction():
                raise AssertionError("wrong CA connected")
        except PlanningError:
            pass
        wrong_identity = ProductionPostgreSQLAdapter.rehearsal({**config, "host": "127.0.0.1"}, password="test", root=keys.root)
        try:
            with wrong_identity.transaction():
                raise AssertionError("wrong hostname connected")
        except PlanningError:
            pass
        # Same trusted cert but wrong identity: an explicit host override is
        # rejected by libpq verify-full before role/SQL access.
        with mock.patch("psycopg.connect", wraps=psycopg.connect) as connect:
            with adapter.transaction():
                pass
            if connect.call_args.kwargs["sslmode"] != "verify-full" or "hostaddr" in connect.call_args.kwargs:
                raise AssertionError("server identity verification weakened")
        output.write_text(json.dumps({"scope": "v3-isolated-tls-postgresql", "publishable": False,
            "tls_verify_full": "PASS", "wrong_ca_rejection": "PASS", "wrong_hostname_rejection": "PASS", "restricted_role_denials": "PASS", "two_process_cas": "PASS",
            "transaction_rollback": "PASS", "fresh_first_reauthorization": "PASS", "external_ha_restore": "UNVERIFIED", "production_activation": "BLOCKED",
            "checkpoint": ledger.inspect()["checkpoint"]}, indent=2) + "\n")
        print("PASS: real TLS verify-full, restricted roles, signed ledger, independent process CAS, fresh first-publication reauthorization")
    finally:
        for fx in fixtures:
            fx.close()
        keys.close()


if __name__ == "__main__":
    main()
