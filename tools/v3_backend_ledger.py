"""Transactional replay/CAS/audit ledger with SQLite and PostgreSQL adapters.

SQLite is a disposable rehearsal provider. PostgreSQL uses row locking and
serializable transactions for independent runners; this milestone restricts
connections to localhost test databases. External HA, backup restoration,
TLS and independent monotonic checkpoints remain activation prerequisites.
"""
import contextlib
import datetime as dt
import pathlib
import sqlite3

from v3_backend_trust import (b64, canonical, encode, require_test_root,
                              strict_json, verify_bytes)
from v3_policy_profile import sha
from v3_promotion_planner import PlanningError

DDL = (
    "CREATE TABLE IF NOT EXISTS head (id INTEGER PRIMARY KEY, body TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY, body TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS consumed (kind TEXT NOT NULL, identity TEXT NOT NULL, attempt TEXT NOT NULL, PRIMARY KEY(kind, identity))",
    "CREATE TABLE IF NOT EXISTS views (digest TEXT PRIMARY KEY, body TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, body TEXT NOT NULL, signature TEXT NOT NULL)",
)


class Session:
    def __init__(self, connection, postgres=False):
        self.connection, self.postgres = connection, postgres

    def execute(self, sql, params=()):
        return self.connection.execute(sql.replace("?", "%s") if self.postgres else sql, params)


class SQLiteAdapter:
    scope = "isolated-sqlite"

    def __init__(self, root, filename="ledger.sqlite"):
        import re
        self.root = require_test_root(root)
        if not re.fullmatch(r"[a-z0-9-]+\.sqlite", filename):
            raise PlanningError("unsafe database path")
        self.path = self.root / filename

    @contextlib.contextmanager
    def transaction(self):
        require_test_root(self.root)
        if self.path.is_symlink():
            raise PlanningError("unsafe database file")
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            yield Session(connection)
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()


class PostgreSQLAdapter:
    scope = "isolated-postgresql"

    def __init__(self, *, host, port, dbname, user, password):
        import re
        if host not in {"localhost", "127.0.0.1", "::1"} or not re.fullmatch(r"ro_v3_test_[a-z0-9_]+", dbname):
            raise PlanningError("live database writes are BLOCKED")
        if type(port) is not int or not 1024 <= port <= 65535:
            raise PlanningError("invalid isolated database port")
        self.config = dict(host=host, port=port, dbname=dbname, user=user, password=password)

    @contextlib.contextmanager
    def transaction(self):
        try:
            import psycopg
        except ImportError as exc:
            raise PlanningError("PostgreSQL provider requires psycopg; execution UNVERIFIED") from exc
        try:
            with psycopg.connect(**self.config, connect_timeout=10) as connection:
                connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                if connection.execute("SHOW server_encoding").fetchone()[0] not in {"UTF8", b"UTF8"}:
                    raise PlanningError("PostgreSQL ledger requires a UTF8 database")
                # Row locking protects CAS; serialization failures are explicit
                # retryable rejections, never a reason to bypass the old base.
                connection.execute("SELECT pg_advisory_xact_lock(713044)")
                yield Session(connection, True)
        except psycopg.errors.SerializationFailure as exc:
            raise PlanningError("provider serialization conflict; retry immutable request") from exc


class Ledger:
    def __init__(self, adapter, signer, *, audit_key, audit_key_sha256, clock):
        self.adapter, self.signer, self.clock = adapter, signer, clock
        self.audit_key, self.audit_key_sha256 = audit_key, audit_key_sha256
        if signer.key_sha256 != audit_key_sha256:
            raise PlanningError("audit signer differs from independent audit root")
        with adapter.transaction() as db:
            for sql in DDL:
                db.execute(sql)
            if db.execute("SELECT body FROM head WHERE id=1").fetchone() is None:
                db.execute("INSERT INTO head(id,body) VALUES(1,?)", (canonical({"digest": None, "generation": 0, "last_verified": None}).decode(),))
                self._append(db, "initialize", None)
            self._integrity(db)

    def _lock(self, db):
        db.execute("SELECT body FROM head WHERE id=1" + (" FOR UPDATE" if db.postgres else ""))

    @staticmethod
    def head(db):
        return strict_json(db.execute("SELECT body FROM head WHERE id=1").fetchone()[0])

    @staticmethod
    def attempt(db, attempt):
        row = db.execute("SELECT body FROM attempts WHERE id=?", (attempt,)).fetchone()
        if row is None:
            raise PlanningError("unknown immutable attempt")
        value = strict_json(row[0])
        from ro_repo import validate_schema
        validate_schema(value, "backend-attempt-v3")
        return value

    @staticmethod
    def put_attempt(db, value):
        from ro_repo import validate_schema
        validate_schema(value, "backend-attempt-v3")
        db.execute("UPDATE attempts SET body=? WHERE id=?", (canonical(value).decode(), value["attempt_id"]))

    @staticmethod
    def consume(db, kind, identity, attempt):
        existing = db.execute("SELECT attempt FROM consumed WHERE kind=? AND identity=?", (kind, identity)).fetchone()
        if existing:
            raise PlanningError("consumed authorization/workload replay")
        db.execute("INSERT INTO consumed(kind,identity,attempt) VALUES(?,?,?)", (kind, identity, attempt))

    @staticmethod
    def state_digest(db):
        state = {}
        for name, fields, order in (("head", "id,body", "id"), ("attempts", "id,body", "id"),
                                     ("consumed", "kind,identity,attempt", "kind,identity"), ("views", "digest,body", "digest")):
            state[name] = [list(row) for row in db.execute("SELECT " + fields + " FROM " + name + " ORDER BY " + order).fetchall()]
        return sha(state)

    def _append(self, db, operation, attempt):
        previous = db.execute("SELECT seq,body FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        event = {"domain": "ro-repo-v3-audit-1", "seq": 1 if previous is None else previous[0] + 1,
                 "parent_sha256": None if previous is None else sha(strict_json(previous[1])),
                 "operation": operation, "attempt_id": attempt,
                 "at": dt.datetime.fromtimestamp(self.clock(), dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                 "state_sha256": self.state_digest(db), "audit_key_sha256": self.audit_key_sha256}
        signature = encode(self.signer.sign(canonical(event)))
        db.execute("INSERT INTO events(seq,body,signature) VALUES(?,?,?)", (event["seq"], canonical(event).decode(), signature))
        return {"seq": event["seq"], "sha256": sha(event)}

    def _integrity(self, db, checkpoint=None):
        previous = None
        rows = db.execute("SELECT seq,body,signature FROM events ORDER BY seq").fetchall()
        if not rows:
            raise PlanningError("missing independently signed audit history")
        checkpoints = {}
        for index, (seq, raw, signature) in enumerate(rows, 1):
            event = strict_json(raw)
            if set(event) != {"domain", "seq", "parent_sha256", "operation", "attempt_id", "at", "state_sha256", "audit_key_sha256"} or event["domain"] != "ro-repo-v3-audit-1" or seq != index or event["seq"] != seq or event["parent_sha256"] != previous or event["audit_key_sha256"] != self.audit_key_sha256:
                raise PlanningError("audit sequence/domain/identity corruption")
            verify_bytes(self.audit_key, self.audit_key_sha256, canonical(event), b64(signature))
            previous = sha(event)
            checkpoints[seq] = previous
        if event["state_sha256"] != self.state_digest(db):
            raise PlanningError("state differs from authenticated audit")
        if checkpoint is not None and checkpoints.get(checkpoint["seq"]) != checkpoint["sha256"]:
            raise PlanningError("ledger rollback violates independent checkpoint")
        return {"seq": len(rows), "sha256": previous}

    def execute(self, operation, attempt, change, *, checkpoint=None, inject=None):
        with self.adapter.transaction() as db:
            self._lock(db)
            self._integrity(db, checkpoint)
            before = self.state_digest(db)
            result = change(db)
            if self.state_digest(db) == before:
                return result, self._integrity(db, checkpoint)
            if inject:
                inject("before-audit")
            receipt = self._append(db, operation, attempt)
            if inject:
                inject("after-audit")
            return result, receipt

    def inspect(self, attempt=None, *, checkpoint=None):
        with self.adapter.transaction() as db:
            self._lock(db)
            return {"checkpoint": self._integrity(db, checkpoint), "head": self.head(db),
                    "attempt": None if attempt is None else self.attempt(db, attempt),
                    "publishable": False, "scope": self.adapter.scope}
