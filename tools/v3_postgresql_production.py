"""Separately configured TLS/restricted-role ledger adapter, activation guarded.

The production route never connects in this milestone. The identical session
implementation can execute only through the explicit loopback test factory.
DBA provisioning is separate from the writer: no runtime DDL or elevated role.
"""
import contextlib
import os
import pathlib
import re

from v3_backend_ledger import Session, DDL
from v3_backend_trust import digest, require_test_root
from v3_promotion_planner import PlanningError


class ProductionPostgreSQLAdapter:
    scope = "production-postgresql-blocked"
    managed_schema = True

    def __init__(self, config, *, password):
        required = {"host", "port", "dbname", "user", "schema", "sslrootcert", "sslrootcert_sha256", "application_name"}
        if not isinstance(config, dict) or set(config) != required:
            raise PlanningError("provision explicit DB host/port/name/role/schema/CA pin/application_name")
        if (not isinstance(config["host"], str) or not re.fullmatch(r"[a-zA-Z0-9.-]+", config["host"]) or
                type(config["port"]) is not int or not 1 <= config["port"] <= 65535 or
                any(not isinstance(config[k], str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", config[k]) for k in ("dbname", "user", "schema", "application_name")) or
                config["user"] in {"postgres", "root"} or not isinstance(password, str) or not password):
            raise PlanningError("invalid production DB identity or privileged role")
        if not isinstance(config["sslrootcert"], str) or not isinstance(config["sslrootcert_sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", config["sslrootcert_sha256"]):
            raise PlanningError("independently pinned PostgreSQL CA required")
        ca = pathlib.Path(config["sslrootcert"])
        if not ca.is_absolute() or ca.is_symlink() or not ca.is_file() or digest(ca.read_bytes()) != config["sslrootcert_sha256"]:
            raise PlanningError("independently pinned PostgreSQL CA required")
        self.config, self.password, self.test_root = dict(config), password, None

    @classmethod
    def rehearsal(cls, config, *, password, root):
        root = require_test_root(root)
        if config.get("host") not in {"localhost", "127.0.0.1"} or not re.fullmatch(r"ro_v3_test_[a-z0-9_]+", config.get("dbname", "")):
            raise PlanningError("TLS rehearsal requires loopback isolated test DB")
        value = cls(config, password=password)
        value.scope, value.test_root = "isolated-postgresql", root
        return value

    @contextlib.contextmanager
    def transaction(self):
        if self.test_root is None:
            raise PlanningError("production DB activation BLOCKED; provision TLS roles/checkpoint/restore acceptance then review activation")
        require_test_root(self.test_root)
        if digest(pathlib.Path(self.config["sslrootcert"]).read_bytes()) != self.config["sslrootcert_sha256"]:
            raise PlanningError("PostgreSQL CA changed")
        import psycopg
        try:
            # Every parameter is explicit; no service DSN, hostaddr, environment
            # SSL fallback or search_path supplied by an untrusted connection URL.
            with psycopg.connect(host=self.config["host"], port=self.config["port"], dbname=self.config["dbname"],
                    user=self.config["user"], password=self.password, sslmode="verify-full", sslrootcert=self.config["sslrootcert"],
                    gssencmode="disable", connect_timeout=10, application_name=self.config["application_name"]) as connection:
                connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                connection.execute("SET LOCAL synchronous_commit = on")
                connection.execute("SET LOCAL statement_timeout = '30s'")
                connection.execute("SET LOCAL idle_in_transaction_session_timeout = '60s'")
                connection.execute('SET LOCAL search_path = "' + self.config["schema"] + '", pg_catalog')
                if connection.execute("SHOW server_encoding").fetchone()[0] != "UTF8" or not connection.pgconn.ssl_in_use:
                    raise PlanningError("UTF8 and verified TLS required")
                role = connection.execute("SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone()
                if role is None or any(role):
                    raise PlanningError("restricted writer role required")
                if connection.execute("SELECT count(*) FROM pg_roles WHERE (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) AND pg_has_role(current_user,oid,'MEMBER')").fetchone()[0]:
                    raise PlanningError("writer must not be a member of privileged roles")
                if connection.execute("SELECT pg_has_role(current_user, nspowner, 'MEMBER'), has_schema_privilege(current_user, oid, 'CREATE') FROM pg_namespace WHERE nspname=%s", (self.config["schema"],)).fetchone() != (False, False):
                    raise PlanningError("writer must not own/create ledger schema")
                for table in ("events", "consumed", "views", "attempts", "head"):
                    identity = self.config["schema"] + "." + table
                    row = connection.execute("SELECT pg_has_role(current_user,relowner,'MEMBER') FROM pg_class WHERE oid=to_regclass(%s)", (identity,)).fetchone()
                    if row is None or row[0]:
                        raise PlanningError("writer must not own ledger tables")
                    allowed = {"SELECT", "INSERT"} | ({"UPDATE"} if table in {"attempts", "head"} else set())
                    for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
                        actual = connection.execute("SELECT has_table_privilege(current_user,%s,%s)", (identity, privilege)).fetchone()[0]
                        if actual != (privilege in allowed):
                            raise PlanningError("ledger role grants differ from restricted contract: " + table)
                    if table not in {"attempts", "head"} and connection.execute("SELECT has_any_column_privilege(current_user,%s,'UPDATE')", (identity,)).fetchone()[0]:
                        raise PlanningError("append-only tables must not have column UPDATE grants")
                connection.execute("SELECT pg_advisory_xact_lock(713044)")
                yield Session(connection, True)
        except psycopg.errors.SerializationFailure as exc:
            raise PlanningError("provider serialization conflict; retry immutable request") from exc
        except psycopg.OperationalError as exc:
            raise PlanningError("verified TLS database connection unavailable") from exc


def provisioning_sql(schema="ro_v3", owner="ro_v3_owner", writer="ro_v3_writer"):
    if any(not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", v) for v in (schema, owner, writer)) or owner == writer:
        raise PlanningError("invalid role provisioning identities")
    return "\n".join([
        "-- DBA review artifact; never executed against production by this tool.",
        f"CREATE ROLE {owner} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;",
        f"CREATE ROLE {writer} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;",
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC;",
        f"CREATE SCHEMA {schema} AUTHORIZATION {owner};", f"SET ROLE {owner};", f"SET search_path={schema},pg_catalog;",
        *(sql.replace("IF NOT EXISTS ", "") + ";" for sql in DDL), "RESET ROLE;",
        f"REVOKE ALL ON SCHEMA {schema} FROM PUBLIC;", f"GRANT USAGE ON SCHEMA {schema} TO {writer};",
        f"GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA {schema} TO {writer};",
        f"GRANT UPDATE ON {schema}.head,{schema}.attempts TO {writer};",
        "-- Configure hostssl + SCRAM/client certificates, database CONNECT grants, fsync/full_page_writes, backup and independent checkpoints separately.", ""])


def initialize_empty_rehearsal(adapter, signer, attestation, *, audit_key, audit_key_sha256, now, guard=None, consumed=None):
    """Seed a provisioned EMPTY test ledger after independent empty-state proof.

    Never revive a missing head in an existing ledger. Production initialization
    still requires protected import/cutover and remains blocked by the adapter.
    """
    from v3_backend_trust import require_attestation, key_identity, HEX
    from v3_backend_ledger import Ledger
    payload = require_attestation(attestation, "empty-stable")
    required = {"database", "schema", "storage_commit", "inventory_sha256", "remote_sha256", "stable_absent", "writer_exclusive", "issued_at", "expires_at"}
    observation_fields = {"nonce", "origin", "observation", "history_sha256"}
    if (set(payload) not in (required, required | observation_fields) or payload["database"] != adapter.config["dbname"] or payload["schema"] != adapter.config["schema"] or
            not re.fullmatch(r"[a-f0-9]{40}", payload["storage_commit"]) or not HEX.fullmatch(payload["inventory_sha256"]) or not HEX.fullmatch(payload["remote_sha256"]) or
            payload["stable_absent"] is not True or payload["writer_exclusive"] is not True or not payload["issued_at"] <= now < payload["expires_at"] or
            signer.key_sha256 != audit_key_sha256 or digest(audit_key) != audit_key_sha256):
        raise PlanningError("fresh independently authenticated empty-stable/cutover proof required")
    ledger = Ledger.__new__(Ledger)
    ledger.adapter, ledger.signer, ledger.clock = adapter, signer, lambda: now
    ledger.audit_key, ledger.audit_key_sha256 = audit_key, audit_key_sha256
    with adapter.transaction() as db:
        for name in ("head", "attempts", "consumed", "views", "events"):
            if db.execute("SELECT COUNT(*) FROM " + name).fetchone()[0] != 0:
                raise PlanningError("refusing to initialize nonempty provisioned ledger")
        if guard:
            guard(db)
        from v3_backend_trust import canonical
        db.execute("INSERT INTO head VALUES(1,?)", (canonical({"digest": None, "generation": 0, "last_verified": None}).decode(),))
        for kind, identity in (consumed or {}).items():
            ledger.consume(db, kind, identity, "empty-initialize-" + attestation.sha256)
        ledger._append(db, "empty-initialize-" + attestation.sha256, None)
        if guard:
            guard(db)
        return ledger._integrity(db)
