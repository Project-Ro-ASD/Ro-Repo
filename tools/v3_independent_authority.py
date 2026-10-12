"""Independent monotonic checkpoint/history interface and local test service.

The service must be operated outside the ledger's failure/restore domain. This
implementation is a reproducible loopback test service with disposable keys;
its deployment, storage durability and signer custody remain UNVERIFIED.
Reads bind a caller nonce and short lifetime, preventing replay of signed tips.
"""
import contextlib
import http.server
import re
import secrets
import sqlite3
import urllib.request

from v3_backend_trust import canonical, digest, key_identity, require_test_root, strict_json, verify_envelope, require_attestation
from v3_promotion_planner import PlanningError
from v3_backend_ledger import Ledger


class LocalAuthority:
    def __init__(self, root, signer, updater_key, updater_pin, clock, *, recovery_key=None, recovery_pin=None):
        if digest(updater_key) != updater_pin or key_identity(updater_key) == key_identity(signer.public):
            raise PlanningError("independent checkpoint and updater roots required")
        if recovery_key is not None and (digest(recovery_key) != recovery_pin or key_identity(recovery_key) in {key_identity(updater_key), key_identity(signer.public)}):
            raise PlanningError("independent restore/abort observer root required")
        self.root = require_test_root(root)
        self.path = self.root / "independent.sqlite"
        self.signer, self.updater_key, self.updater_pin, self.clock = signer, updater_key, updater_pin, clock
        self.recovery_key, self.recovery_pin = recovery_key, recovery_pin
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS records (name TEXT PRIMARY KEY, body TEXT NOT NULL)")

    @contextlib.contextmanager
    def _db(self):
        require_test_root(self.root)
        if self.path.is_symlink():
            raise PlanningError("unsafe independent service storage")
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def exchange(self, request):
        if (not isinstance(request, dict) or set(request) != {"name", "nonce", "update"} or
                not isinstance(request["name"], str) or not isinstance(request["nonce"], str) or
                not re.fullmatch(r"[a-z0-9_/-]{1,200}", request["name"]) or not re.fullmatch(r"[a-f0-9]{64}", request["nonce"]) or
                request["update"] is not None and not isinstance(request["update"], dict)):
            raise PlanningError("invalid independent authority request")
        name, nonce = request["name"], request["nonce"]
        with self._db() as db:
            row = db.execute("SELECT body FROM records WHERE name=?", (name,)).fetchone()
            old = None if row is None else strict_json(row[0])
            if request["update"] is not None:
                raw = canonical(request["update"])
                payload = request["update"].get("payload", {})
                expected = {"name": name, "nonce": nonce, "previous": old, "value": payload.get("value")}
                update = verify_envelope(raw, role="independent-update", public_key=self.updater_key,
                    key_sha256=self.updater_pin, expected=expected, now=self.clock()).payload
                value = update["value"]
                if name.startswith("history/"):
                    # The observer's current UTC time is the only allowed fresh
                    # genesis. Clients cannot import an old claimed timestamp.
                    if old is not None or not isinstance(value, dict) or set(value) != {"candidate_sha256", "promotion_group", "publication_run", "availability_sha256", "published_at"}:
                        raise PlanningError("history genesis is immutable")
                    import datetime as dt
                    stamp = dt.datetime.fromtimestamp(self.clock(), dt.timezone.utc).isoformat().replace("+00:00", "Z")
                    if (value["published_at"] not in {None, stamp} or name != "history/" + value["candidate_sha256"] or
                            not re.fullmatch(r"[0-9a-f]{64}", value["availability_sha256"]) or not re.fullmatch(r"[1-9][0-9]*", value["publication_run"])):
                        raise PlanningError("fresh independently observed history genesis required")
                    # A real network client cannot predict the server's exact
                    # fractional UTC clock. Null requests a fresh server-assigned
                    # timestamp; signed output freezes it without backdating.
                    value = {**value, "published_at": stamp}
                elif name.startswith("checkpoint/"):
                    if (not isinstance(value, dict) or set(value) != {"seq", "sha256"} or type(value["seq"]) is not int or value["seq"] < 1 or
                            not isinstance(value["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) or
                            old is not None and (value["seq"] < old["seq"] or value["seq"] == old["seq"] and value != old)):
                        raise PlanningError("checkpoint regression/substitution")
                    pending = db.execute("SELECT body FROM records WHERE name=?", ("reservation/" + name.split("/", 1)[1],)).fetchone()
                    if pending is not None:
                        pending = strict_json(pending[0])
                        if pending["status"] == "PREPARED" and value != pending["target"]:
                            raise PlanningError("checkpoint must acknowledge exact independent reservation")
                elif name.startswith("reservation/"):
                    self._reservation(db, name, old, value)
                else:
                    raise PlanningError("unsupported independent record namespace")
                db.execute("INSERT INTO records VALUES(?,?) ON CONFLICT(name) DO UPDATE SET body=excluded.body", (name, canonical(value).decode()))
                old = value
            return self.signer.envelope("independent-state", {"name": name, "nonce": nonce, "value": old,
                "issued_at": int(self.clock()), "expires_at": int(self.clock()) + 30})

    def _reservation(self, db, name, old, value):
        if not isinstance(value, dict) or set(value) != {"base", "target", "status", "observation"}:
            raise PlanningError("invalid independent transaction reservation")
        for tip in (value["base"], value["target"]):
            if not isinstance(tip, dict) or set(tip) != {"seq", "sha256"} or type(tip["seq"]) is not int or tip["seq"] < 1 or not re.fullmatch(r"[a-f0-9]{64}", tip["sha256"]):
                raise PlanningError("invalid reservation checkpoint")
        if value["target"]["seq"] != value["base"]["seq"] + 1:
            raise PlanningError("reservation must bind the next signed audit event")
        row = db.execute("SELECT body FROM records WHERE name=?", ("checkpoint/" + name.split("/", 1)[1],)).fetchone()
        tip = None if row is None else strict_json(row[0])
        if value["status"] == "PREPARED":
            if tip != value["base"] or value["observation"] is not None or old is not None and old["status"] == "PREPARED":
                raise PlanningError("unresolved independent reservation blocks writers")
        elif value["status"] in {"COMMITTED", "ABORTED"}:
            if old is None or old["status"] != "PREPARED" or any(old[k] != value[k] for k in ("base", "target")):
                raise PlanningError("reservation finalization substitution")
            if value["status"] == "COMMITTED":
                if tip != value["target"] or value["observation"] is not None:
                    raise PlanningError("commit requires independently acknowledged target")
            else:
                if tip != value["base"] or self.recovery_key is None:
                    raise PlanningError("independent abort/restore observer missing")
                observation = value["observation"]
                logs = observation.get("payload", {}).get("logs_sha256") if isinstance(observation, dict) else None
                if not isinstance(logs, str) or not re.fullmatch(r"[a-f0-9]{64}", logs):
                    raise PlanningError("independent abort logs missing")
                verify_envelope(canonical(observation), role="restore-observation", public_key=self.recovery_key, key_sha256=self.recovery_pin,
                    expected={"reservation": name, "base": value["base"], "target": value["target"],
                              "transaction_not_committed": True, "writers_fenced": True, "logs_sha256": logs}, now=self.clock())
        else:
            raise PlanningError("unsupported reservation state")


class AuthorityClient:
    def __init__(self, exchange, *, public_key, key_sha256, clock, updater=None):
        self.exchange, self.public_key, self.pin, self.clock, self.updater = exchange, public_key, key_sha256, clock, updater

    def read(self, name):
        return self._request(name, None)

    def advance(self, name, previous, value):
        if self.updater is None:
            raise PlanningError("read-only independent checkpoint client")
        return self._request(name, (previous, value))

    def _request(self, name, update):
        nonce = secrets.token_hex(32)
        request = {"name": name, "nonce": nonce, "update": None}
        if update is not None:
            request["update"] = strict_json(self.updater.envelope("independent-update", {"name": name, "nonce": nonce,
                "previous": update[0], "value": update[1], "issued_at": int(self.clock()), "expires_at": int(self.clock()) + 30}))
        raw = self.exchange(request)
        parsed = strict_json(raw)
        value = parsed.get("payload", {}).get("value")
        return verify_envelope(raw, role="independent-state", public_key=self.public_key, key_sha256=self.pin,
            expected={"name": name, "nonce": nonce, "value": value}, now=self.clock()).payload["value"]


class CheckpointedLedger(Ledger):
    """Mandatory external read before every operation, reconciliation after commit.

    A signed next-event reservation is durable independently BEFORE DB commit.
    A committed target is acknowledged after commit. If a crash leaves the
    target absent, an independently operated/fenced abort observer must prove
    noncommit; a local old DB cannot silently clear the reservation.
    """
    def __init__(self, ledger, client, identity):
        if key_identity(ledger.audit_key) == key_identity(client.public_key):
            raise PlanningError("ledger audit and independent checkpoint roots must differ")
        if not re.fullmatch(r"[a-z0-9_-]{1,64}", identity):
            raise PlanningError("invalid independent ledger identity")
        self.ledger, self.client, self.name = ledger, client, "checkpoint/" + identity
        self.reservation_name = "reservation/" + identity
        if client.read(self.name) is None:
            raise PlanningError("independent checkpoint missing; separately authenticate initial seeding")

    def __getattr__(self, name):
        return getattr(self.ledger, name)

    def execute(self, operation, attempt, change, *, checkpoint=None, **kwargs):
        self.reconcile()
        external = self.client.read(self.name)
        if external is None:
            raise PlanningError("independent checkpoint missing")
        # An additional caller checkpoint must also be honored, never replace
        # the mandatory independently fetched tip with a local claim.
        if checkpoint is not None:
            self.ledger.inspect(checkpoint=checkpoint)
        def prepare(receipt):
            current = self.client.read(self.name)
            old = self.client.read(self.reservation_name)
            if old is not None and old["status"] == "PREPARED":
                raise PlanningError("unresolved independent reservation")
            self.client.advance(self.reservation_name, old, {"base": current, "target": receipt, "status": "PREPARED", "observation": None})
        result, receipt = self.ledger.execute(operation, attempt, change, checkpoint=external, before_commit=prepare, **kwargs)
        self.reconcile()
        return result, receipt

    def inspect(self, attempt=None, *, checkpoint=None):
        self.reconcile()
        external = self.client.read(self.name)
        if external is None:
            raise PlanningError("independent checkpoint missing")
        if checkpoint is not None:
            self.ledger.inspect(checkpoint=checkpoint)
        return self.ledger.inspect(attempt, checkpoint=external)

    def reconcile(self):
        # Keep the ledger serialization lock across checkpoint CAS. Other
        # checkpointed writers cannot commit while this receipt is sampled.
        with self.ledger.adapter.transaction() as db:
            self.ledger._lock(db)
            old = self.client.read(self.name)
            if old is None:
                raise PlanningError("independent checkpoint missing")
            current = self.ledger._integrity(db, old)
            reservation = self.client.read(self.reservation_name)
            if reservation is not None and reservation["status"] == "PREPARED":
                if current != reservation["target"]:
                    raise PlanningError("reserved transaction absent; independent fenced abort/restore observation required")
                self.client.advance(self.name, old, current)
                self.client.advance(self.reservation_name, reservation, {**reservation, "status": "COMMITTED"})
            elif current != old:
                raise PlanningError("unreserved DB history exceeds independent checkpoint")
            return current

    def reconcile_abort(self, raw_observation):
        with self.ledger.adapter.transaction() as db:
            self.ledger._lock(db)
            old = self.client.read(self.name)
            pending = self.client.read(self.reservation_name)
            if pending is None or pending["status"] != "PREPARED" or self.ledger._integrity(db, old) != pending["base"]:
                raise PlanningError("abort cannot discard a committed or substituted transaction")
            # The independent service verifies its separately provisioned
            # observer signature. A local DB assertion never grants this action.
            return self.client.advance(self.reservation_name, pending, {**pending, "status": "ABORTED", "observation": strict_json(raw_observation)})

    def verify_restore(self, observation, *, now):
        payload = require_attestation(observation, "restore-observation")
        current = self.inspect()
        if (set(payload) != {"issued_at", "expires_at", "checkpoint", "ledger_identity", "failover", "restore", "logs_sha256"} or
                not payload["issued_at"] <= now < payload["expires_at"] or
                payload.get("checkpoint") != current["checkpoint"] or payload.get("ledger_identity") != self.name or
                payload.get("failover") != "PASS" or payload.get("restore") != "PASS" or
                not isinstance(payload.get("logs_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", payload["logs_sha256"])):
            raise PlanningError("independent restore/failover acceptance required")
        return {"scope": "v3-restore-observation", "observation_sha256": observation.sha256,
                "production_activation": "BLOCKED", "checkpoint": current["checkpoint"]}


def server(authority):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if self.path != "/v1/exchange" or not 1 <= length <= 65536:
                    raise PlanningError("invalid bounded request")
                raw = authority.exchange(strict_json(self.rfile.read(length)))
                self.send_response(200)
            except (PlanningError, ValueError):
                raw = b'{"error":"independent authority rejected request"}'
                self.send_response(409)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *args):
            pass
    return http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)


def https_exchange(url):
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.username or parts.password or parts.fragment or parts.query:
        raise PlanningError("independent authority requires pinned HTTPS endpoint")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise PlanningError("independent authority redirect rejected")
    def exchange(request):
        req = urllib.request.Request(url, data=canonical(request), headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=10) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise PlanningError("independent response exceeds bound")
        return raw
    return exchange
