#!/usr/bin/env bash
# Disposable container only: ephemeral TLS server and two isolated databases.
set -euo pipefail
{ test -f /run/.containerenv || test -f /.dockerenv; } || { echo 'Run only in a disposable Fedora container'; exit 1; }
output="${1:?new evidence directory required}"
mkdir -p "$output"
work="$(mktemp -d /tmp/v3-closure-pg-XXXXXXXX)"
chmod 755 "$work"
mkdir "$work/data"
chown postgres:postgres "$work/data"
runuser -u postgres -- initdb -D "$work/data" -A trust -U postgres --encoding=UTF8 > "$output/initdb.log" 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/data/server.key" -out "$work/data/server.crt" -days 1 -subj /CN=localhost -addext 'subjectAltName=DNS:localhost' > "$output/tls-keygen.log" 2>&1
chmod 600 "$work/data/server.key"
chown postgres:postgres "$work/data/server.key" "$work/data/server.crt"
printf '%s\n' '' 'ssl=on' "ssl_cert_file='server.crt'" "ssl_key_file='server.key'" >> "$work/data/postgresql.conf"
touch "$work/postgres.log"
chown postgres:postgres "$work/postgres.log"
runuser -u postgres -- pg_ctl -D "$work/data" -l "$work/postgres.log" -o "-h 127.0.0.1 -p 55432 -k $work/data" -w start || { cat "$work/postgres.log"; exit 1; }
trap 'runuser -u postgres -- pg_ctl -D "$work/data" -m immediate stop >/dev/null 2>&1 || true' EXIT
createdb -h 127.0.0.1 -p 55432 -U postgres ro_v3_test_backend
python3 tests/v3-backend-postgres-e2e.py --output "$output/postgres.json"
createdb -h 127.0.0.1 -p 55432 -U postgres ro_v3_test_tls
PYTHONPATH=tools python3 -c 'from v3_postgresql_production import provisioning_sql; print(provisioning_sql())' > "$work/provision.sql"
psql -h 127.0.0.1 -p 55432 -U postgres -d ro_v3_test_tls -v ON_ERROR_STOP=1 -f "$work/provision.sql" > "$output/provisioning.log"
cp "$work/data/server.crt" "$work/ca.pem"
python3 tests/v3-closure-postgres-e2e.py --ca "$work/ca.pem" --output "$output/tls-postgres.json"
