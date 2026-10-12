# V3 backend isolated acceptance evidence

Acceptance date: 2026-10-12 (Europe/Istanbul). Tested implementation commit:
`dc671edb0f1196720466025d53299efa72b88f80`.

Canonical source inventory digest for tools/tests/schemas/config:
`e123885f9fb0750b55729e84984e4a5defc4e074828a45a7a1163620e9180200`.
The complete inventory is in `backend-rehearsal/rehearsal.json`. Fedora acceptance
and backend rehearsal independently record the same digest. Subsequent report/CI
record commits do not modify implementation files.

| Execution | Acceptance | Evidence |
| --- | --- | --- |
| Full Python suite | PASS: 493 tests, zero failures/errors/skips | `unit.log` |
| V3 security suite | PASS: 349 tests (233 baseline + 116 new) | Full suite includes every `test_v3_*.py`; PR CI also runs the V3-only command |
| Backend decisions | PASS: 79 state/crypto/crash tests, 28 input/migration tests, 7 Git tests, 2 workflow tests | Named tests and results in `unit.log` |
| Native x86_64 Fedora 44 real signed fixtures | PASS: bootstrap, complete retained upgrade, immutable RPM/SRPM/metadata validation, `.rpmnew`, channels, deterministic metadata, negative dependency/conflict/unsigned-source checks | `fedora44/acceptance.json`, `fedora44.log`, per-transaction receipts/logs |
| Pinned upstream fixture | PASS: genuine RPM signing/header/checksum and primary-location checks, exact pinned dependency installed by real DNF5 | `fedora44/upstream-fixture.json`, `fedora44/pinned-dependency-closure/` |
| Existing V2 compatibility E2E | PASS: existing script completed and wrote its final fixture receipt; signed single/multi-package real DNF scenarios preserved | `v2-compatibility.log`, `v2-compatibility.json` |
| Actual PostgreSQL provider | PASS: PostgreSQL 18.6, independent processes, one CAS winner, interrupted transaction, eight consumed identities, signed audit/post verification | `postgres.json`, `providers.log` |
| Combined backend and actual Git CAS | PASS: state reaches POST_VERIFIED after independently rereading the signed Git advertisement | `backend-rehearsal/rehearsal.json`, `providers.log` |
| Migration fixture / fresh-authorized recovery / every-state crash | PASS | `fedora44/migration-fixture.json` and corresponding named unit tests |
| Strict schemas / disabled jobs / read-only workflow | PASS | Named schema/workflow tests in `unit.log`; existing production and V2 workflow diffs are empty |
| Native aarch64 / real released applications / official pinned Fedora upstream / Plasma, boot and Ro-Store VMs | UNVERIFIED | Explicit acceptance gates in Fedora/backend JSON and activation checklist |
| Real protected authorization, external provider durability/checkpoints, live Pages deployment/CDN and V2/client cutover | BLOCKED | No live execution, production keys or activation |

The Fedora base was
`registry.fedoraproject.org/fedora@sha256:07584325a68e0308215aff1de506d8da6452d2e465c25729829a01393446f204`.
Packages installed into the disposable runtime are recorded in `runtime.txt` and
the full-set receipts' runtime package-set digests. The acceptance installroots
use only explicitly permitted file repositories. The pinned upstream is a signed
synthetic dependency cache, not independently authenticated official Fedora input.
The legacy V2 compatibility script still uses its original upstream behavior; it
does not establish independently pinned official Fedora acceptance.

All keys included here are disposable public keys. No private key, JWT, service
credential or provider database is exported. Synthetic workload/approval/test
attestations exercise protocol decisions and cannot authorize production. The
legacy V2 fixture receipt is an untrusted observation too.

Reproduction commands, from a writable disposable copy of this commit:

```sh
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s tests -p 'test_v3_*.py' -v
python3 tests/v3-backend-rehearsal.py --output /tmp/new-backend-evidence
bash tests/v3-integration-e2e.sh /tmp/new-fedora-evidence
RO_REPO_E2E_EVIDENCE=/tmp/new-v2.json bash tests/e2e-local.sh
python3 tests/v3-backend-postgres-e2e.py \
  --port 55432 --dbname ro_v3_test_fresh --output /tmp/new-postgres.json
```

The last command requires a fresh UTF8 disposable PostgreSQL database on loopback
and psycopg3. Existing V2 unit tests write relative temporary directories, so a
read-only source mount is not a valid full-suite working directory. This was
corrected with a Git archive in disposable storage; tests were not weakened.

GitHub CI results are recorded separately after the draft PR is opened. CI success
is a review check, not a publication or protected approval.

The first CI Fedora V3 run failed because its runtime lacked PyYAML for the new
migration rehearsal. The existing isolated V3 test workflow now explicitly
installs `python3-yaml` and `openssl`, matching the locally exercised runtime.
This dependency fix does not change any production or V2 workflow.
