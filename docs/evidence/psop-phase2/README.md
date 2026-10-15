# PR-B local acceptance evidence

All publications here are **local disposable test** publications. No remote
repository, Pages build, production ledger or production signing secret is used.
Production activation remains **BLOCKED**; all PSOP receipts are `publishable=false`.

| File | Meaning |
| --- | --- |
| [source-inventory.json](source-inventory.json) | Exact SHA256/mode inventory of the PSOP source, schemas and added tests used for acceptance. Canonical inventory digest: `c1a4ee92c40ee697987bec8a85ab2344135d0587f4ac7940673029e52fb4b0e8`. |
| [tests.json](tests.json) | Commands, counts, runtime scope and cached Fedora image identity. |
| [full-discovery.log.gz](full-discovery.log.gz) | Final local full discovery: 652 tests, zero skips, PASS. |
| [psop-targeted.log.gz](psop-targeted.log.gz) | 11 unchanged PR-A guards + 33 new PR-B tests: 44 PASS. |
| [e2e.json](e2e.json) / [offline-e2e.log.gz](offline-e2e.log.gz) | Three actual RPM/GPG/SQLite/Git publication flows; 17 negative assertions. Ephemeral test identities and exact local Git/result/approval digests are retained. |
| [actual-history.json](actual-history.json) | Read-only verification of six actual public signed legacy publications. Integrity PASS; production first-availability/coverage/dwell BLOCKED. |
| [source-audit.json](source-audit.json) | Unchanged original 234-file baseline, source guard PASS and production activation BLOCKED. The older `base_main` value intentionally anchors the original Phase-A protected-file baseline. |
| [refs.json](refs.json) | Unchanged main/Pages/#78 references, verified through read-only remote requests. |

The standalone RPM E2E ran with `--network none`, source mounted read-only, and
only a temporary output mount. It builds/signs fresh synthetic RPM inputs; the
publisher does not rebuild or re-sign RPMs. The aarch64 repository view is checked
through actual headers/preflight and local `rpm --test --ignorearch`, not native
aarch64 DNF acceptance. Model-test claims are authenticated synthetic claims,
not evidence that DNF5, GUI or application tests ran.

GitHub CI results must be checked against the final PR head. These local files do
not attest GitHub CI. No provider deadline fencing, Pages build ordering, global
CDN freshness, external HTTPS/Pages, client DNF5 or GUI acceptance is claimed.

Implementation and remaining boundaries:
[API/security map](../../psop/PR-B-IMPLEMENTATION.md),
[PASS/BLOCKED/UNVERIFIED matrix](../../psop/PR-B-REPORT.md).
