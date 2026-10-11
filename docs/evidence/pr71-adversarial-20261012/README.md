# PR #71 adversarial review evidence

These are local/CI **test-only observations**, not production attestations,
signing material or publication approvals. Production activation remains BLOCKED.
Only ephemeral **public** keys are stored. No private key is included.

`inventory.json` hashes every other file in this directory. `tested-sources.json`
records the exact tools/tests/schemas/config source inventory used by the Fedora
fixture. Its canonical digest is the `source_code_sha256` in `acceptance.json`:
`d53511af1a9f90bc4038fddc66c9f829a43421db6a60710976bbf9b5a956bf98`.
Those source bytes are committed at `464925754e27714fda30305f9373b50a45368151`.
Documentation-only commits do not change this tested inventory.

- `negative-before-7-failures.log`: seven isolated decision regressions before fixes.
- `live-before-2-failures.log`: two new live-pointer regressions before their fix.
- `unsigned-source-before-failure.log`: real Fedora validator accepted the unsigned
  SRPM; the negative test failed because the expected rejection did not occur.
- `unit-final-377.log`, `security-final-233.log`: final passing host suites.
- `acceptance.json`, `bootstrap/`, `upgrade/`: actual Fedora 44/DNF5 full-set fixture,
  signed roles, real dependency/conflict/SRPM negatives and source-bound receipts.
- `legacy-local-completed.json` and its log: first local V2 E2E completed; rpmlint
  had no errors and four synthetic fixture warnings. Its copied source inventory
  also matched the digest above. The retry log records an output-directory collision
  caused by the review driver; that retry exited 1 and is excluded from PASS totals.
- `rpm-vercmp-probe.py` / `rpm-vercmp-observation.json`: 1,500 deterministic native
  RPM 6.0.2 comparisons over the planner's admitted version/release segment grammar.
  Hyphen is an EVR delimiter and is rejected within those planner segments. Epoch
  and downgrade cases are covered separately by the unit suite.
- `ci-checks.json`: five successful automatic jobs at the exact implementation
  commit. The CI log confirms 377 general and 233 V3 tests, real legacy/full-set
  Fedora fixtures and runtime checks. CI success grants no production authority.
- `workflow-verification.json`: all 13 pre-existing workflows unchanged from main;
  all eleven new production jobs unconditionally disabled and read-only.

Reproduction commands from the repository root:

```bash
python3 -m unittest discover -s tests -p 'test_v3_adversarial_review.py' -v
python3 -m unittest discover -s tests -p 'test_v3_*.py' -v
python3 -m unittest discover -s tests -v
bash tests/v3-integration-e2e.sh NEW_EMPTY_EVIDENCE_DIRECTORY
RO_REPO_E2E_EVIDENCE=NEW_COMPATIBILITY_REPORT bash tests/e2e-local.sh
python3 docs/evidence/pr71-adversarial-20261012/rpm-vercmp-probe.py
```

Fedora commands require a disposable Fedora 44 environment with RPM/build/sign,
GPG, DNF5, createrepo_c and test Python dependencies. The observed base image was
`registry.fedoraproject.org/fedora@sha256:07584325a68e0308215aff1de506d8da6452d2e465c25729829a01393446f204`.
Runtime packages are independently hashed in receipts; the image digest alone
does not identify later installed dependencies. Freshly generated signatures,
keys and timestamps will differ on a new run.
