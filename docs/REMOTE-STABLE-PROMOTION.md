# Remote Stable Exact-Snapshot Promotion

Status: PHASE 2 STEP 8 IMPLEMENTATION

## Goal

Promote the exact remotely-tested beta snapshot to the mutable stable channel
without rebuilding packages or repository metadata.

The stable channel may receive a new signed `publication-v1.json`, but the RPMs,
repodata, snapshot manifest, snapshot signatures, and repository metadata bytes
must come from the already-published immutable snapshot.

Canonical flow:

```text
current remote beta
  -> exact remote Fedora 44 validation
  -> promotion evidence
  -> beta dwell policy
  -> stable publication manifest signing
  -> repo-stable approval
  -> exact snapshot materialization as stable
  -> remote stable verification
```

## Remote beta validation

Workflow:

`.github/workflows/validate-remote-beta-promotion.yml`

Inputs:

- exact `snapshot_id`
- exact current `beta_publication_run`

The workflow is read-only and has no protected environment or secret access.

It validates the real remote x86_64 beta repository at:

`https://repo.ro-asd.org/rpm/fedora/44/beta/x86_64`

Required tests for the current `ro-assist` normal application snapshot:

- dependency-solve
- clean-install
- upgrade
- file-conflict
- rpmlint
- smoke

The upgrade baseline is pinned in
`config/promotion-baselines-v1.json`. The initial baseline is the public
Ro-Assist v0.2.1 x86_64 RPM and its exact SHA-256.

The resulting `promotion-validation-v1.json` is bound to:

- exact immutable snapshot ID
- exact beta publication run
- exact validation workflow run
- beta start timestamp
- baseline release and digest

There is no `latest` lookup.

## Dwell policy

The producer registry is authoritative for risk class and required tests.

For the current snapshot:

```text
package: ro-assist
risk_class: normal-app
promotion_group: ro-assist
minimum beta dwell: 7 days
```

The current beta publication being promoted must match the validation evidence.

A normal promotion before the dwell period completes fails closed with
`BETA_DWELL_NOT_MET`.

Step 8 does not use the emergency promotion path for this canary.

## Stable authority separation

Workflow:

`.github/workflows/promote-remote-stable.yml`

### verify-promotion-policy

Read-only.

It:

- downloads one exact validation-run artifact;
- verifies the current beta identity;
- verifies the evidence schema;
- derives risk class, promotion groups, and required tests from the producer registry;
- enforces the beta dwell period;
- produces `promotion-manifest-v1.json`.

### repo-production-signing

This protected job:

- re-verifies the promotion bundle against the current beta;
- verifies the immutable snapshot;
- creates a new stable `publication-v1.json`;
- signs only that channel publication manifest with the metadata signing subkey.

It cannot write `pages-storage`.

### repo-stable

This protected job:

- receives the already-signed stable publication;
- has no signing secret;
- re-verifies the current beta identity immediately before publication;
- verifies the immutable snapshot and signed stable publication;
- materializes stable from exact snapshot repository bytes;
- persists promotion evidence and promotion manifest;
- commits the stable channel to `pages-storage`.

Signing authority and stable publication authority remain separate.

## Public stable paths

```text
https://repo.ro-asd.org/rpm/fedora/44/stable/x86_64/
https://repo.ro-asd.org/rpm/fedora/44/stable/aarch64/
https://repo.ro-asd.org/rpm/fedora/44/stable/source/
https://repo.ro-asd.org/rpm/fedora/44/stable/publication-v1.json
https://repo.ro-asd.org/rpm/fedora/44/stable/publication-v1.json.asc
```

## Persistent audit paths

Validation evidence:

```text
/evidence/promotions/<snapshot_id>/<validation_run>/promotion-validation-v1.json
```

Promotion manifest:

```text
/promotions/fedora/44/<snapshot_id>/<stable_workflow_run>/promotion-manifest-v1.json
```

Signed stable publication history:

```text
/publications/fedora/44/stable/<stable_workflow_run>/
```

## Stable verification

After publication, the workflow verifies:

- local stable architecture trees equal the immutable snapshot trees;
- the exact stable publication run reaches `repo.ro-asd.org`;
- the complete remote stable tree equals `pages-storage` byte-for-byte;
- the stable publication manifest detached signature is valid;
- persisted validation evidence and promotion manifest remain schema-valid.

## Initial snapshot

`repo-f44-20260920-001`

The first successful beta publication began at:

`2026-09-20T18:45:39Z`

For a normal application, the earliest normal stable promotion time is therefore:

`2026-09-27T18:45:39Z`

The policy gate must reject earlier attempts.

## Next step

After the exact stable snapshot is published and remotely verified, Step 9 runs
the remote Fedora 44 DNF end-to-end validation directly against the stable
channel.
