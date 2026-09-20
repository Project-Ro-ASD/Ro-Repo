# Remote Beta Rollback

Status: PHASE 2 STEP 7 IMPLEMENTATION

## Scope

Step 7 rolls the mutable remote beta channel back to an earlier, already-signed
beta publication history entry.

Rollback does not:

- rebuild RPMs;
- re-sign RPMs;
- regenerate repodata;
- re-sign repodata;
- create a new publication-v1 manifest;
- use any production signing secret.

Canonical flow:

```text
current beta publication
  -> choose exact earlier signed beta publication_run
  -> verify earlier publication signature
  -> verify referenced immutable snapshot
  -> rematerialize beta from exact snapshot bytes
  -> write rollback-evidence-v1
  -> push pages-storage
  -> verify repo.ro-asd.org
```

## Input identity

Workflow:

`.github/workflows/rollback-remote-beta.yml`

Inputs:

- `target_publication_run`: exact earlier beta publication workflow run ID;
- `reason`: mandatory non-empty operator reason.

The target is resolved only from:

```text
/publications/fedora/44/beta/<target_publication_run>/
```

There is no `latest`, previous-by-directory-order, tag, or fuzzy lookup.

## Authority

Rollback uses only the protected `repo-beta` environment.

The workflow contains no reference to:

- `repo-production-signing`;
- RPM signing secrets;
- metadata signing secrets;
- private keys;
- passphrases.

The beta publisher therefore has authority to select an already-authorized
signed publication, but not to mint a new signed publication.

## Signed-history verification

Before changing beta, rollback verifies:

1. target history entry exists;
2. publication-v1 schema;
3. channel is exactly beta;
4. publication_run equals the requested exact run ID;
5. referenced immutable snapshot exists;
6. detached publication-v1 signature verifies against the snapshot metadata key.

Only then is the target publication passed to the same remote-channel
materialization primitive used by normal beta publication.

## Rollback evidence

Every rollback writes:

```text
/rollbacks/fedora/44/beta/<rollback_workflow_run>.json
```

The evidence records:

- rollback workflow run;
- UTC timestamp;
- operator reason;
- previous publication run;
- previous snapshot ID;
- SHA-256 of previous publication manifest;
- target publication run;
- target snapshot ID;
- SHA-256 of target publication manifest.

The evidence is operational audit evidence. It does not replace or mutate the
signed publication manifests.

## Remote verification

After push, the workflow waits for `repo.ro-asd.org` to expose the exact target
publication run and snapshot ID.

It then verifies:

- full remote beta tree equals `pages-storage` byte-for-byte;
- the rolled-back publication manifest detached signature is valid.

## Client semantics

Repository rollback changes only what new dependency solves and updates see.

It does not automatically downgrade a client that already installed a higher
NEVRA. A bad package already installed on a client normally requires a forward
hotfix, explicit downgrade, or another recovery mechanism.

## Step 7 canary

Only one successful beta publication initially exists:

`35530066972`

A real rollback requires two publication identities. Canary sequence:

1. publish the same immutable snapshot `repo-f44-20260920-001` to beta again,
   producing a new signed publication run;
2. verify that second publication remotely;
3. run `rollback-remote-beta.yml` with
   `target_publication_run=35530066972`;
4. provide a non-empty canary reason;
5. verify the remote beta publication_run is again `35530066972`;
6. verify rollback evidence exists.

Using the same snapshot for both publication identities deliberately tests the
channel control plane without introducing new package bytes.

## Next step

Step 8 promotes the exact tested beta snapshot to stable under promotion policy.
Stable promotion must reuse the exact immutable snapshot and must not rebuild or
re-sign package repository content.
