# GitHub Pages Publication Backend

Status: PHASE 2 STEP 4 IMPLEMENTATION

## Scope

Step 4 publishes an already-built, already-signed, immutable Step 3 candidate
snapshot into the persistent GitHub Pages backend.

It does not:

- rebuild RPMs;
- re-sign RPMs;
- regenerate repository metadata;
- re-sign repository metadata;
- create or move beta;
- create or move stable;
- bind `repo.ro-asd.org`.

Canonical boundary:

```text
exact successful build-candidate-snapshot workflow run
  -> exact candidate-snapshot-<snapshot_id>-<run_id> artifact
  -> production candidate verification
  -> immutable pages-storage tree
  -> GitHub Pages branch publication
```

## Persistent backend

The persistent Pages source is the dedicated `pages-storage` branch.

Snapshot path:

```text
/snapshots/fedora/44/<snapshot_id>/
```

Example:

```text
/snapshots/fedora/44/repo-f44-20260920-001/
```

The branch is storage, not source code. It must contain `.nojekyll` so RPM,
repodata, detached signatures, and JSON evidence are served byte-for-byte
without Jekyll processing.

No beta or stable channel directory is created in Step 4.

## Exact input identity

The workflow `.github/workflows/publish-pages-snapshot.yml` accepts:

- `candidate_run`: exact numeric successful candidate workflow run ID;
- `snapshot_id`: exact `repo-f44-YYYYMMDD-NNN` identity.

The source run must be:

- in `Project-Ro-ASD/Ro-Repo`;
- produced by `.github/workflows/build-candidate-snapshot.yml`;
- triggered with `workflow_dispatch`;
- successful;
- from `main`;
- bound to an exact 40-character commit SHA.

The workflow accepts exactly one non-expired artifact named:

`candidate-snapshot-<snapshot_id>-<candidate_run>`

No `latest`, newest-run lookup, branch-head artifact selection, or fuzzy
artifact matching is allowed.

## Candidate verification

Before publication, the workflow imports only the canonical metadata public key
embedded in the candidate and runs:

```text
tools/ro-repo verify-production-candidate
```

This verifies:

- repository-snapshot-v1 schema and snapshot identity;
- repository snapshot detached signature;
- exact metadata signing fingerprint;
- each repomd.xml digest;
- each repomd.xml detached signature;
- signed RPM digests;
- RPM signatures through the embedded canonical RPM public key;
- noarch copy parity;
- snapshot-build-evidence-v1 schema;
- exact candidate workflow run binding;
- repository manifest SHA-256 binding;
- RPM and metadata role fingerprints;
- snapshot build evidence detached signature.

No private signing key is present in the Step 4 workflow.

## Immutability

`stage-pages-snapshot` writes only:

`pages-storage:/snapshots/fedora/44/<snapshot_id>/`

If the target does not exist, the exact verified candidate tree is copied.

If the target already exists:

- byte-for-byte identical tree: idempotent success;
- any different byte, filename, extra file, missing file, or symlink:
  fail closed.

A snapshot path is therefore never overwritten.

The deterministic tree digest covers relative file paths, sizes, and bytes.
Symlinks are forbidden inside immutable snapshot trees.

## GitHub Pages configuration

One manual repository setting is required after the `pages-storage` branch is
initialized:

```text
Repository Settings
  -> Pages
  -> Build and deployment
  -> Source: Deploy from a branch
  -> Branch: pages-storage
  -> Folder: / (root)
  -> Save
```

This replaces the legacy Pages source that currently publishes `main`.

Step 4 intentionally uses branch-backed Pages storage because it preserves all
previous immutable snapshots across deployments. A Pages deployment artifact
alone is not the persistence layer.

## Permissions

The publication workflow has only:

```text
contents: write
actions: read
```

It references no RPM signing secret, metadata signing secret, private key, or
passphrase.

`contents: write` is required only to append the verified immutable snapshot
to `pages-storage`.

## Step 4 canary

The first production backend canary is:

```text
candidate run: 35523196901
snapshot:      repo-f44-20260920-001
```

Success criteria:

1. the exact candidate artifact is resolved;
2. all production candidate verification passes;
3. the snapshot is committed to `pages-storage`;
4. Pages source is set to `pages-storage / (root)`;
5. the signed repository snapshot manifest is reachable remotely at the
   GitHub Pages URL;
6. its bytes/hash match the candidate copy.

Beta and stable remain untouched after this canary.

## Next step

Step 5 binds `repo.ro-asd.org` to the same GitHub Pages backend.

Step 6 then creates the remote beta channel as a mutable view over an exact
immutable snapshot. Step 6 must not rebuild or re-sign Step 4 content.
