# Remote Beta Publication

Status: PHASE 2 STEP 6 IMPLEMENTATION

## Scope

Step 6 publishes one already-built, already-signed immutable snapshot as the
remote `beta` DNF channel.

The snapshot is not rebuilt or re-signed.

Canonical lifecycle:

```text
immutable snapshot
  -> signed publication-v1 manifest
  -> protected beta publisher
  -> remote beta channel view
```

## Public paths

Immutable source:

```text
https://repo.ro-asd.org/snapshots/fedora/44/<snapshot_id>/
```

Mutable beta view:

```text
https://repo.ro-asd.org/rpm/fedora/44/beta/x86_64/
https://repo.ro-asd.org/rpm/fedora/44/beta/aarch64/
https://repo.ro-asd.org/rpm/fedora/44/beta/source/
https://repo.ro-asd.org/rpm/fedora/44/beta/publication-v1.json
https://repo.ro-asd.org/rpm/fedora/44/beta/publication-v1.json.asc
```

## Authority separation

The workflow `.github/workflows/publish-remote-beta.yml` uses two protected
environments.

### repo-production-signing

This job:

- reads the immutable snapshot;
- verifies the snapshot;
- creates `publication-v1.json`;
- signs only that publication manifest with the production metadata subkey;
- uploads the signed publication bundle.

It has no write permission to `pages-storage`.

### repo-beta

This job:

- receives the already-signed publication bundle;
- has no signing secret;
- verifies the signed publication manifest;
- verifies the referenced immutable snapshot;
- materializes the beta channel from exact snapshot RPM/repodata bytes;
- commits the channel update to `pages-storage`.

Signing authority and publication authority are therefore separate.

## Byte identity

For each architecture:

```text
snapshots/fedora/44/<snapshot_id>/rpm/<arch>/
```

must be byte-for-byte equal to:

```text
rpm/fedora/44/beta/<arch>/
```

No `createrepo_c`, RPM signing, metadata signing, package rebuild, or
dependency resolution occurs during channel materialization.

The only newly-created signed object is `publication-v1.json`.

## Publication history

Every signed beta publication manifest is preserved under:

```text
/publications/fedora/44/beta/<publication_run>/
```

The history entry contains:

- `publication-v1.json`
- `publication-v1.json.asc`

A publication run ID is immutable. Reusing the same run ID with different bytes
fails closed.

This history is the basis for Step 7 remote beta rollback.

## Remote verification

After the Pages storage commit, the workflow waits for the exact publication run
to become visible at `repo.ro-asd.org`.

It then verifies:

- exact `publication_run`;
- exact `snapshot_id`;
- complete beta tree byte-for-byte equality with `pages-storage`;
- publication manifest detached signature.

The remote verification job is read-only and uses no secrets.

## First beta canary

Snapshot:

`repo-f44-20260920-001`

The publication workflow run ID becomes the first beta publication identity.

Step 6 is closed only after the remote beta verification job succeeds.

## Next step

Step 7 performs remote beta rollback by selecting an earlier signed publication
history entry and rematerializing its exact immutable snapshot bytes.

A repository rollback does not automatically downgrade already-installed higher
NEVRA packages on clients.
