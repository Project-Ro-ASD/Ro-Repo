# Ro-Repo V2 Production Snapshot CI

Status: PHASE 2 STEP 3 IMPLEMENTATION

## Scope

This step converts one or more exact successful Ro-Repo production signing runs
into one immutable candidate repository snapshot artifact.

It does not publish GitHub Pages, beta, stable, or `repo.ro-asd.org`.

Canonical boundary:

```text
exact successful accept-component workflow run IDs
  -> accepted-component-<run_id>
  -> signed-component-<run_id>
  -> signed bundle revalidation
  -> createrepo_c per architecture
  -> metadata signing
  -> repository-snapshot-v1
  -> snapshot-build-evidence-v1
  -> candidate-snapshot-<snapshot_id>-<workflow_run> artifact
```

No producer release, branch, `latest`, or mutable channel is a valid direct
snapshot input.

## Exact input identity

The workflow accepts:

- `signing_runs`: comma-separated exact numeric Ro-Repo workflow run IDs;
- `snapshot_id`: exact `repo-f44-YYYYMMDD-NNN` identifier;
- optional `parent_snapshot`: exact prior snapshot ID.

Every source run is queried through the GitHub API and must be:

- in `Project-Ro-ASD/Ro-Repo`;
- produced by `.github/workflows/accept-component.yml`;
- triggered through `workflow_dispatch`;
- completed successfully;
- from the `main` branch;
- bound to an exact 40-character commit SHA.

The workflow downloads only:

- `accepted-component-<run_id>`;
- `signed-component-<run_id>`.

The downloaded artifact contents are then revalidated by Ro-Repo. GitHub run
metadata alone is not treated as sufficient trust evidence.

## Signed bundle revalidation

`tools/ro-repo build-production-snapshot` must fail closed unless all of the
following hold:

- the accepted object remains internally consistent;
- production acceptance provenance is
  `github_attestation_exact_match`;
- the signing evidence validates against its schema;
- signing evidence `workflow_run` equals the exact source run ID;
- acceptance manifest digest equals the signing evidence binding;
- RPM signing fingerprint equals the canonical production RPM role fingerprint;
- signed RPM set exactly matches the accepted RPM set;
- producer artifact hashes remain unchanged;
- signed artifact hashes match the downloaded bytes;
- signed RPM bytes differ from producer bytes;
- signed RPM headers still match the accepted manifest;
- every RPM verifies against the canonical production RPM public key;
- filenames are unique across all source signing runs.

A snapshot may contain several components. The source run list is therefore an
explicit full-set input. No implicit "current repository contents" or "latest
component" lookup exists in this step.

## Metadata signing role

RPM signing and metadata signing remain separate roles.

Canonical metadata signing fingerprint:

`1715DDA529B9ADB46D47CB389A62B8F9026E75E5`

Canonical public key:

`keys/production/ro-asd-metadata-signing-public.asc`

The snapshot workflow uses only these environment secrets:

- `RO_REPO_METADATA_SIGNING_SUBKEY_B64`
- `RO_REPO_METADATA_SIGNING_PASSPHRASE`

It must not reference the RPM signing private-key secret.

The existing protected `repo-production-signing` environment is reused in
Step 3 so an unprotected environment is never auto-created by a workflow
reference. The metadata and RPM secret values remain separate and jobs map only
the role-specific secrets they require.

The offline primary private key remains forbidden in CI.

## Ephemeral metadata key handling

The workflow must:

1. create a temporary private GNUPGHOME;
2. decode only the metadata subkey-only export;
3. validate the exact metadata fingerprint and signing role;
4. reject primary-secret or extra-secret material;
5. keep the passphrase in a mode-0600 temporary file;
6. never put a literal passphrase in argv;
7. unset secret environment variables after materialization;
8. kill the temporary GPG agent and delete temporary key/passphrase material.

## Candidate snapshot contents

The candidate snapshot contains:

```text
repository-snapshot-v1.json
repository-snapshot-v1.json.asc
snapshot-build-evidence-v1.json
snapshot-build-evidence-v1.json.asc
keys/
  RPM-GPG-KEY-ro-asd
  REPODATA-GPG-KEY-ro-asd
rpm/
  x86_64/
    *.rpm
    repodata/
      repomd.xml
      repomd.xml.asc
      ...
  aarch64/
    *.rpm
    repodata/
      repomd.xml
      repomd.xml.asc
      ...
  source/
    *.rpm
    repodata/
      repomd.xml
      repomd.xml.asc
      ...
```

`noarch` packages are copied into both binary architecture repositories.

Each `repomd.xml`, the repository snapshot manifest, and snapshot build
evidence are signed by the exact metadata signing subkey.

The complete candidate is verified again before it is atomically moved to its
final local snapshot path.

## Snapshot build evidence

`snapshot-build-evidence-v1.json` binds:

- snapshot ID;
- snapshot build workflow run;
- exact source signing run IDs;
- repository snapshot manifest SHA-256;
- RPM signing fingerprint;
- metadata signing fingerprint;
- producer release identity for each component;
- acceptance manifest digest for each component.

It is separately signed with the metadata role key.

## Output

A successful workflow uploads:

`candidate-snapshot-<snapshot_id>-<github.run_id>`

with 90-day Actions retention.

This Actions artifact is the Step 3 handoff object. It is not yet a DNF channel
and is not the permanent public backend.

Step 4 will consume an exact candidate snapshot and implement the GitHub Pages
publication backend without rebuilding or re-signing the snapshot.

## Tests

Pull-request CI must cover:

- exact signed bundle succeeds;
- mutated signed RPM is rejected;
- mismatched signing workflow run is rejected;
- wrong RPM signing fingerprint is rejected;
- duplicate source run IDs are rejected;
- production snapshot workflow references metadata secrets only;
- Fedora 44 E2E creates separate RPM and metadata subkey-only keyrings;
- Fedora 44 E2E builds and verifies a production-style candidate snapshot;
- source signing evidence mutation fails closed;
- existing Phase 1 snapshot/promotion tests remain green.
